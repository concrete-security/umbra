(function (A) {
  const UI = A.UI;

  // ── Tuning constants ───────────────────────────────────────────────────
  const MAX_PARTICLES = 90; // hard cap on concurrent dots
  const SEG_MS = 1100; // base travel time per path segment (cvm→sc, sc→dest)
  const REPLAY_SPEEDUP = 26; // compress the traffic window so the graph stays lively
  const BLOCK_CODE = 403; // SC policy block convention (enforcement.py _blocked_result)

  const prefersReducedMotion =
    typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Module state — survives polls so the animation never resets.
  const S = {
    root: null,
    stage: null,
    svg: null,
    overlay: null,
    layers: { edges: null, fx: null, particles: null },
    nodeEls: new Map(), // key → HTMLElement
    model: null,
    layout: null, // { cvm:[{node,pos}], sc:{node,pos}, dest:[{node,pos}], w, h }
    flows: [], // [{ from:{x,y}, sc:{x,y}, to:{x,y}|null, blocked, ratePerSec, nextSpawn }]
    particles: [],
    effects: [], // expanding rings at the SC / arrival pulses
    pool: [], // recycled particle <g> nodes
    raf: null,
    lastT: 0,
    ro: null,
  };

  function isBlocked(code) {
    return Number(code) === BLOCK_CODE;
  }

  // ── Geometry ────────────────────────────────────────────────────────────
  // Smooth horizontal S-curve control points between two points.
  function curve(p0, p1) {
    const mx = (p0.x + p1.x) / 2;
    return { p0, c1: { x: mx, y: p0.y }, c2: { x: mx, y: p1.y }, p3: p1 };
  }

  function bezier(seg, t) {
    const u = 1 - t;
    const a = u * u * u;
    const b = 3 * u * u * t;
    const c = 3 * u * t * t;
    const d = t * t * t;
    return {
      x: a * seg.p0.x + b * seg.c1.x + c * seg.c2.x + d * seg.p3.x,
      y: a * seg.p0.y + b * seg.c1.y + c * seg.c2.y + d * seg.p3.y,
    };
  }

  function pathD(seg) {
    return `M ${seg.p0.x} ${seg.p0.y} C ${seg.c1.x} ${seg.c1.y}, ${seg.c2.x} ${seg.c2.y}, ${seg.p3.x} ${seg.p3.y}`;
  }

  function svgEl(name, attrs) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  // ── Skeleton (built once) ────────────────────────────────────────────────
  function buildSkeleton(panel) {
    const root = document.createElement("div");
    root.className = "topo";
    root.setAttribute("data-topo-root", "");
    root.innerHTML = `
      <div class="topo-statstrip" data-topo-stats></div>
      <div class="topo-stage bg-grad-hero" data-topo-stage>
        <div class="hero-grid topo-grid"></div>
        <svg class="topo-svg" data-topo-svg preserveAspectRatio="none">
          <defs>
            <linearGradient id="topo-grad-allow" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stop-color="#6aa0f6" stop-opacity="0.05"/>
              <stop offset="1" stop-color="#6aa0f6" stop-opacity="0.4"/>
            </linearGradient>
            <linearGradient id="topo-grad-block" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stop-color="#f07178" stop-opacity="0.05"/>
              <stop offset="1" stop-color="#f07178" stop-opacity="0.35"/>
            </linearGradient>
          </defs>
          <g data-edges></g>
          <g data-fx></g>
          <g data-particles></g>
        </svg>
        <div class="topo-overlay" data-topo-overlay></div>
        <div class="topo-empty hidden" data-topo-empty></div>
      </div>
      <div class="topo-legend" data-topo-legend></div>`;
    panel.innerHTML = "";
    panel.appendChild(root);

    S.root = root;
    S.stage = root.querySelector("[data-topo-stage]");
    S.svg = root.querySelector("[data-topo-svg]");
    S.overlay = root.querySelector("[data-topo-overlay]");
    S.layers.edges = S.svg.querySelector("[data-edges]");
    S.layers.fx = S.svg.querySelector("[data-fx]");
    S.layers.particles = S.svg.querySelector("[data-particles]");
    S.nodeEls = new Map();

    bindOverlay();

    if (S.ro) S.ro.disconnect();
    if (typeof ResizeObserver === "function") {
      S.ro = new ResizeObserver(() => {
        if (!S.model) return;
        relayout();
      });
      S.ro.observe(S.stage);
    }
  }

  function bindOverlay() {
    S.overlay.addEventListener("click", (e) => {
      const cvm = e.target.closest("[data-node-cvm]");
      if (cvm) return void A.Drawer.openCvm(cvm.getAttribute("data-node-cvm"));
      const sc = e.target.closest("[data-node-sc]");
      if (sc) {
        if (S.model?.sc) A.Drawer.openSc(S.model.sc);
        return;
      }
      const dest = e.target.closest("[data-node-dest]");
      if (dest) {
        const host = dest.getAttribute("data-node-dest");
        if (host && host !== "__other") {
          A.trafficState = { from: "", to: "", hostFilter: host, items: [], nextCursor: null, summary: null };
        }
        if (A.has(A.P.TRAFFIC)) location.hash = "traffic";
        return;
      }
      const more = e.target.closest("[data-node-more]");
      if (more) location.hash = "cvms";
    });
  }

  // ── Public entry ───────────────────────────────────────────────────────
  function render(panel, model) {
    if (!panel) return;
    if (!S.root || !S.root.isConnected || !panel.contains(S.root)) {
      buildSkeleton(panel);
    }
    S.model = model;
    renderStats(model);
    renderLegend(model);
    relayout(); // (re)position nodes + edges + recompute flow geometry
    ensureRunning();
  }

  // ── Stat strip ───────────────────────────────────────────────────────────
  function renderStats(m) {
    const el = S.root.querySelector("[data-topo-stats]");
    const st = m.stats;
    const scPill = m.sc
      ? `<span class="topo-stat-pill ${m.sc.ok ? "is-ok" : "is-warn"}"><span class="dot ${m.sc.ok ? "dot-ok dot-pulse" : "dot-warn"}"></span>${m.sc.ok ? "Enforcing" : UI.escapeHtml(m.sc.state || "offline")}</span>`
      : `<span class="topo-stat-pill is-warn"><span class="dot dot-warn"></span>No Security CVM</span>`;
    const items = [
      { label: "CVMs running", value: `${st.cvmsRunning}/${st.cvmsTotal}`, tone: st.errored ? "warn" : "ink" },
      { label: "Egress", value: st.total ? `${st.reqPerMin}<span class="topo-stat-unit"> req/min</span>` : "idle", tone: "ink" },
      { label: "Allowed", value: st.total ? `${st.allowedPct}%` : "—", tone: "ok" },
      { label: "Blocked", value: st.total ? `${st.blockedPct}%` : "—", tone: st.blocked ? "err" : "mute" },
    ];
    el.innerHTML = `
      <div class="topo-stats-left">
        <span class="topo-scope">${UI.icon("entity", "h-3.5 w-3.5")}${UI.escapeHtml(m.scope.entityName || "Topology")}</span>
        ${scPill}
      </div>
      <div class="topo-stats-metrics">
        ${items
          .map(
            (it) => `
          <div class="topo-metric">
            <span class="topo-metric-val tone-${it.tone}">${it.value}</span>
            <span class="topo-metric-label">${UI.escapeHtml(it.label)}</span>
          </div>`
          )
          .join("")}
        ${m.scope.canLaunch ? `<button type="button" class="btn btn-primary btn-sm topo-launch" data-topo-launch>${UI.icon("plus", "h-3.5 w-3.5")} Launch CVM</button>` : ""}
      </div>`;
    el.querySelector("[data-topo-launch]")?.addEventListener("click", () => A.openLaunchModal && A.openLaunchModal());
  }

  function renderLegend(m) {
    const el = S.root.querySelector("[data-topo-legend]");
    if (!m.hasTrafficPerm) {
      el.innerHTML = `<span class="topo-legend-note">${UI.icon("info", "h-3.5 w-3.5")} Live egress flow requires the Traffic Logs permission. Showing topology only.</span>`;
      return;
    }
    el.innerHTML = `
      <span class="topo-legend-item"><span class="topo-swatch is-allow"></span>Allowed — routed through the Security CVM</span>
      <span class="topo-legend-item"><span class="topo-swatch is-block"></span>Blocked — stopped at the gateway</span>
      <span class="topo-legend-note">${UI.icon("info", "h-3.5 w-3.5")} Last ${m.stats.windowMin}m · click any node to inspect</span>`;
  }

  // ── Layout + node DOM diffing ─────────────────────────────────────────────
  function relayout() {
    const m = S.model;
    const stageRect = S.stage.getBoundingClientRect();
    const w = Math.max(320, stageRect.width);
    const h = Math.max(360, stageRect.height);
    S.svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    S.svg.setAttribute("width", w);
    S.svg.setAttribute("height", h);

    const empty = S.root.querySelector("[data-topo-empty]");
    if (!m.cvms.length && !m.sc) {
      empty.classList.remove("hidden");
      empty.innerHTML = emptyStateHtml(m);
      S.layers.edges.innerHTML = "";
      S.layout = null;
      // drop node DOM
      S.nodeEls.forEach((el) => el.remove());
      S.nodeEls.clear();
      return;
    }
    empty.classList.add("hidden");

    const colX = { cvm: w * 0.14, sc: w * 0.5, dest: w * 0.86 };
    const topPad = 64;
    const botPad = 30;

    const spread = (items, x) => {
      const n = items.length;
      const usable = h - topPad - botPad;
      return items.map((node, i) => {
        const y = n === 1 ? h * 0.5 : topPad + (usable * i) / (n - 1);
        return { node, pos: { x, y } };
      });
    };

    const layout = {
      w,
      h,
      cvm: spread(m.cvms.length ? m.cvms : [], colX.cvm),
      dest: spread(m.dests.length ? m.dests : [], colX.dest),
      sc: m.sc ? { node: m.sc, pos: { x: colX.sc, y: h * 0.5 } } : null,
    };
    S.layout = layout;

    syncNodes(layout, m);
    drawEdges(layout, m);
    buildFlows(layout, m);
  }

  function nodeKey(kind, id) {
    return kind + ":" + id;
  }

  function syncNodes(layout, m) {
    const seen = new Set();

    const place = (el, pos) => {
      el.style.left = pos.x + "px";
      el.style.top = pos.y + "px";
    };

    // CVM nodes
    layout.cvm.forEach(({ node, pos }) => {
      const key = nodeKey("cvm", node.id);
      seen.add(key);
      let el = S.nodeEls.get(key);
      if (!el) {
        el = document.createElement("button");
        el.type = "button";
        el.setAttribute("data-node-cvm", node.id);
        S.overlay.appendChild(el);
        S.nodeEls.set(key, el);
      }
      el.className = "topo-node topo-cvm " + (node.error ? "is-error" : node.ok ? "is-ok" : "is-idle");
      el.title = `${node.fqdn || node.id}\n${node.state}${node.profiles?.length ? " · " + node.profiles.map((p) => p.name).join(", ") : ""}`;
      el.innerHTML = `
        <span class="${UI.dotClass(node.state)}"></span>
        <span class="topo-node-label">${UI.escapeHtml(node.label)}</span>
        ${node.total ? `<span class="topo-node-count">${node.total}</span>` : ""}`;
      place(el, pos);
    });

    // "+N more" affordance
    if (m.moreCvms > 0) {
      const key = "more:cvm";
      seen.add(key);
      let el = S.nodeEls.get(key);
      if (!el) {
        el = document.createElement("button");
        el.type = "button";
        el.setAttribute("data-node-more", "");
        S.overlay.appendChild(el);
        S.nodeEls.set(key, el);
      }
      el.className = "topo-node topo-more";
      el.textContent = `+${m.moreCvms} more`;
      const last = layout.cvm[layout.cvm.length - 1];
      place(el, { x: layout.w * 0.14, y: (last ? last.pos.y : layout.h * 0.5) + 46 });
    }

    // SC hub
    if (layout.sc) {
      const key = "sc:hub";
      seen.add(key);
      let el = S.nodeEls.get(key);
      if (!el) {
        el = document.createElement("button");
        el.type = "button";
        el.setAttribute("data-node-sc", "");
        S.overlay.appendChild(el);
        S.nodeEls.set(key, el);
      }
      const sc = layout.sc.node;
      el.className = "topo-node topo-sc " + (sc.ok ? "is-ok" : "is-warn");
      el.title = `${sc.fqdn || "Security CVM"}\n${sc.state}`;
      el.innerHTML = `
        <span class="topo-sc-ring"></span>
        <span class="topo-sc-badge">${UI.icon("shield", "h-6 w-6")}</span>
        <span class="topo-sc-meta">
          <span class="topo-sc-title">Security CVM</span>
          <span class="topo-sc-sub">${sc.ok ? "enforcing policy" : UI.escapeHtml(sc.state || "offline")}</span>
        </span>`;
      place(el, layout.sc.pos);
    }

    // Destination nodes
    layout.dest.forEach(({ node, pos }) => {
      const key = nodeKey("dest", node.key);
      seen.add(key);
      let el = S.nodeEls.get(key);
      if (!el) {
        el = document.createElement("button");
        el.type = "button";
        el.setAttribute("data-node-dest", node.key);
        S.overlay.appendChild(el);
        S.nodeEls.set(key, el);
      }
      const blockHeavy = node.blocked > 0 && node.blocked >= node.allowed;
      el.className = "topo-node topo-dest " + (blockHeavy ? "is-block" : "is-allow") + (node.isOther ? " is-other" : "");
      el.title = node.isOther ? `${node.total} requests to other hosts` : `${node.host} · ${node.total} requests`;
      el.innerHTML = `
        <span class="topo-dest-host">${UI.escapeHtml(node.isOther ? "other hosts" : node.host)}</span>
        <span class="topo-dest-count">${node.total}${node.blocked ? ` · <span class="topo-dest-blocked">${node.blocked}✕</span>` : ""}</span>`;
      place(el, pos);
    });

    // Column labels
    ensureColLabel("cvm", "Dev CVMs", layout.w * 0.14);
    if (layout.sc) ensureColLabel("sc", "Gateway", layout.w * 0.5);
    if (layout.dest.length) ensureColLabel("dest", "Destinations", layout.w * 0.86);
    seen.add("label:cvm");
    seen.add("label:sc");
    seen.add("label:dest");

    // Remove stale nodes
    S.nodeEls.forEach((el, key) => {
      if (!seen.has(key)) {
        el.remove();
        S.nodeEls.delete(key);
      }
    });
  }

  function ensureColLabel(kind, text, x) {
    const key = "label:" + kind;
    let el = S.nodeEls.get(key);
    if (kind === "sc" && !S.layout?.sc) {
      if (el) {
        el.remove();
        S.nodeEls.delete(key);
      }
      return;
    }
    if (kind === "dest" && !S.layout?.dest.length) {
      if (el) {
        el.remove();
        S.nodeEls.delete(key);
      }
      return;
    }
    if (!el) {
      el = document.createElement("div");
      el.className = "topo-collabel";
      S.overlay.appendChild(el);
      S.nodeEls.set(key, el);
    }
    el.textContent = text;
    el.style.left = x + "px";
    el.style.top = "26px";
  }

  // ── Static edges ───────────────────────────────────────────────────────
  function drawEdges(layout, m) {
    const g = S.layers.edges;
    g.innerHTML = "";
    if (!layout.sc) return;
    const sc = layout.sc.pos;
    const maxTotal = Math.max(1, ...m.cvms.map((c) => c.total));

    layout.cvm.forEach(({ node, pos }) => {
      const seg = curve(pos, sc);
      const active = node.total > 0;
      const blockHeavy = node.blocked > 0 && node.blocked >= node.allowed;
      const op = active ? 0.18 + 0.5 * (node.total / maxTotal) : 0.07;
      g.appendChild(
        svgEl("path", {
          d: pathD(seg),
          fill: "none",
          stroke: blockHeavy ? "url(#topo-grad-block)" : "url(#topo-grad-allow)",
          "stroke-width": active ? 1.6 : 1,
          "stroke-opacity": op,
          "stroke-linecap": "round",
        })
      );
    });

    const maxDest = Math.max(1, ...m.dests.map((d) => d.total));
    layout.dest.forEach(({ node, pos }) => {
      const seg = curve(sc, pos);
      const blockHeavy = node.blocked > 0 && node.blocked >= node.allowed;
      const op = 0.18 + 0.5 * (node.total / maxDest);
      g.appendChild(
        svgEl("path", {
          d: pathD(seg),
          fill: "none",
          stroke: blockHeavy ? "url(#topo-grad-block)" : "url(#topo-grad-allow)",
          "stroke-width": 1.6,
          "stroke-opacity": op,
          "stroke-linecap": "round",
        })
      );
    });
  }

  // ── Flow geometry for the particle system ─────────────────────────────────
  function buildFlows(layout, m) {
    S.flows = [];
    if (!layout.sc || !m.flows.length) return;
    const sc = layout.sc.pos;
    const cvmPos = new Map(layout.cvm.map(({ node, pos }) => [node.id, pos]));
    const destPos = new Map(layout.dest.map(({ node, pos }) => [node.key, pos]));
    const windowSec = m.stats.windowMin * 60;

    m.flows.forEach((f) => {
      const from = cvmPos.get(f.cvmId);
      if (!from) return;
      const to = f.blocked ? null : destPos.get(f.destKey) || destPos.get("__other") || null;
      const segs = [curve(from, sc)];
      if (to) segs.push(curve(sc, to));
      const ratePerSec = (f.count / windowSec) * REPLAY_SPEEDUP;
      S.flows.push({ segs, blocked: f.blocked, ratePerSec, nextSpawn: 0, scPos: sc, endPos: to });
    });
  }

  // ── Animation loop ─────────────────────────────────────────────────────
  function ensureRunning() {
    if (prefersReducedMotion) return; // static graph; no rAF
    if (S.raf != null) return;
    S.lastT = 0;
    S.raf = requestAnimationFrame(frame);
  }

  function stopLoop() {
    if (S.raf != null) cancelAnimationFrame(S.raf);
    S.raf = null;
  }

  function alive() {
    const panel = S.root && S.root.closest(".panel");
    return S.root && S.root.isConnected && panel && panel.classList.contains("active") && !document.hidden;
  }

  function frame(now) {
    if (!alive()) {
      stopLoop();
      return;
    }
    const dt = S.lastT ? Math.min(0.05, (now - S.lastT) / 1000) : 0.016;
    S.lastT = now;
    spawn(dt);
    step(dt);
    S.raf = requestAnimationFrame(frame);
  }

  function spawn(dt) {
    for (const flow of S.flows) {
      if (flow.ratePerSec <= 0) continue;
      // expected spawns this frame; supports >1/frame for hot flows
      let expected = flow.ratePerSec * dt;
      while (expected > 0) {
        if (Math.random() < Math.min(1, expected)) addParticle(flow);
        expected -= 1;
      }
    }
  }

  function addParticle(flow) {
    if (S.particles.length >= MAX_PARTICLES) return;
    let g = S.pool.pop();
    if (!g) {
      g = svgEl("g", { class: "topo-particle" });
      g.appendChild(svgEl("circle", { class: "topo-particle-halo", r: 6 }));
      g.appendChild(svgEl("circle", { class: "topo-particle-core", r: 2.2 }));
    }
    g.setAttribute("class", "topo-particle " + (flow.blocked ? "is-block" : "is-allow"));
    S.layers.particles.appendChild(g);
    S.particles.push({
      g,
      segs: flow.segs,
      blocked: flow.blocked,
      seg: 0,
      t: 0,
      dur: SEG_MS * (0.85 + Math.random() * 0.3),
      scPos: flow.scPos,
      endPos: flow.endPos,
    });
  }

  function step(dt) {
    const ms = dt * 1000;
    for (let i = S.particles.length - 1; i >= 0; i--) {
      const p = S.particles[i];
      p.t += ms / p.dur;
      while (p.t >= 1 && p.seg < p.segs.length - 1) {
        p.t -= 1;
        p.seg += 1;
      }
      if (p.t >= 1) {
        // reached the end of its last segment
        if (p.blocked) emitRing(p.scPos, "block");
        else if (p.endPos) emitRing(p.endPos, "allow");
        retire(p, i);
        continue;
      }
      const pt = bezier(p.segs[p.seg], easeInOut(p.t));
      p.g.setAttribute("transform", `translate(${pt.x} ${pt.y})`);
      // fade in/out near the ends of the whole journey
      const global = (p.seg + p.t) / p.segs.length;
      const fade = Math.min(1, global * 6, (1 - global) * 6 + 0.2);
      p.g.style.opacity = String(Math.max(0.15, Math.min(1, fade)));
    }
    stepEffects(ms);
  }

  function retire(p, i) {
    S.particles.splice(i, 1);
    p.g.style.opacity = "0";
    if (p.g.parentNode) p.g.parentNode.removeChild(p.g);
    if (S.pool.length < 40) S.pool.push(p.g);
  }

  function easeInOut(t) {
    return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  }

  function emitRing(pos, kind) {
    const ring = svgEl("circle", {
      class: "topo-ring is-" + kind,
      cx: pos.x,
      cy: pos.y,
      r: kind === "block" ? 9 : 5,
    });
    S.layers.fx.appendChild(ring);
    S.effects.push({ el: ring, life: 0, dur: kind === "block" ? 520 : 420, r0: kind === "block" ? 9 : 5, r1: kind === "block" ? 26 : 16 });
  }

  function stepEffects(ms) {
    for (let i = S.effects.length - 1; i >= 0; i--) {
      const fx = S.effects[i];
      fx.life += ms;
      const k = fx.life / fx.dur;
      if (k >= 1) {
        fx.el.remove();
        S.effects.splice(i, 1);
        continue;
      }
      fx.el.setAttribute("r", String(fx.r0 + (fx.r1 - fx.r0) * easeInOut(k)));
      fx.el.style.opacity = String(1 - k);
    }
  }

  // ── Empty states ─────────────────────────────────────────────────────────
  function emptyStateHtml(m) {
    if (!m.sc && !m.cvms.length) {
      return `
        <div class="topo-empty-inner">
          ${UI.icon("shield", "h-10 w-10 text-mute-soft")}
          <h3>No topology to show yet</h3>
          <p>${m.scope.canLaunch ? "Provision a Security CVM and launch a Dev CVM to see the live egress map." : "This entity has no Security CVM or Dev CVMs yet."}</p>
          ${m.scope.isPlatform ? `<p class="topo-empty-hint">Use the entity picker above to view another tenant.</p>` : ""}
        </div>`;
    }
    return "";
  }

  A.Graph = { render, stop: stopLoop };
})(window.Admin);
