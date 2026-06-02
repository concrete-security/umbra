(function (A) {
  const UI = A.UI;

  function policyFromEditor(root) {
    const policy = {};
    const rows = root.querySelectorAll("[data-sandbox-row]");
    const sandbox_env = {};
    rows.forEach((row) => {
      const k = row.querySelector("[data-sandbox-key]")?.value?.trim();
      const v = row.querySelector("[data-sandbox-val]")?.value ?? "";
      if (k) sandbox_env[k] = v;
    });
    if (Object.keys(sandbox_env).length) policy.sandbox_env = sandbox_env;
    const adv = root.querySelector("#profile-advanced")?.value?.trim();
    if (adv) {
      try {
        const extra = JSON.parse(adv);
        if (extra && typeof extra === "object") {
          Object.keys(extra).forEach((key) => {
            if (key !== "sandbox_env") policy[key] = extra[key];
          });
        }
      } catch {
        throw new Error("Advanced policy is not valid JSON");
      }
    }
    return policy;
  }

  function sandboxEditor(policy, readonly) {
    const env = policy?.sandbox_env || {};
    const rows = Object.entries(env)
      .map(
        ([k, v], i) =>
          `<div class="flex items-center gap-2 mb-1.5" data-sandbox-row="${i}">
            <input data-sandbox-key class="input input-sm font-mono flex-1" placeholder="VAR_NAME" value="${UI.escapeHtml(k)}" ${readonly ? "disabled" : ""}>
            <input data-sandbox-val class="input input-sm font-mono flex-1" placeholder="value" value="${UI.escapeHtml(v)}" ${readonly ? "disabled" : ""}>
            ${readonly ? "" : `<button type="button" class="btn btn-ghost btn-xs" data-rm-sandbox aria-label="Remove">${UI.icon("x", "h-3.5 w-3.5")}</button>`}
          </div>`
      )
      .join("");
    const opaque = { ...policy };
    delete opaque.sandbox_env;
    return `
      <section class="card card-pad mb-3">
        <header class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("system", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink">Edit policy</h4>
            ${UI.helpHint("Raw policy editor. Non-secret sandbox env vars get a key/value editor; destination rules, secret injection, DLP patterns, and WebSocket assertions live in the advanced JSON. The summary above reflects the saved policy.")}
          </div>
        </header>
        <p class="text-xs text-mute mb-3">Non-secret variables seeded into every CVM that attaches this profile. Use the advanced editor below for destination rules, body/WebSocket assertions, traffic attributes, DLP patterns, and proxy-time secret injection.</p>

        <label class="field-label">Sandbox environment</label>
        <div id="sandbox-rows" class="mb-1.5">${rows || `<p class="text-xs text-mute italic mb-1.5">No variables defined.</p>`}</div>
        ${readonly ? "" : `<button type="button" class="btn btn-ghost btn-xs" id="add-sandbox-row">${UI.icon("plus", "h-3.5 w-3.5")} Add variable</button>`}

        <details class="mt-4 group">
          <summary class="flex items-center gap-1.5 text-2xs uppercase tracking-wider text-mute cursor-pointer hover:text-ink mb-2">
            ${UI.icon("chevron-right", "h-3 w-3 transition-transform group-open:rotate-90")}
            Advanced policy (raw JSON)
            ${UI.helpHint("Full policy object: allowed_destinations, blocked_destinations, secret_patterns, secret_injections, and sandbox_env. Destination rules may include body_assertions, websocket_assertions, and traffic_log_attributes. Validated server-side.")}
          </summary>
          <textarea id="profile-advanced" class="textarea-mono w-full" ${readonly ? "readonly" : ""}>${UI.escapeHtml(Object.keys(opaque).length ? JSON.stringify(opaque, null, 2) : "{}")}</textarea>
        </details>
      </section>`;
  }

  // ── Policy read view (egress map) ────────────────────────────────────────
  // Renders the saved policy as a human-readable capability summary: where the
  // sandbox may egress, which credentials the SC injects, what DLP patterns are
  // scanned, and which inbound frames are filtered. Editing stays on the raw
  // sandbox-env rows + advanced JSON below (see sandboxEditor).

  const esc = (s) => UI.escapeHtml(s == null ? "" : String(s));
  const arr = (x) => (Array.isArray(x) ? x : []);
  const trunc = (s, n) => {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  };
  const lastSeg = (ptr) => {
    const segs = String(ptr || "").split("/").filter(Boolean);
    return segs.length ? segs[segs.length - 1] : String(ptr || "");
  };
  const fmtMethods = (m) => {
    m = arr(m);
    if (!m.length) return "ANY";
    return m.length <= 4 ? m.join(" ") : m.slice(0, 3).join(" ") + " +" + (m.length - 3);
  };
  const fmtPaths = (p) => {
    p = arr(p);
    if (!p.length || p.includes("/")) return "all paths";
    return p.length === 1 ? p[0] : p[0] + " +" + (p.length - 1);
  };
  const fmtValues = (vals, max) => {
    vals = arr(vals);
    max = max || 3;
    const head = vals.slice(0, max).map((v) => trunc(v, 12));
    return head.join(", ") + (vals.length > max ? " +" + (vals.length - max) : "");
  };
  const maskTpl = (tpl) =>
    typeof tpl === "string" && tpl.includes("${secret}") ? tpl.replace("${secret}", "••••") : "••••";
  const wildHostMatch = (a, b) => {
    if (!a || !b) return false;
    a = String(a).toLowerCase();
    b = String(b).toLowerCase();
    if (a === b) return true;
    const suf = (h) => (h.startsWith("*.") ? h.slice(1) : null);
    const sa = suf(a);
    const sb = suf(b);
    if (sb && a.endsWith(sb)) return true;
    if (sa && b.endsWith(sa)) return true;
    return false;
  };

  function destLabel(rule) {
    const scheme = rule.scheme ? `<span class="scheme">${esc(rule.scheme)}://</span>` : "";
    const ports = arr(rule.ports);
    const portTxt =
      ports.length && !(ports.length === 1 && (ports[0] === 443 || ports[0] === 80))
        ? " :" + ports.join(",")
        : "";
    return { scheme, host: esc(rule.host || "—"), portTxt: esc(portTxt) };
  }

  function allowedLane(rule, injections) {
    const { scheme, host, portTxt } = destLabel(rule);
    const bodyA = arr(rule.body_assertions);
    const wsA = arr(rule.websocket_assertions);
    const logA = arr(rule.traffic_log_attributes);
    const secrets = injections.filter((inj) => wildHostMatch(inj.match && inj.match.host, rule.host));

    const guards = [];
    if (secrets.length)
      guards.push(
        `<span class="chip chip-accent">${UI.icon("key", "h-3 w-3")} ${secrets.length} secret${secrets.length === 1 ? "" : "s"}</span>`
      );
    if (bodyA.length)
      guards.push(`<span class="chip chip-warn">${UI.icon("filter", "h-3 w-3")} body-gated</span>`);
    if (wsA.length)
      guards.push(`<span class="chip chip-accent">${UI.icon("filter", "h-3 w-3")} inbound filter</span>`);
    if (logA.length) guards.push(`<span class="chip">${UI.icon("traffic", "h-3 w-3")} logged</span>`);

    const detail = [];
    bodyA.forEach((a) =>
      detail.push(
        `<div class="row">only when <b>${esc(lastSeg(a.field))}</b> ∈ {${esc(fmtValues(a.allow_values))}} <span class="egress-mono">(${esc(a.kind)})</span></div>`
      )
    );
    wsA.forEach((w) => detail.push(`<div class="row">${wsSentence(w)}</div>`));
    logA.forEach((t) =>
      detail.push(`<div class="row">logs <b>${esc(t.name)}</b> from <span class="egress-mono">${esc(t.field)}</span></div>`)
    );

    const detailHtml = detail.length
      ? `<details class="egress-detail"><summary>guardrail details</summary><div class="rows">${detail.join("")}</div></details>`
      : "";

    return `<div class="egress-lane">
        <div class="egress-lane-head">
          <span class="host">${scheme}${host}</span>
          <span class="meta">${esc(fmtMethods(rule.methods))} · ${esc(fmtPaths(rule.path_prefixes))}${portTxt}</span>
        </div>
        ${guards.length ? `<div class="egress-guards">${guards.join("")}</div>` : ""}
        ${detailHtml}
      </div>`;
  }

  function wsSentence(w) {
    const when = w.when && typeof w.when === "object" ? w.when : {};
    const whenTxt =
      Object.entries(when)
        .map(([k, v]) => `${esc(lastSeg(k))}=${esc(trunc(v, 16))}`)
        .join(", ") || "any";
    const req = w.require && typeof w.require === "object" ? w.require : {};
    const reqTxt = Object.entries(req)
      .map(([k, m]) => `<b>${esc(lastSeg(k))}</b> ∈ {${esc(fmtValues(m && m.in))}}`)
      .join(" and ");
    const tail = reqTxt ? `deliver only when ${reqTxt}; else drop` : "drop";
    return `inbound <span class="egress-mono">${whenTxt}</span> frames: ${tail}`;
  }

  function blockedLane(rule) {
    const { scheme, host, portTxt } = destLabel(rule);
    const paths = arr(rule.path_prefixes);
    const hasPath = paths.length && !paths.includes("/");
    const isHttps = (rule.scheme || "https") === "https";
    const warn =
      hasPath && isHttps
        ? `<div class="egress-note">${UI.icon("alert", "h-3.5 w-3.5")} Path prefixes can't be enforced on an HTTPS CONNECT tunnel — this blocks the entire host.</div>`
        : "";
    return `<div class="egress-lane is-deny">
        <div class="egress-lane-head">
          <span class="host">${scheme}${host}</span>
          <span class="meta">${esc(fmtMethods(rule.methods))} · ${hasPath ? esc(fmtPaths(paths)) : "all paths"}${portTxt}</span>
        </div>${warn}
      </div>`;
  }

  function secretRow(inj) {
    const m = inj.match && typeof inj.match === "object" ? inj.match : {};
    const dest = m.host
      ? `${m.scheme ? esc(m.scheme) + "://" : ""}${esc(m.host)}${
          arr(m.path_prefixes).length && !arr(m.path_prefixes).includes("/") ? " " + esc(fmtPaths(m.path_prefixes)) : ""
        }`
      : "any allowed destination";
    return `<div class="egress-row">
        <span class="name">${esc(inj.id || "secret")}</span>
        <span class="arrow">→ sets</span>
        <span class="egress-mono">${esc(inj.header || "")}</span>:
        <span class="mask">${esc(maskTpl(inj.value_template))}</span>
        <span class="arrow">on</span>
        <span class="egress-mono">${dest}</span>
      </div>`;
  }

  function dlpRow(pat) {
    const scopeTxt =
      [pat.scan_headers ? "headers" : null, pat.scan_body ? "body" : null].filter(Boolean).join(" + ") || "—";
    return `<div class="egress-row">
        <span class="name">${esc(pat.name || pat.id || "pattern")}</span>
        <span class="egress-mono">${esc(trunc(pat.pattern, 48))}</span>
        <span class="egress-spacer"></span>
        <span class="chip">${esc(scopeTxt)}</span>
      </div>`;
  }

  function policyView(policy) {
    policy = policy && typeof policy === "object" ? policy : {};
    const allowed = arr(policy.allowed_destinations);
    const blocked = arr(policy.blocked_destinations);
    const injections = arr(policy.secret_injections);
    const patterns = arr(policy.secret_patterns);
    const env = policy.sandbox_env && typeof policy.sandbox_env === "object" ? policy.sandbox_env : {};
    const envKeys = Object.keys(env);
    const wsCount = allowed.reduce((n, r) => n + arr(r.websocket_assertions).length, 0);

    const bits = [`<span><b>${allowed.length}</b> allowed host${allowed.length === 1 ? "" : "s"}</span>`];
    if (blocked.length) bits.push(`<span><b>${blocked.length}</b> blocked</span>`);
    if (injections.length)
      bits.push(`<span><b>${injections.length}</b> secret${injections.length === 1 ? "" : "s"} injected</span>`);
    if (patterns.length) bits.push(`<span><b>${patterns.length}</b> DLP pattern${patterns.length === 1 ? "" : "s"}</span>`);
    if (wsCount) bits.push(`<span>inbound filtered</span>`);
    if (envKeys.length) bits.push(`<span><b>${envKeys.length}</b> env var${envKeys.length === 1 ? "" : "s"}</span>`);

    const laneHtml = allowed.length
      ? allowed.map((r) => allowedLane(r, injections)).join("")
      : `<div class="egress-lane is-allnone">
           <div class="egress-lane-head">
             <span class="host">${UI.icon("shield", "h-3.5 w-3.5")} Deny all egress</span>
           </div>
           <div class="egress-guards"><span class="meta">No destinations allowed — every outbound request is blocked by default.</span></div>
         </div>`;

    const sub = (icon, title, rows) =>
      `<div class="egress-sub"><div class="egress-sub-title">${UI.icon(icon, "h-3.5 w-3.5")} ${esc(title)}</div>${rows}</div>`;

    const blockedHtml = blocked.length ? sub("x", "Blocked destinations", blocked.map(blockedLane).join("")) : "";
    const secretsHtml = injections.length ? sub("key", "Injected secrets", injections.map(secretRow).join("")) : "";
    const dlpHtml = patterns.length ? sub("shield", "Data-loss prevention", patterns.map(dlpRow).join("")) : "";
    const envHtml = envKeys.length
      ? sub(
          "system",
          "Sandbox environment",
          envKeys
            .map(
              (k) =>
                `<div class="egress-row"><span class="name">${esc(k)}</span><span class="arrow">=</span><span class="egress-mono">${esc(trunc(env[k], 60))}</span></div>`
            )
            .join("")
        )
      : "";

    return `
      <section class="card card-pad mb-3">
        <header class="flex items-center gap-2 mb-3">
          <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("shield", "h-3.5 w-3.5")}</span>
          <h4 class="text-sm font-semibold text-ink">What this profile can do</h4>
          ${UI.helpHint("Rendered from the saved policy: destinations the sandbox may reach, credentials the Security CVM injects, DLP patterns scanned on egress, and inbound frames filtered. Edit the raw policy below.")}
        </header>
        <div class="egress">
          <div class="egress-summary">${bits.join("")}</div>
          <div class="egress-flow">
            <div class="egress-origin">
              <span class="glyph">${UI.icon("cvm", "h-4 w-4")}</span>
              <span class="title">Agent sandbox</span>
              <span class="conduit">${UI.icon("shield", "h-3 w-3")} guarded egress</span>
            </div>
            <div class="egress-lanes">${laneHtml}</div>
          </div>
          ${blockedHtml}${secretsHtml}${dlpHtml}${envHtml}
        </div>
      </section>`;
  }

  async function renderProfiles() {
    const panel = A.el("panel-profiles");
    const eid = A.viewEntityId();
    const canManage = A.canManageProfiles();
    if (!eid) {
      panel.innerHTML = UI.pageHeader("Profiles", "Policy bundles attached to your CVMs.", { icon: "profile" }) + UI.emptyV2({ icon: "profile", title: "No entity selected", body: "Pick an entity from the top bar to see its profiles." });
      return;
    }
    const listRes = await A.api("/api/v1/entities/" + eid + "/profiles");
    if (!listRes.ok) {
      panel.innerHTML =
        UI.pageHeader("Profiles", "Policy bundles attached to your CVMs.", { icon: "profile" }) +
        UI.emptyV2({ icon: "alert", title: "Failed to load profiles", body: await A.parseError(listRes) });
      return;
    }
    const items = (await listRes.json()).items || [];
    if (!A.selectedProfileId && items.length) A.selectedProfileId = items[0].id;

    const listHtml = items
      .map(
        (p) => `
          <button type="button" class="block w-full text-left px-3 py-2.5 border-b border-line/60 transition-colors ${p.id === A.selectedProfileId ? "bg-accent/10 text-ink border-l-2 border-l-accent" : "hover:bg-elev text-ink"}" data-pid="${UI.escapeHtml(p.id)}">
            <div class="flex items-center justify-between gap-2">
              <span class="text-sm font-medium truncate">${UI.escapeHtml(p.name)}</span>
              ${p.assigned ? `<span class="chip chip-accent">member</span>` : ""}
            </div>
            <div class="mt-1 flex items-center gap-3 text-2xs text-mute">
              <span class="inline-flex items-center gap-1">${UI.icon("cvm", "h-3 w-3")} ${p.attached_cvm_count ?? 0} CVM${(p.attached_cvm_count ?? 0) === 1 ? "" : "s"}</span>
              ${p.member_count != null ? `<span class="inline-flex items-center gap-1">${UI.icon("users", "h-3 w-3")} ${p.member_count} member${p.member_count === 1 ? "" : "s"}</span>` : ""}
            </div>
          </button>`
      )
      .join("");

    let editor = UI.emptyV2({ icon: "profile", title: "Select a profile", body: items.length ? "Pick a profile from the list to view and edit its policy and members." : "No profiles yet." });
    if (A.selectedProfileId && items.length) {
      editor = await renderEditor(panel);
    }

    const createBtn = canManage
      ? `<button type="button" class="btn btn-primary" id="profile-create">${UI.icon("plus", "h-4 w-4")} Create profile</button>`
      : "";

    panel.innerHTML =
      UI.pageHeader("Profiles", "A profile bundles the egress policy, environment, secret injection rules, and member list that govern a CVM. Attach a profile to a CVM to apply its rules.", {
        icon: "profile",
        actions: createBtn,
      }) +
      `<div class="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-4">
        <div class="card overflow-hidden">
          <header class="px-3 py-2 border-b border-line bg-elev/40">
            <h3 class="section-title">${items.length} profile${items.length === 1 ? "" : "s"}</h3>
          </header>
          <div class="max-h-[640px] overflow-auto">
            ${listHtml || UI.emptyV2({ icon: "profile", title: "No profiles yet", body: canManage ? "Create one to define what your CVMs can do." : "Ask an admin to create one." })}
          </div>
        </div>
        <div>${editor}</div>
      </div>`;

    bindHandlers(panel);
  }

  async function renderEditor() {
    const res = await A.api("/api/v1/profiles/" + A.selectedProfileId);
    if (!res.ok) return UI.emptyV2({ icon: "alert", title: "Failed to load profile" });
    const p = await res.json();
    const etag = res.headers.get("ETag") || "";
    if (!etag) {
      console.warn("Profile ETag not found in response headers");
    }
    const readonly = !A.canManageProfiles();
    const attached = (p.attached_cvms || [])
      .map(
        (c) => `<button type="button" class="chip chip-accent chip-button" data-cvm="${UI.escapeHtml(c.id)}">${UI.icon("cvm", "h-3 w-3")}${UI.escapeHtml(c.fqdn || c.id)} <span class="text-mute-soft">${UI.escapeHtml(c.state)}</span></button>`
      )
      .join("");

    return `
      <input type="hidden" id="profile-etag" value="${UI.escapeHtml(etag)}">

      <section class="card card-pad mb-3">
        <header class="flex items-center justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("profile", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink truncate">${UI.escapeHtml(p.name)}</h4>
            ${UI.copyButton(p.id, p.id.slice(0, 10) + "…")}
          </div>
          <div class="flex items-center gap-2">
            ${readonly ? `<span class="chip">read-only</span>` : `<button type="button" class="btn btn-primary btn-sm" id="profile-save">${UI.icon("check", "h-3.5 w-3.5")} Save</button>`}
            ${readonly ? "" : `<button type="button" class="btn btn-ghost btn-sm" id="profile-delete">${UI.icon("x", "h-3.5 w-3.5")}</button>`}
          </div>
        </header>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label class="field-label">Name</label>
            <input id="profile-name" class="input" ${readonly ? "disabled" : ""} value="${UI.escapeHtml(p.name)}">
          </div>
          <div>
            <label class="field-label">Description</label>
            <input id="profile-desc" class="input" ${readonly ? "disabled" : ""} placeholder="What is this profile for?" value="${UI.escapeHtml(p.description || "")}">
          </div>
        </div>
        <div id="profile-msg" class="mt-2 text-sm"></div>
      </section>

      ${policyView(p.policy || {})}

      ${readonly ? "" : sandboxEditor(p.policy || {}, false)}

      <section class="card card-pad mb-3">
        <header class="flex items-center gap-2 mb-2">
          <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("cvm", "h-3.5 w-3.5")}</span>
          <h4 class="text-sm font-semibold text-ink">Attached CVMs</h4>
          ${UI.helpHint("CVMs that currently apply this profile's policy.")}
        </header>
        <p class="text-xs text-mute mb-2">${(p.attached_cvms || []).length} CVM${(p.attached_cvms || []).length === 1 ? "" : "s"} apply this profile.</p>
        <div class="flex flex-wrap gap-2">${attached || `<span class="text-xs text-mute italic">No CVMs currently attached. Attach this profile when launching or via the CVM detail drawer.</span>`}</div>
      </section>

      ${readonly ? "" : await membersSection(p.id)}
    `;
  }

  async function membersSection(profileId) {
    const res = await A.api("/api/v1/profiles/" + profileId + "/users");
    const members = res.ok ? (await res.json()).items || [] : [];
    return `
      <section class="card card-pad">
        <header class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("users", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink">Members</h4>
            ${UI.helpHint("Users authorized to launch CVMs that bind this profile.")}
          </div>
          <button type="button" class="btn btn-sm" id="member-add-open">${UI.icon("plus", "h-3.5 w-3.5")} Add member</button>
        </header>
        <p class="text-xs text-mute mb-2">${members.length} member${members.length === 1 ? "" : "s"}</p>
        ${members.length
          ? `<ul class="divide-y divide-line/60">${members
              .map(
                (m) => `
                  <li class="flex items-center justify-between py-2">
                    <div class="flex items-center gap-2 min-w-0">
                      <span class="flex h-6 w-6 items-center justify-center rounded-full bg-elev text-mute">${UI.icon("user", "h-3 w-3")}</span>
                      <span class="text-sm text-ink truncate">${UI.escapeHtml(m.email)}</span>
                    </div>
                    <button type="button" class="btn btn-ghost btn-xs" data-rm-member="${UI.escapeHtml(m.user_id)}" data-rm-email="${UI.escapeHtml(m.email)}">${UI.icon("x", "h-3.5 w-3.5")} Remove</button>
                  </li>`
              )
              .join("")}</ul>`
          : `<p class="text-xs text-mute italic">No members yet. Add users so they can launch CVMs with this profile.</p>`}
      </section>`;
  }

  function bindHandlers(panel) {
    panel.querySelectorAll("[data-pid]").forEach((btn) => {
      btn.addEventListener("click", () => {
        A.selectedProfileId = btn.dataset.pid;
        renderProfiles();
      });
    });
    panel.querySelector("#profile-create")?.addEventListener("click", openCreateModal);
    panel.querySelector("#profile-save")?.addEventListener("click", saveProfile);
    panel.querySelector("#profile-delete")?.addEventListener("click", deleteProfile);
    panel.querySelector("#add-sandbox-row")?.addEventListener("click", () => {
      const wrap = panel.querySelector("#sandbox-rows");
      const idx = wrap.children.length;
      const div = document.createElement("div");
      div.className = "flex items-center gap-2 mb-1.5";
      div.dataset.sandboxRow = String(idx);
      div.innerHTML = `
        <input data-sandbox-key class="input input-sm font-mono flex-1" placeholder="VAR_NAME">
        <input data-sandbox-val class="input input-sm font-mono flex-1" placeholder="value">
        <button type="button" class="btn btn-ghost btn-xs" data-rm-sandbox aria-label="Remove">${UI.icon("x", "h-3.5 w-3.5")}</button>`;
      wrap.appendChild(div);
      div.querySelector("[data-rm-sandbox]").onclick = () => div.remove();
    });
    panel.querySelectorAll("[data-rm-sandbox]").forEach((btn) => {
      btn.onclick = () => btn.closest("[data-sandbox-row]")?.remove();
    });
    panel.querySelectorAll("[data-cvm]").forEach((btn) => {
      btn.addEventListener("click", () => A.Drawer.openCvm(btn.dataset.cvm, "summary"));
    });
    panel.querySelector("#member-add-open")?.addEventListener("click", openAddMemberModal);
    panel.querySelectorAll("[data-rm-member]").forEach((btn) => {
      btn.addEventListener("click", () => removeMember(btn.dataset.rmMember, btn.dataset.rmEmail));
    });
  }

  function openCreateModal() {
    UI.dialog({
      title: "Create profile",
      subtitle: "A profile groups your CVMs under a shared policy. After creating, attach members and assign it to CVMs on launch.",
      primary: { label: "Create profile", run: createProfile },
      body: `
        <div class="space-y-3">
          <div>
            <label class="field-label">Name <span class="text-err">*</span></label>
            <input id="cp-name" class="input" placeholder="e.g. engineering-default" autocomplete="off">
            <span class="field-hint">Used to reference this profile from the CLI and to identify it in CVM launches.</span>
          </div>
          <div>
            <label class="field-label">Description</label>
            <input id="cp-desc" class="input" placeholder="What is this profile for?" autocomplete="off">
          </div>
        </div>`,
      onBind: (overlay) => overlay.querySelector("#cp-name").focus(),
    });
  }

  async function createProfile(overlay) {
    const name = overlay.querySelector("#cp-name").value.trim();
    const desc = overlay.querySelector("#cp-desc").value.trim();
    if (!name) {
      UI.toast("Name is required", "err");
      return false;
    }
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify({ name, description: desc }),
    });
    if (!response.ok) {
      UI.toast(await A.parseError(response), "err");
      return false;
    }
    const p = await response.json();
    A.selectedProfileId = p.id;
    UI.toast("Profile created", "ok");
    renderProfiles();
  }

  async function saveProfile() {
    const panel = A.el("panel-profiles");
    const msg = panel.querySelector("#profile-msg");
    const etag = panel.querySelector("#profile-etag")?.value;
    let policy;
    try {
      policy = policyFromEditor(panel);
    } catch (e) {
      msg.innerHTML = `<span class="text-err">${UI.escapeHtml(e.message)}</span>`;
      return;
    }
    const body = {
      name: panel.querySelector("#profile-name").value,
      description: panel.querySelector("#profile-desc").value,
      policy,
    };
    const response = await A.api("/api/v1/profiles/" + A.selectedProfileId, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        ...(etag ? { "If-Match": etag } : {}),
      },
      body: JSON.stringify(body),
    });
    if (response.ok) {
      UI.toast("Profile saved", "ok");
      renderProfiles();
    } else {
      msg.innerHTML = `<span class="text-err">${UI.escapeHtml(await A.parseError(response))}</span>`;
    }
  }

  async function deleteProfile() {
    const panel = A.el("panel-profiles");
    const etag = panel.querySelector("#profile-etag")?.value;
    const ok = await UI.strongConfirm({
      title: "Delete profile",
      body: "Removes this profile and detaches it from any CVM. CVMs that currently use it will lose its policy. Type DELETE to confirm.",
      confirmWord: "DELETE",
      primary: "Delete",
      danger: true,
    });
    if (!ok) return;
    const response = await A.api("/api/v1/profiles/" + A.selectedProfileId, {
      method: "DELETE",
      headers: etag ? { "If-Match": etag } : {},
    });
    if (response.status === 204 || response.ok) {
      A.selectedProfileId = null;
      UI.toast("Profile deleted", "ok");
      renderProfiles();
    } else UI.toast(await A.parseError(response), "err");
  }

  async function openAddMemberModal() {
    const profileId = A.selectedProfileId;
    if (!profileId) return;
    const [usersRes, membersRes] = await Promise.all([
      A.api("/api/v1/entities/" + A.viewEntityId() + "/users"),
      A.api("/api/v1/profiles/" + profileId + "/users"),
    ]);
    const users = usersRes.ok ? (await usersRes.json()).items || [] : [];
    const members = membersRes.ok ? (await membersRes.json()).items || [] : [];
    const memberIds = new Set(members.map((m) => m.user_id));
    const candidates = users.filter((u) => !memberIds.has(u.id) && u.state === "active");

    if (!candidates.length) {
      UI.toast("All active users are already members", "info");
      return;
    }
    UI.dialog({
      title: "Add member to profile",
      subtitle: "Members are the users authorized to launch CVMs that bind this profile.",
      primary: { label: "Add member", run: addMember },
      body: `
        <div>
          <label class="field-label">Search</label>
          <input class="input mb-3" data-member-search placeholder="Filter by email…">
        </div>
        <div class="max-h-64 overflow-auto rounded-input border border-line">
          ${candidates.map((u) => `
            <label class="flex items-center gap-2 px-3 py-2 border-b border-line/60 hover:bg-elev cursor-pointer last:border-b-0" data-member-row="${UI.escapeHtml(u.email)}">
              <input type="radio" name="member-pick" value="${UI.escapeHtml(u.id)}" class="accent-accent">
              <span class="flex h-6 w-6 items-center justify-center rounded-full bg-elev text-mute">${UI.icon("user", "h-3 w-3")}</span>
              <span class="text-sm text-ink truncate">${UI.escapeHtml(u.email)}</span>
            </label>
          `).join("")}
        </div>`,
      onBind: (overlay) => {
        overlay.querySelector("[data-member-search]")?.addEventListener("input", (e) => {
          const q = e.target.value.toLowerCase();
          overlay.querySelectorAll("[data-member-row]").forEach((row) => {
            row.style.display = row.dataset.memberRow.toLowerCase().includes(q) ? "" : "none";
          });
        });
      },
    });
  }

  async function addMember(overlay) {
    const picked = overlay.querySelector("input[name=member-pick]:checked");
    if (!picked) {
      UI.toast("Select a user", "err");
      return false;
    }
    const userId = picked.value;
    const etag = A.el("panel-profiles").querySelector("#profile-etag")?.value;
    const response = await A.api("/api/v1/profiles/" + A.selectedProfileId + "/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(etag ? { "If-Match": etag } : {}),
      },
      body: JSON.stringify({ user_id: userId }),
    });
    if (response.ok) {
      UI.toast("Member added", "ok");
      renderProfiles();
    } else {
      UI.toast(await A.parseError(response), "err");
      return false;
    }
  }

  async function removeMember(userId, email) {
    const ok = await UI.confirm({
      title: "Remove member",
      message: `Remove ${email || "this user"} from the profile? They will lose the ability to launch CVMs that bind this profile.`,
      okLabel: "Remove",
      danger: true,
    });
    if (!ok) return;
    const panel = A.el("panel-profiles");
    const etag = panel.querySelector("#profile-etag")?.value;
    const response = await A.api("/api/v1/profiles/" + A.selectedProfileId + "/users/" + userId, {
      method: "DELETE",
      headers: etag ? { "If-Match": etag } : {},
    });
    if (response.status === 204 || response.ok) {
      UI.toast("Member removed", "ok");
      renderProfiles();
    } else UI.toast(await A.parseError(response), "err");
  }

  A.Views = A.Views || {};
  A.Views.renderProfiles = renderProfiles;
  // Pure policy renderer, reusable read-only (e.g. CVM drawer effective policy).
  A.Views.profilePolicyView = policyView;
})(window.Admin);
