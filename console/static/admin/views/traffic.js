(function (A) {
  const UI = A.UI;

  function ensureState() {
    A.trafficState = A.trafficState || { from: "", to: "", hostFilter: "", granularity: "auto", items: [], nextCursor: null, summary: null, timeseries: null, gen: 0, loading: false };
    if (!A.trafficState.granularity) A.trafficState.granularity = "auto";
    return A.trafficState;
  }

  function rangeParams(st) {
    const p = {};
    if (st.from) p.from = new Date(st.from).toISOString();
    if (st.to) p.to = new Date(st.to).toISOString();
    return p;
  }

  function timeseriesParams(st) {
    const p = { buckets: "60", ...rangeParams(st) };
    if (st.granularity && st.granularity !== "auto") p.granularity = st.granularity;
    if (st.hostFilter) p.destination_host = st.hostFilter;
    return p;
  }

  function logParams(st, withCursor) {
    const p = { limit: "80", ...rangeParams(st) };
    if (st.hostFilter) p.destination_host = st.hostFilter;
    if (withCursor && st.nextCursor) p.cursor = st.nextCursor;
    return p;
  }

  // Entry point: reset accumulation, then fetch the first page plus the
  // window-wide host summary (per-host totals over the whole selected range,
  // independent of how many rows are paged into the table).
  async function renderTraffic() {
    const st = ensureState();
    // Bump the generation so any page fetch still in flight from a previous
    // filter is recognized as stale and dropped instead of polluting this view.
    const gen = st.gen = (st.gen || 0) + 1;
    st.items = [];
    st.nextCursor = null;
    st.loading = false;
    const [body, summary, timeseries] = await Promise.all([
      A.fetchTrafficLogs(logParams(st, false)),
      A.fetchTrafficHostSummary(rangeParams(st)),
      A.fetchTrafficTimeseries(timeseriesParams(st)),
    ]);
    if (gen !== st.gen) return;
    st.items = body.items || [];
    st.nextCursor = body.next_cursor || null;
    st.summary = summary;
    st.timeseries = timeseries;
    draw(st);
  }

  // Append the next page; never discard already-loaded rows.
  async function loadMore() {
    const st = ensureState();
    if (!st.nextCursor || st.loading) return;
    st.loading = true;
    const gen = st.gen;
    const body = await A.fetchTrafficLogs(logParams(st, true));
    if (gen !== st.gen) return; // a filter change superseded this page
    st.loading = false;
    st.items = st.items.concat(body.items || []);
    st.nextCursor = body.next_cursor || null;
    draw(st);
  }

  function bucketLabel(sec) {
    sec = Number(sec) || 0;
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.round(sec / 60)} min`;
    const h = sec / 3600;
    return `${h % 1 ? h.toFixed(1) : h} h`;
  }

  const GRANULARITIES = [["auto", "Auto"], ["day", "Day"], ["week", "Week"], ["month", "Month"]];

  // How a single bucket reads as a period, given the resolved granularity.
  function periodLabel(ts) {
    const g = ts && ts.granularity;
    if (g === "day") return "per day";
    if (g === "week") return "per week";
    if (g === "month") return "per month";
    if (g === "hour") return "per hour";
    return ts && ts.bucket_seconds ? `per ${bucketLabel(ts.bucket_seconds)}` : "";
  }

  // Format a bucket label for the x-axis, adapting to the chart's granularity.
  function axisTime(iso, ts) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const g = ts && ts.granularity;
    const iso10 = d.toISOString();
    if (g === "month") return iso10.slice(0, 7); // YYYY-MM
    if (g === "week" || g === "day") return iso10.slice(5, 10); // MM-DD
    const span = (ts && ts.bucket_seconds ? ts.bucket_seconds : 0) * Math.max(1, ((ts && ts.buckets) || []).length - 1);
    const hm = iso10.slice(11, 16);
    return span > 2 * 86400 ? `${iso10.slice(5, 10)} ${hm}` : hm;
  }

  // Per-period volume bars (allowed blue, blocked stacked red) so spikes stand
  // out, plus a cumulative running-total line (gold, right-scaled) that climbs
  // across the window as proof of growth. The hover overlay is positioned in %
  // so it never distorts with the non-uniformly scaled SVG.
  function chartCard(ts, st) {
    const pts = (ts && ts.buckets) || [];
    const totals = (ts && ts.totals) || { allowed: 0, blocked: 0, total: 0, peak: 0, peak_ts: null };
    const n = pts.length;
    const H = 100;
    const W = Math.max(1, n);
    const volMax = Math.max(1, totals.peak || 0);
    const cumMax = Math.max(1, totals.total || 0);
    const barW = n > 120 ? 0.9 : 0.7; // thin gaps when there are many periods
    const pad = (1 - barW) / 2;

    let barsSvg = "";
    let cumLine = "";
    if (n) {
      barsSvg = pts
        .map((p, i) => {
          const ha = (p.allowed / volMax) * H;
          const hb = (p.blocked / volMax) * H;
          const x = i + pad;
          const aY = H - ha;
          const bY = H - ha - hb;
          const a = ha > 0 ? `<rect class="tchart-bar-allow" x="${x}" y="${aY}" width="${barW}" height="${ha}"/>` : "";
          const b = hb > 0 ? `<rect class="tchart-bar-block" x="${x}" y="${bY}" width="${barW}" height="${hb}"/>` : "";
          return a + b;
        })
        .join("");
      const cum = pts.map((p, i) => `${i + 0.5} ${H - (p.cumulative / cumMax) * H}`);
      cumLine = `M ${cum.join(" L ")}`;
    }

    const allowedPct = totals.total ? Math.round((totals.allowed / totals.total) * 100) : 0;
    const blockedPct = totals.total ? 100 - allowedPct : 0;

    const tickCount = Math.min(6, n);
    const ticks = n
      ? Array.from({ length: tickCount }, (_, k) => {
          const i = tickCount === 1 ? 0 : Math.round((k * (n - 1)) / (tickCount - 1));
          return `<span>${UI.escapeHtml(axisTime(pts[i].ts, ts))}</span>`;
        }).join("")
      : "";

    const granButtons = GRANULARITIES.map(
      ([key, label]) =>
        `<button type="button" class="filter-chip ${(st.granularity || "auto") === key ? "active" : ""}" data-gran="${key}">${label}</button>`
    ).join("");

    const peakLabel = totals.peak ? `${totals.peak.toLocaleString()}${ts && ts.granularity !== "auto" ? "/" + (ts.granularity === "day" ? "day" : ts.granularity === "week" ? "wk" : ts.granularity === "month" ? "mo" : ts.granularity) : ""}` : "—";

    return `
      <div class="card card-pad mb-4">
        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 mb-1">
          <h3 class="text-sm font-semibold text-ink">Egress over time</h3>
          <div class="flex items-center gap-3 text-2xs text-mute">
            <span>${totals.total.toLocaleString()} request${totals.total === 1 ? "" : "s"}</span>
            <span class="inline-flex items-center gap-1"><span class="tchart-tip-sw is-allow"></span>${allowedPct}% allowed</span>
            <span class="inline-flex items-center gap-1"><span class="tchart-tip-sw is-block"></span>${blockedPct}% blocked</span>
            <span class="inline-flex items-center gap-1" title="Busiest ${UI.escapeHtml(periodLabel(ts) || "bucket")}"><span class="tchart-tip-sw is-cum"></span>peak ${UI.escapeHtml(peakLabel)}</span>
          </div>
          <div class="tchart-gran ml-auto">${granButtons}</div>
        </div>
        <div class="flex items-center justify-between text-2xs text-mute mb-2">
          <span class="inline-flex items-center gap-1"><span class="tchart-tip-sw is-cum"></span>cumulative total ${UI.escapeHtml(periodLabel(ts))}</span>
          ${ts ? `<span>${UI.escapeHtml(UI.fmtTsShort(ts.from))} → ${UI.escapeHtml(UI.fmtTsShort(ts.to))}</span>` : ""}
        </div>
        <div class="tchart" data-tchart>
          <div class="tchart-ymax">${volMax.toLocaleString()}</div>
          <div class="tchart-cmax">Σ ${cumMax.toLocaleString()}</div>
          <svg class="tchart-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
            <line class="tchart-baseline" x1="0" y1="${H}" x2="${W}" y2="${H}" vector-effect="non-scaling-stroke"/>
            ${barsSvg}
            <path class="tchart-cum-line" d="${cumLine}" vector-effect="non-scaling-stroke"/>
          </svg>
          <div class="tchart-overlay">
            <div class="tchart-guide" data-guide></div>
            <div class="tchart-peak" data-peak></div>
            <div class="tchart-dot" data-dot></div>
            <div class="tchart-tip" data-tip></div>
          </div>
          ${totals.total ? "" : `<div class="tchart-empty">No egress in this window.</div>`}
        </div>
        <div class="tchart-xaxis">${ticks}</div>
      </div>`;
  }

  function wireChart(panel, ts) {
    const pts = (ts && ts.buckets) || [];
    const root = panel.querySelector("[data-tchart]");
    if (!root || !pts.length) return;
    const totals = (ts && ts.totals) || {};
    const guide = root.querySelector("[data-guide]");
    const dot = root.querySelector("[data-dot]");
    const tip = root.querySelector("[data-tip]");
    const peak = root.querySelector("[data-peak]");
    const cumMax = Math.max(1, totals.total || 0);
    const n = pts.length;
    const centerPct = (i) => ((i + 0.5) / n) * 100;

    // Mark the peak bar so the busiest period is obvious at a glance. The bar is
    // scaled against the peak, so its top sits at y=0 (100% tall) — the marker
    // rides just above it.
    const peakIdx = totals.peak_ts ? pts.findIndex((p) => p.ts === totals.peak_ts) : -1;
    if (peak && peakIdx >= 0 && totals.peak > 0) {
      peak.style.left = centerPct(peakIdx) + "%";
      peak.style.top = "0%";
      peak.title = `Peak: ${totals.peak.toLocaleString()} on ${UI.fmtTsShort(totals.peak_ts)}`;
      peak.style.display = "block";
    }

    root.addEventListener("mousemove", (e) => {
      const r = root.getBoundingClientRect();
      const fx = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
      const i = Math.min(n - 1, Math.max(0, Math.floor(fx * n)));
      const p = pts[i];
      const xpct = centerPct(i);
      const ypct = 100 - (p.cumulative / cumMax) * 100; // dot rides the cumulative line
      guide.style.left = xpct + "%";
      guide.style.display = "block";
      dot.style.left = xpct + "%";
      dot.style.top = ypct + "%";
      dot.style.display = "block";
      tip.style.left = xpct + "%";
      tip.style.top = ypct + "%";
      tip.innerHTML =
        `<div class="tchart-tip-time">${UI.escapeHtml(UI.fmtTsShort(p.ts))}</div>` +
        `<div class="tchart-tip-row"><span class="tchart-tip-sw is-allow"></span>Allowed<span class="tchart-tip-val">${p.allowed.toLocaleString()}</span></div>` +
        `<div class="tchart-tip-row"><span class="tchart-tip-sw is-block"></span>Blocked<span class="tchart-tip-val">${p.blocked.toLocaleString()}</span></div>` +
        `<div class="tchart-tip-row"><span class="tchart-tip-sw is-cum"></span>Cumulative<span class="tchart-tip-val">${p.cumulative.toLocaleString()}</span></div>`;
      tip.style.display = "block";
    });
    root.addEventListener("mouseleave", () => {
      guide.style.display = "none";
      dot.style.display = "none";
      tip.style.display = "none";
    });
  }

  function draw(st) {
    const panel = A.el("panel-traffic");
    if (!panel) return;
    const items = st.items;

    const hosts = (st.summary && st.summary.hosts) || [];
    const max = Math.max(1, ...hosts.map((h) => h.count));
    const bars = hosts
      .slice(0, 8)
      .map((h) => {
        const active = st.hostFilter === h.host;
        return `
          <button type="button" class="w-full flex items-center gap-2 text-left text-xs hover:bg-elev rounded px-1.5 py-1 -mx-1.5 ${active ? "bg-accent/10" : ""}" data-host-filter="${UI.escapeHtml(h.host)}">
            <span class="flex-1 truncate font-mono text-2xs ${active ? "text-accent" : "text-ink-dim"}">${UI.escapeHtml(h.host)}</span>
            <span class="text-2xs text-mute w-12 text-right">${UI.escapeHtml(h.count.toLocaleString())}</span>
            <div class="w-24 h-1.5 rounded-full bg-bg overflow-hidden"><div class="h-full bg-accent" style="width:${Math.round((h.count / max) * 100)}%"></div></div>
          </button>`;
      })
      .join("");

    const cols = [
      { key: "timestamp", label: "Time", render: (t) => `<span class="text-mute" title="${UI.escapeHtml(UI.fmtTsFull(t.timestamp))}">${UI.escapeHtml(UI.fmtTsShort(t.timestamp))}</span>` },
      { key: "cvm_id", label: "CVM", render: (t) => t.cvm_id ? UI.copyButton(t.cvm_id, String(t.cvm_id).slice(0, 8)) : '<span class="text-mute">—</span>' },
      { key: "method", label: "Method", render: (t) => `<span class="font-mono text-2xs text-ink">${UI.escapeHtml(t.method || "—")}</span>` },
      { key: "host", label: "Host", render: (t) => `<span class="font-mono text-2xs">${UI.escapeHtml(t.destination_host || "—")}</span>` },
      { key: "path", label: "Path", render: (t) => `<span class="font-mono text-2xs text-mute" title="${UI.escapeHtml(t.path || "")}">${UI.escapeHtml(truncate(t.path || "—", 50))}</span>` },
      { key: "code", label: "Status", render: (t) => `<span class="${UI.codeClass(t.response_code)} font-medium">${t.response_code ?? "—"}</span>` },
      { key: "bytes", label: "Bytes", align: "right", render: (t) => UI.escapeHtml(UI.fmtBytes(t.bytes_transferred)) },
    ];

    const table = items.length
      ? UI.tableV2(cols, items, { onRowClick: true, tall: true })
      : UI.emptyV2({ icon: "traffic", title: "No egress events", body: "Either nothing was sent in this window, or the Security CVM isn't logging yet." });

    const footer = items.length
      ? `<div class="mt-3 flex items-center justify-center gap-3">
           <span class="text-2xs text-mute">Showing ${items.length.toLocaleString()} event${items.length === 1 ? "" : "s"}${st.nextCursor ? "" : " — end of range"}</span>
           ${st.nextCursor ? `<button type="button" class="btn btn-sm" id="traffic-more">${UI.icon("chevron-down", "h-3.5 w-3.5")} Load more</button>` : ""}
         </div>`
      : "";

    panel.innerHTML =
      UI.pageHeader("Egress traffic", "Every outbound request from your CVMs, captured at the Security CVM. Click a row to open the CVM's full egress detail.", { icon: "traffic" }) +
      `<div class="card card-pad mb-4">
        <div class="flex flex-wrap items-center gap-2 mb-3">
          ${UI.dateRange({ id: "traffic-range", from: st.from, to: st.to, presets: [["24h", "24h"], ["7d", "7d"], ["30d", "30d"], ["90d", "90d"], ["1y", "1y"], ["custom", "Custom"]] })}
          ${st.hostFilter ? `<span class="chip chip-accent">${UI.icon("filter", "h-3 w-3")} host = ${UI.escapeHtml(st.hostFilter)}<button type="button" class="ml-1 text-mute hover:text-ink" id="clear-host">×</button></span>` : ""}
          <button type="button" class="btn btn-ghost btn-xs ml-auto" id="traffic-clear">${UI.icon("x", "h-3.5 w-3.5")} Clear filters</button>
        </div>
      </div>

      ${chartCard(st.timeseries, st)}

      <div class="grid grid-cols-1 md:grid-cols-[1fr_320px] gap-4">
        <div>${table}${footer}</div>
        <aside class="card card-pad self-start">
          <header class="mb-3">
            <h3 class="text-sm font-semibold text-ink">Top hosts (whole range)</h3>
            <p class="text-2xs text-mute">Totals across the selected time range. Click a host to filter the log to it.</p>
          </header>
          <div class="space-y-0.5">${bars || `<span class="text-xs text-mute italic">No hosts in this range.</span>`}</div>
        </aside>
      </div>`;

    wireChart(panel, st.timeseries);

    panel.querySelector("[data-date-range=traffic-range]")?.addEventListener("range-change", (e) => {
      st.from = e.detail.from;
      st.to = e.detail.to;
      renderTraffic();
    });
    panel.querySelectorAll("[data-gran]").forEach((b) => {
      b.addEventListener("click", () => {
        st.granularity = b.dataset.gran;
        renderTraffic();
      });
    });
    panel.querySelectorAll("[data-host-filter]").forEach((b) => {
      b.addEventListener("click", () => {
        st.hostFilter = st.hostFilter === b.dataset.hostFilter ? "" : b.dataset.hostFilter;
        renderTraffic();
      });
    });
    panel.querySelector("#clear-host")?.addEventListener("click", () => {
      st.hostFilter = "";
      renderTraffic();
    });
    panel.querySelector("#traffic-clear")?.addEventListener("click", () => {
      A.trafficState = null;
      renderTraffic();
    });
    panel.querySelector("#traffic-more")?.addEventListener("click", loadMore);
    panel.querySelectorAll("tbody tr[data-row-idx]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-copy]")) return;
        const t = items[Number(tr.dataset.rowIdx)];
        if (t?.cvm_id) A.Drawer.openCvm(t.cvm_id, "egress");
      });
    });
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  A.Views = A.Views || {};
  A.Views.renderTraffic = renderTraffic;
})(window.Admin);
