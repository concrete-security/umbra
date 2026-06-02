(function (A) {
  const UI = A.UI;

  function ensureState() {
    A.trafficState = A.trafficState || { from: "", to: "", hostFilter: "", items: [], nextCursor: null, summary: null, gen: 0, loading: false };
    return A.trafficState;
  }

  function rangeParams(st) {
    const p = {};
    if (st.from) p.from = new Date(st.from).toISOString();
    if (st.to) p.to = new Date(st.to).toISOString();
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
    const [body, summary] = await Promise.all([
      A.fetchTrafficLogs(logParams(st, false)),
      A.fetchTrafficHostSummary(rangeParams(st)),
    ]);
    if (gen !== st.gen) return;
    st.items = body.items || [];
    st.nextCursor = body.next_cursor || null;
    st.summary = summary;
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
          ${UI.dateRange({ id: "traffic-range", from: st.from, to: st.to })}
          ${st.hostFilter ? `<span class="chip chip-accent">${UI.icon("filter", "h-3 w-3")} host = ${UI.escapeHtml(st.hostFilter)}<button type="button" class="ml-1 text-mute hover:text-ink" id="clear-host">×</button></span>` : ""}
          <button type="button" class="btn btn-ghost btn-xs ml-auto" id="traffic-clear">${UI.icon("x", "h-3.5 w-3.5")} Clear filters</button>
        </div>
      </div>

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

    panel.querySelector("[data-date-range=traffic-range]")?.addEventListener("range-change", (e) => {
      st.from = e.detail.from;
      st.to = e.detail.to;
      renderTraffic();
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
