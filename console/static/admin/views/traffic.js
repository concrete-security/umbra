(function (A) {
  const UI = A.UI;

  function ensureState() {
    A.trafficState = A.trafficState || { from: "", to: "", hostFilter: "", cursor: null };
    return A.trafficState;
  }

  async function renderTraffic() {
    const panel = A.el("panel-traffic");
    if (!panel) return;
    const st = ensureState();
    const params = { limit: "80" };
    if (st.from) params.from = new Date(st.from).toISOString();
    if (st.to) params.to = new Date(st.to).toISOString();
    if (st.hostFilter) params.destination_host = st.hostFilter;
    if (st.cursor) params.cursor = st.cursor;
    const body = await A.fetchTrafficLogs(params);
    const items = body.items || [];

    const hostCounts = {};
    items.forEach((t) => {
      const h = t.destination_host || "—";
      hostCounts[h] = (hostCounts[h] || 0) + 1;
    });
    const hosts = Object.entries(hostCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max = Math.max(1, ...hosts.map((h) => h[1]));
    const bars = hosts
      .map(
        ([h, n]) => `
          <button type="button" class="w-full flex items-center gap-2 text-left text-xs hover:bg-elev rounded px-1.5 py-1 -mx-1.5 ${st.hostFilter === h ? "bg-accent/10" : ""}" data-host-filter="${UI.escapeHtml(h)}">
            <span class="flex-1 truncate font-mono text-2xs ${st.hostFilter === h ? "text-accent" : "text-ink-dim"}">${UI.escapeHtml(h)}</span>
            <span class="text-2xs text-mute w-8 text-right">${n}</span>
            <div class="w-24 h-1.5 rounded-full bg-bg overflow-hidden"><div class="h-full bg-accent" style="width:${Math.round((n / max) * 100)}%"></div></div>
          </button>`
      )
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
      ? UI.tableV2(cols, items, {
          onRowClick: true,
          rowAttr: (t) => `data-traffic-idx="${items.indexOf(t)}"`,
          tall: true,
        })
      : UI.emptyV2({ icon: "traffic", title: "No egress events", body: "Either nothing was sent in this window, or the Security CVM isn't logging yet." });

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
        <div>${table}
          ${body.next_cursor ? `<div class="mt-3 flex justify-center"><button type="button" class="btn btn-sm" id="traffic-more">${UI.icon("chevron-down", "h-3.5 w-3.5")} Load more</button></div>` : ""}
        </div>
        <aside class="card card-pad self-start">
          <header class="mb-3">
            <h3 class="text-sm font-semibold text-ink">Top hosts (this view)</h3>
            <p class="text-2xs text-mute">Click a host to filter the log to it.</p>
          </header>
          <div class="space-y-0.5">${bars || `<span class="text-xs text-mute italic">No hosts in this window.</span>`}</div>
        </aside>
      </div>`;

    panel.querySelector("[data-date-range=traffic-range]")?.addEventListener("range-change", (e) => {
      st.from = e.detail.from;
      st.to = e.detail.to;
      st.cursor = null;
      renderTraffic();
    });
    panel.querySelectorAll("[data-host-filter]").forEach((b) => {
      b.addEventListener("click", () => {
        st.hostFilter = st.hostFilter === b.dataset.hostFilter ? "" : b.dataset.hostFilter;
        st.cursor = null;
        renderTraffic();
      });
    });
    panel.querySelector("#clear-host")?.addEventListener("click", () => {
      st.hostFilter = "";
      st.cursor = null;
      renderTraffic();
    });
    panel.querySelector("#traffic-clear")?.addEventListener("click", () => {
      A.trafficState = null;
      renderTraffic();
    });
    panel.querySelector("#traffic-more")?.addEventListener("click", () => {
      st.cursor = body.next_cursor;
      renderTraffic();
    });
    panel.querySelectorAll("[data-traffic-idx]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-copy]")) return;
        const idx = Number(tr.dataset.trafficIdx);
        const t = items[idx];
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
