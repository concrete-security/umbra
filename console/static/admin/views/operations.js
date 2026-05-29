(function (A) {
  const UI = A.UI;

  let statusFilter = "all";
  let kindFilter = "all";
  let expanded = new Set();

  async function renderOperations() {
    const panel = A.el("panel-operations");
    if (!panel) return;
    if (!A.isPlatform()) {
      panel.innerHTML = UI.pageHeader("Operations", "Async platform operations.", { icon: "operations" }) +
        UI.emptyV2({ icon: "alert", title: "Operator only", body: "Requires PLATFORM_OPERATOR." });
      return;
    }
    const response = await A.api(A.adminQuery("operations", { limit: "100" }));
    const body = response.ok ? await response.json() : { items: [] };
    const items = body.items || [];

    const statusCounts = items.reduce((acc, o) => { acc[o.status] = (acc[o.status] || 0) + 1; return acc; }, { all: items.length });
    const kinds = Array.from(new Set(items.map((o) => o.kind))).sort();

    let filtered = items.slice();
    if (statusFilter !== "all") filtered = filtered.filter((o) => o.status === statusFilter);
    if (kindFilter !== "all") filtered = filtered.filter((o) => o.kind === kindFilter);

    const statusChips = [
      ["all", "All"],
      ["pending", "Pending"],
      ["running", "Running"],
      ["succeeded", "Succeeded"],
      ["failed", "Failed"],
    ].map(([id, label]) =>
      `<button type="button" class="filter-chip${statusFilter === id ? " active" : ""}" data-op-status="${id}">${UI.escapeHtml(label)} <span class="text-mute-soft">${statusCounts[id] || 0}</span></button>`
    ).join("");

    const kindSelect = `
      <select class="input input-sm w-44" data-op-kind>
        <option value="all">All kinds</option>
        ${kinds.map((k) => `<option value="${UI.escapeHtml(k)}" ${k === kindFilter ? "selected" : ""}>${UI.escapeHtml(k)}</option>`).join("")}
      </select>`;

    const cols = [
      { key: "updated_at", label: "Updated", render: (o) => `<span class="text-mute" title="${UI.escapeHtml(UI.fmtTsFull(o.updated_at))}">${UI.relTime(o.updated_at)}</span>` },
      { key: "kind", label: "Kind", render: (o) => `<span class="font-mono text-2xs text-ink">${UI.escapeHtml(o.kind)}</span>` },
      {
        key: "status",
        label: "Status",
        render: (o) => `${UI.badge(o.status)}${o.error?.code ? ` <span class="text-2xs text-err">${UI.escapeHtml(o.error.code)}</span>` : ""}`,
      },
      {
        key: "progress",
        label: "Progress",
        render: (o) => {
          if (!o.progress) return '<span class="text-mute">—</span>';
          const pct = o.progress.percent ?? 0;
          return `
            <div class="flex items-center gap-2">
              <span class="text-2xs text-mute">${UI.escapeHtml(o.progress.step || "—")}</span>
              <div class="w-16">${UI.bar(pct, 100, { tone: o.status === "failed" ? "err" : "accent" })}</div>
              <span class="text-2xs text-mute">${pct}%</span>
            </div>`;
        },
      },
      { key: "actor", label: "Actor", render: (o) => UI.escapeHtml(o.actor_email || "—") },
      { key: "target", label: "Target", render: (o) => o.target?.id ? UI.copyButton(o.target.id, o.target.id.slice(0, 12) + "…") : '<span class="text-mute">—</span>' },
    ];

    const table = filtered.length
      ? renderTable(cols, filtered)
      : UI.emptyV2({ icon: "operations", title: "No operations match", body: "Try a different filter." });

    panel.innerHTML =
      UI.pageHeader("Operations", "Asynchronous lifecycle work — every launch, update, decommission, and reconcile. Click a row to inspect its progress and result.", { icon: "operations" }) +
      `<div class="card card-pad mb-4">
        <div class="flex flex-wrap items-center gap-2.5">
          <div class="flex flex-wrap items-center gap-1.5">${statusChips}</div>
          ${kindSelect}
          <span class="flex-1"></span>
          <button type="button" class="btn btn-sm btn-ghost" id="ops-refresh">${UI.icon("refresh", "h-3.5 w-3.5")} Refresh</button>
        </div>
      </div>
      ${table}`;

    panel.querySelectorAll("[data-op-status]").forEach((btn) => {
      btn.addEventListener("click", () => { statusFilter = btn.dataset.opStatus; renderOperations(); });
    });
    panel.querySelector("[data-op-kind]")?.addEventListener("change", (e) => { kindFilter = e.target.value; renderOperations(); });
    panel.querySelector("#ops-refresh")?.addEventListener("click", () => renderOperations());
    panel.querySelectorAll("[data-op-id]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-copy]") || e.target.closest("button")) return;
        const id = tr.dataset.opId;
        if (expanded.has(id)) expanded.delete(id);
        else expanded.add(id);
        renderOperations();
      });
    });
    panel.querySelectorAll("[data-op-retry]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const id = btn.dataset.opRetry;
        const op = filtered.find((o) => o.id === id);
        if (op) await retryOp(op);
      });
    });
  }

  function renderTable(cols, rows) {
    const head =
      `<tr>${cols.map((c) => `<th>${UI.escapeHtml(c.label)}</th>`).join("")}<th></th></tr>`;
    const body = rows.map((o) => {
      const cells = cols.map((c) => `<td>${c.render(o) ?? "—"}</td>`).join("");
      const action = o.status === "failed"
        ? `<td class="text-right"><button type="button" class="btn btn-xs" data-op-retry="${UI.escapeHtml(o.id)}">${UI.icon("refresh", "h-3.5 w-3.5")} Retry</button></td>`
        : `<td class="text-right text-mute">${UI.icon(expanded.has(o.id) ? "chevron-down" : "chevron-right", "h-4 w-4")}</td>`;
      const detail = expanded.has(o.id) ? `<tr><td colspan="${cols.length + 1}" class="bg-bg/40 px-4 py-3"><pre class="font-mono text-2xs text-ink-dim overflow-auto max-h-64 whitespace-pre-wrap">${UI.escapeHtml(JSON.stringify({ id: o.id, result: o.result, error: o.error, created_at: o.created_at, expires_at: o.expires_at }, null, 2))}</pre></td></tr>` : "";
      return `<tr class="cursor-pointer" data-op-id="${UI.escapeHtml(o.id)}">${cells}${action}</tr>${detail}`;
    }).join("");
    return `<div class="overflow-auto rounded-card border border-line max-h-[640px]"><table class="data-table"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
  }

  async function retryOp(op) {
    UI.toast(`Retry for ${op.kind} not yet wired — re-issue the originating action`, "info");
  }

  A.Views = A.Views || {};
  A.Views.renderOperations = renderOperations;
})(window.Admin);
