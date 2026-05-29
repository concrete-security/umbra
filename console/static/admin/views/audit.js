(function (A) {
  const UI = A.UI;

  function ensureState() {
    A.auditState = A.auditState || {
      from: "",
      to: "",
      action: "",
      actor: "",
      targetType: "",
      cursor: null,
      pages: [],
    };
    return A.auditState;
  }

  function buildPath(st, limit = "60") {
    const params = { limit };
    if (st.action) params.action = st.action;
    if (st.actor) params.actor_id = st.actor;
    if (st.targetType) params.target_type = st.targetType;
    if (st.from) params.from = new Date(st.from).toISOString();
    if (st.to) params.to = new Date(st.to).toISOString();
    if (st.cursor) params.cursor = st.cursor;
    return A.isPlatform()
      ? A.adminQuery("audit/events", params)
      : "/api/v1/audit/events?" + new URLSearchParams(params).toString();
  }

  async function renderAudit() {
    const panel = A.el("panel-audit");
    if (!panel) return;
    if (!A.has(A.P.AUDIT)) {
      panel.innerHTML =
        UI.pageHeader("Audit log", "Every administrative action signed and chained.", { icon: "audit" }) +
        UI.emptyV2({ icon: "alert", title: "No permission", body: "Audit access requires AUDIT_VIEW." });
      return;
    }
    const st = ensureState();
    const res = await A.api(buildPath(st));
    const body = res.ok ? await res.json() : { items: [] };
    const items = body.items || [];

    const canExport = A.has(A.P.AUDIT_EXPORT);

    const cols = [
      { key: "timestamp", label: "Time", render: (a) => `<span class="text-mute" title="${UI.escapeHtml(UI.fmtTsFull(a.timestamp))}">${UI.relTime(a.timestamp)}</span>` },
      { key: "action", label: "Action", render: (a) => `<span class="font-mono text-2xs text-ink">${UI.escapeHtml(a.action || "—")}</span>` },
      { key: "actor", label: "Actor", render: (a) => UI.escapeHtml(a.actor_email || "system") },
      { key: "target", label: "Target", render: (a) => a.target_type ? `<span class="text-mute">${UI.escapeHtml(a.target_type)}</span> ${a.target_id ? `<span class="font-mono text-2xs ml-1">${UI.escapeHtml(String(a.target_id).slice(0, 12))}…</span>` : ""}` : '<span class="text-mute">—</span>' },
      { key: "description", label: "Detail", render: (a) => UI.escapeHtml(truncate(a.description || "", 80)) },
    ];

    const table = items.length
      ? UI.tableV2(cols, items, {
          onRowClick: true,
          rowAttr: (a) => `data-audit-idx="${items.indexOf(a)}"`,
          tall: true,
        })
      : UI.emptyV2({ icon: "audit", title: "No audit events match", body: "Adjust filters or widen the date range." });

    panel.innerHTML =
      UI.pageHeader("Audit log", "Every administrative action on this entity, signed and chained for tamper evidence. Click a row to inspect the before/after diff.", {
        icon: "audit",
        actions: canExport ? `<button type="button" class="btn" id="audit-export">${UI.icon("download", "h-4 w-4")} Export…</button>` : "",
      }) +
      `<div class="card card-pad mb-4 space-y-3">
        <div class="flex flex-wrap items-center gap-2.5">
          <label class="relative inline-flex items-center w-72">
            ${UI.icon("search", "h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute pointer-events-none")}
            <input type="search" class="input input-sm pl-8 w-full" data-search id="audit-action" placeholder="Filter by action (e.g. cvm.terminate)" value="${UI.escapeHtml(st.action)}">
          </label>
          <input type="search" class="input input-sm w-56" id="audit-actor" placeholder="Actor email" value="${UI.escapeHtml(st.actor)}">
          <select class="input input-sm w-44" id="audit-target-type">
            <option value="">All target types</option>
            <option value="cvm" ${st.targetType === "cvm" ? "selected" : ""}>CVM</option>
            <option value="security_cvm" ${st.targetType === "security_cvm" ? "selected" : ""}>Security CVM</option>
            <option value="user" ${st.targetType === "user" ? "selected" : ""}>User</option>
            <option value="profile" ${st.targetType === "profile" ? "selected" : ""}>Profile</option>
            <option value="entity" ${st.targetType === "entity" ? "selected" : ""}>Entity</option>
          </select>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          ${UI.dateRange({ id: "audit-range", from: st.from, to: st.to })}
          <button type="button" class="btn btn-ghost btn-xs" id="audit-clear">${UI.icon("x", "h-3.5 w-3.5")} Clear filters</button>
        </div>
      </div>
      ${table}
      ${body.next_cursor ? `
        <div class="mt-3 flex justify-center">
          <button type="button" class="btn btn-sm" id="audit-more">${UI.icon("chevron-down", "h-3.5 w-3.5")} Load more</button>
        </div>` : ""}`;

    bindHandlers(panel, items, body.next_cursor);
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function bindHandlers(panel, items, nextCursor) {
    const st = ensureState();
    let timer;
    panel.querySelector("#audit-action")?.addEventListener("input", (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => { st.action = e.target.value.trim(); st.cursor = null; renderAudit(); }, 300);
    });
    panel.querySelector("#audit-actor")?.addEventListener("input", (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => { st.actor = e.target.value.trim(); st.cursor = null; renderAudit(); }, 300);
    });
    panel.querySelector("#audit-target-type")?.addEventListener("change", (e) => {
      st.targetType = e.target.value;
      st.cursor = null;
      renderAudit();
    });
    panel.querySelector("[data-date-range=audit-range]")?.addEventListener("range-change", (e) => {
      st.from = e.detail.from;
      st.to = e.detail.to;
      st.cursor = null;
      renderAudit();
    });
    panel.querySelector("#audit-clear")?.addEventListener("click", () => {
      A.auditState = null;
      renderAudit();
    });
    panel.querySelector("#audit-more")?.addEventListener("click", () => {
      st.cursor = nextCursor;
      renderAudit();
    });
    panel.querySelector("#audit-export")?.addEventListener("click", () => openExportModal(st));
    panel.querySelectorAll("[data-audit-idx]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const idx = Number(tr.dataset.auditIdx);
        const ev = items[idx];
        if (ev) openDrilldown(ev);
      });
    });
  }

  function openDrilldown(ev) {
    UI.dialog({
      title: ev.action || "Audit event",
      subtitle: `By ${ev.actor_email || "system"} · ${UI.fmtTsFull(ev.timestamp)}`,
      size: "xl",
      primary: { label: "Close" },
      body: `
        <div class="space-y-4">
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-2xs">
            <div><div class="text-mute uppercase tracking-wider mb-0.5">Target</div><div class="text-ink font-mono">${UI.escapeHtml((ev.target_type || "—") + (ev.target_id ? " / " + String(ev.target_id).slice(0, 16) + "…" : ""))}</div></div>
            <div><div class="text-mute uppercase tracking-wider mb-0.5">Actor IP</div><div class="text-ink font-mono">${UI.escapeHtml(ev.ip_address || "—")}</div></div>
            <div><div class="text-mute uppercase tracking-wider mb-0.5">Request ID</div><div>${ev.request_id ? UI.copyButton(ev.request_id, ev.request_id.slice(0, 10) + "…") : "—"}</div></div>
            <div><div class="text-mute uppercase tracking-wider mb-0.5">Chain hash</div><div>${ev.row_hash ? UI.copyButton(ev.row_hash, ev.row_hash.slice(0, 10) + "…") : "—"}</div></div>
          </div>
          ${ev.description ? `<div class="card card-pad text-sm text-ink">${UI.escapeHtml(ev.description)}</div>` : ""}
          ${UI.diffView(ev.before, ev.after)}
          ${ev.target_type === "cvm" && ev.target_id ? `<button type="button" class="btn btn-sm" data-show-cvm="${UI.escapeHtml(ev.target_id)}">${UI.icon("cvm", "h-3.5 w-3.5")} Show in CVMs</button>` : ""}
        </div>`,
      onBind: (overlay) => {
        overlay.querySelector("[data-show-cvm]")?.addEventListener("click", (e) => {
          const id = e.currentTarget.dataset.showCvm;
          overlay.remove();
          A.Drawer.openCvm(id, "audit");
        });
      },
    });
  }

  function openExportModal(st) {
    UI.dialog({
      title: "Export audit log",
      subtitle: "Triggers a background export. When ready, a download link is returned.",
      wide: true,
      primary: { label: "Start export", run: doExport },
      body: `
        <div class="space-y-3">
          <div>
            <label class="field-label">Time range</label>
            ${UI.dateRange({ id: "audit-export-range", from: st.from, to: st.to })}
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label class="field-label">Action filter</label>
              <input class="input" data-ex-action value="${UI.escapeHtml(st.action || "")}" placeholder="e.g. cvm.terminate (optional)">
            </div>
            <div>
              <label class="field-label">Format</label>
              <select class="input" data-ex-format>
                <option value="ndjson">NDJSON (one event per line)</option>
                <option value="csv">CSV</option>
              </select>
            </div>
          </div>
          <p class="text-2xs text-mute">Exports respect your current scope. Use the date range to narrow large windows.</p>
          <div data-ex-msg class="text-sm"></div>
        </div>`,
    });
  }

  async function doExport(overlay) {
    const range = overlay.querySelector("[data-date-range=audit-export-range]");
    const from = range.querySelector("[data-dr-from]").value;
    const to = range.querySelector("[data-dr-to]").value;
    const action = overlay.querySelector("[data-ex-action]").value.trim();
    const format = overlay.querySelector("[data-ex-format]").value;
    const msg = overlay.querySelector("[data-ex-msg]");
    if (!from || !to) {
      msg.innerHTML = `<span class="text-err">Pick a from + to date range</span>`;
      return false;
    }
    const body = {
      format,
      from: new Date(from).toISOString(),
      to: new Date(to).toISOString(),
    };
    if (action) body.action = action;
    msg.innerHTML = `<span class="text-mute">Submitting export…</span>`;
    const r = await A.api("/api/v1/audit/export", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      msg.innerHTML = `<span class="text-err">${UI.escapeHtml(await A.parseError(r))}</span>`;
      return false;
    }
    const op = await r.json();
    msg.innerHTML = `<span class="text-mute">Export running — polling for completion…</span>`;
    try {
      const final = await A.Ops.poll(op.id);
      const token = final.result?.download_token || final.download_token;
      if (token) {
        msg.innerHTML = `
          <div class="rounded-input border border-ok/40 bg-ok/5 p-3 text-sm">
            <p class="text-ink mb-1">Export ready.</p>
            <a href="${A.apiBase()}/api/v1/audit/exports/${encodeURIComponent(token)}" class="btn btn-primary btn-sm" download>
              ${UI.icon("download", "h-3.5 w-3.5")} Download ${UI.escapeHtml(format.toUpperCase())}
            </a>
          </div>`;
      } else {
        msg.innerHTML = `<span class="text-warn">Export finished but no download token returned.</span>`;
      }
      return false; // keep modal open so user can grab link
    } catch (e) {
      msg.innerHTML = `<span class="text-err">${UI.escapeHtml(e.message || "Export failed")}</span>`;
      return false;
    }
  }

  A.Views = A.Views || {};
  A.Views.renderAudit = renderAudit;
})(window.Admin);
