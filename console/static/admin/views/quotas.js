(function (A) {
  const UI = A.UI;

  function path(scope, scopeId, resource) {
    return scope === "entity"
      ? `/api/v1/entities/${scopeId}/quotas${resource ? "/" + resource : ""}`
      : `/api/v1/users/${scopeId}/quotas${resource ? "/" + resource : ""}`;
  }

  async function fetchQuotas(scope, scopeId) {
    const res = await A.api(path(scope, scopeId));
    if (!res.ok) throw new Error(await A.parseError(res));
    const body = await res.json();
    return body.quotas || [];
  }

  function renderList(quotas, scope, scopeId) {
    if (!quotas.length) {
      return `<p class="text-xs text-mute italic">No custom quotas. Every resource is using its default.</p>`;
    }
    return `
      <ul class="divide-y divide-line/60">
        ${quotas.map((q) => `
          <li class="flex items-center justify-between py-3" data-quota-row="${UI.escapeHtml(q.resource)}">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-sm text-ink font-mono">${UI.escapeHtml(q.resource)}</span>
                ${q.set_by ? `<span class="chip">custom</span>` : `<span class="chip">default</span>`}
              </div>
              <div class="mt-1 text-2xs text-mute flex flex-wrap items-center gap-2">
                <span><span class="text-ink font-medium">${q.limit_value ?? "∞"}</span> limit</span>
                <span>·</span>
                <span>used <span class="text-ink">${q.used ?? 0}</span></span>
                ${typeof q.limit_value === "number" && q.limit_value > 0 && typeof q.used === "number" ? `<span class="ml-2 w-24">${UI.bar(q.used, q.limit_value, { tone: q.used >= q.limit_value ? "err" : q.used > q.limit_value * 0.8 ? "warn" : "accent" })}</span>` : ""}
                ${q.set_by ? `<span class="ml-2">set by ${UI.escapeHtml(q.set_by)} ${UI.relTime(q.set_at)}</span>` : ""}
              </div>
            </div>
            ${A.has(A.P.QUOTA_MANAGE) ? `
              <div class="flex items-center gap-1">
                <button type="button" class="btn btn-ghost btn-xs" data-edit-q="${UI.escapeHtml(q.resource)}" data-current="${q.limit_value ?? ""}">${UI.icon("refresh", "h-3.5 w-3.5")} Edit</button>
                ${q.set_by ? `<button type="button" class="btn btn-ghost btn-xs btn-danger" data-clear-q="${UI.escapeHtml(q.resource)}" aria-label="Clear quota">${UI.icon("x", "h-3.5 w-3.5")}</button>` : ""}
              </div>` : ""}
          </li>
        `).join("")}
      </ul>`;
  }

  function bind(root, scope, scopeId, onChange) {
    root.querySelectorAll("[data-edit-q]").forEach((btn) => {
      btn.addEventListener("click", () => openEdit(btn.dataset.editQ, btn.dataset.current, scope, scopeId, onChange));
    });
    root.querySelectorAll("[data-clear-q]").forEach((btn) => {
      btn.addEventListener("click", () => clearQuota(btn.dataset.clearQ, scope, scopeId, onChange));
    });
  }

  function openEdit(resource, current, scope, scopeId, onChange) {
    UI.dialog({
      title: `Edit quota — ${resource}`,
      subtitle: "Set the maximum limit for this resource. Enforced server-side.",
      primary: {
        label: "Save quota",
        async run(overlay) {
          const raw = overlay.querySelector("[data-q-input]").value.trim();
          if (raw === "") { UI.toast("Enter a non-negative integer", "err"); return false; }
          const v = Number(raw);
          if (!Number.isInteger(v) || v < 0) { UI.toast("Limit must be a non-negative integer", "err"); return false; }
          const r = await A.api(path(scope, scopeId, resource), {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ limit_value: v }),
          });
          if (!r.ok) { UI.toast(await A.parseError(r), "err"); return false; }
          UI.toast("Quota updated", "ok");
          onChange && onChange();
        },
      },
      body: `
        <label class="field-label">Limit</label>
        <input class="input font-mono" data-q-input value="${UI.escapeHtml(current || "")}" type="number" min="0" step="1" inputmode="numeric">
        <p class="field-hint">Resource: <span class="font-mono text-ink">${UI.escapeHtml(resource)}</span></p>`,
      onBind: (overlay) => overlay.querySelector("[data-q-input]").focus(),
    });
  }

  async function clearQuota(resource, scope, scopeId, onChange) {
    const ok = await UI.confirm({
      title: `Clear quota — ${resource}`,
      message: "Removes the custom limit. The resource will inherit its default.",
      okLabel: "Clear",
      danger: true,
    });
    if (!ok) return;
    const r = await A.api(path(scope, scopeId, resource), { method: "DELETE" });
    if (r.ok || r.status === 204) {
      UI.toast("Quota cleared", "ok");
      onChange && onChange();
    } else UI.toast(await A.parseError(r), "err");
  }

  A.QuotasView = { renderList, bind, fetchQuotas, openEdit, clearQuota };
})(window.Admin);
