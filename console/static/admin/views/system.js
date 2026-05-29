(function (A) {
  const UI = A.UI;

  async function renderSystem() {
    const panel = A.el("panel-system");
    if (!panel) return;
    if (!A.isPlatform()) {
      panel.innerHTML =
        UI.pageHeader("System", "Platform operator tooling.", { icon: "system" }) +
        UI.emptyV2({ icon: "alert", title: "Operator only", body: "Requires PLATFORM_OPERATOR." });
      return;
    }

    let metrics = {};
    const sysRes = await A.api("/api/v1/admin/system");
    if (sysRes.ok) metrics = await sysRes.json();

    panel.innerHTML =
      UI.pageHeader("System", "High-impact platform actions. Each operation here affects every tenant — confirm twice before running.", { icon: "system" }) +
      `<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        ${UI.statTile({ icon: "system", label: "DB migration head", value: UI.escapeHtml(String(metrics.db?.head || "—")), sub: "Latest applied" })}
        ${UI.statTile({ icon: "operations", label: "Scheduler tick", value: metrics.scheduler?.tick_age_seconds != null ? `${metrics.scheduler.tick_age_seconds}s` : "—", sub: "Time since last tick" })}
        ${UI.statTile({ icon: "shield", label: "DB pool", value: `${metrics.db?.idle_connections ?? "—"} / ${metrics.db?.pool_size ?? "—"}`, sub: "Idle / total" })}
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">

        <section class="card card-pad">
          <header class="flex items-center gap-2 mb-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("refresh", "h-4 w-4")}</span>
            <h4 class="text-sm font-semibold text-ink">Reconcile fleet</h4>
          </header>
          <p class="text-xs text-mute mb-3">Walks every in-flight CVM and Security CVM, advancing stuck operations and (optionally) cleaning up orphans. Safe to run anytime.</p>
          <label class="flex items-center gap-2 text-xs text-mute mb-3 cursor-pointer">
            <input type="checkbox" class="accent-accent" data-rec-orphans checked>
            <span>Include orphans (delete provider-side state with no Console record)</span>
          </label>
          <button type="button" class="btn btn-primary w-full" id="run-reconcile">${UI.icon("refresh", "h-4 w-4")} Reconcile now</button>
        </section>

        <section class="card card-pad">
          <header class="flex items-center gap-2 mb-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-md bg-warn/10 text-warn">${UI.icon("key", "h-4 w-4")}</span>
            <h4 class="text-sm font-semibold text-ink">Rotate JWT signing keys</h4>
          </header>
          <p class="text-xs text-mute mb-3">Issues a new signing key and retires the previous one. Active sessions stay valid for the retire window. New tokens are signed with the new key.</p>
          <div class="space-y-2 mb-3">
            <div>
              <label class="field-label">New key ID</label>
              <input class="input input-sm font-mono" data-rot-kid placeholder="auto" autocomplete="off">
              <span class="field-hint">Leave blank to auto-generate.</span>
            </div>
            <div>
              <label class="field-label">Retire after (seconds)</label>
              <input class="input input-sm font-mono" data-rot-retire value="3600" type="number" min="0" max="86400">
            </div>
          </div>
          <button type="button" class="btn btn-primary w-full" id="run-rotate">${UI.icon("key", "h-4 w-4")} Rotate keys…</button>
        </section>

        <section class="card card-pad">
          <header class="flex items-center gap-2 mb-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-md bg-err/10 text-err">${UI.icon("alert", "h-4 w-4")}</span>
            <h4 class="text-sm font-semibold text-ink">Revoke sessions</h4>
          </header>
          <p class="text-xs text-mute mb-3">Invalidates outstanding sessions matching the filter. Users will need to sign in again. Provide at least one filter.</p>
          <div class="space-y-2 mb-3">
            <div>
              <label class="field-label">User ID</label>
              <input class="input input-sm font-mono" data-rev-user placeholder="(optional)" autocomplete="off">
            </div>
            <div>
              <label class="field-label">Entity ID</label>
              <input class="input input-sm font-mono" data-rev-entity placeholder="(optional)" autocomplete="off">
            </div>
            <div>
              <label class="field-label">Issued before</label>
              <input type="datetime-local" class="input input-sm font-mono" data-rev-before>
            </div>
          </div>
          <button type="button" class="btn btn-danger w-full" id="run-revoke">${UI.icon("x", "h-4 w-4")} Revoke matching…</button>
        </section>
      </div>

      <details class="mt-6">
        <summary class="flex items-center gap-1.5 text-2xs uppercase tracking-wider text-mute cursor-pointer hover:text-ink mb-3">
          ${UI.icon("chevron-right", "h-3 w-3 transition-transform group-open:rotate-90")} Diagnostics
        </summary>
        <div class="card card-pad">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h5 class="section-title mb-2">Top routes (last hour)</h5>
              ${routesTable(metrics.metrics?.requests_total_top || [])}
            </div>
            <div>
              <h5 class="section-title mb-2">Readiness</h5>
              ${readinessTable(metrics.readiness || {})}
            </div>
          </div>
        </div>
      </details>`;

    panel.querySelector("#run-reconcile")?.addEventListener("click", () => runReconcile(panel));
    panel.querySelector("#run-rotate")?.addEventListener("click", () => runRotate(panel));
    panel.querySelector("#run-revoke")?.addEventListener("click", () => runRevoke(panel));
  }

  function routesTable(rows) {
    if (!rows.length) return `<p class="text-xs text-mute italic">No data.</p>`;
    return `
      <div class="overflow-auto rounded-input border border-line max-h-64">
        <table class="data-table">
          <thead><tr><th>Route</th><th class="text-right">Count</th></tr></thead>
          <tbody>${rows.map((r) => `<tr><td class="font-mono text-2xs">${UI.escapeHtml(r.label)}</td><td class="text-right text-mute">${r.count}</td></tr>`).join("")}</tbody>
        </table>
      </div>`;
  }

  function readinessTable(readiness) {
    const entries = Object.entries(readiness || {});
    if (!entries.length) return `<p class="text-xs text-mute italic">No checks.</p>`;
    return `
      <ul class="divide-y divide-line/60 rounded-input border border-line">
        ${entries.map(([k, v]) => `
          <li class="flex items-center justify-between px-3 py-2 text-xs">
            <span class="text-ink">${UI.escapeHtml(k)}</span>
            <span class="${v === "ok" ? "text-ok" : "text-err"}">${UI.escapeHtml(String(v))}</span>
          </li>
        `).join("")}
      </ul>`;
  }

  async function runReconcile(panel) {
    const orphans = panel.querySelector("[data-rec-orphans]").checked;
    const ok = await UI.confirm({
      title: "Reconcile fleet",
      message: orphans
        ? "Advance in-flight operations and clean up orphan provider state. This may take a few minutes."
        : "Advance in-flight operations. Orphan cleanup skipped.",
      okLabel: "Reconcile",
    });
    if (!ok) return;
    const response = await A.api("/api/v1/admin/reconcile", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify({ include_orphans: orphans }),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return; }
    const body = await response.json();
    const counts = body.counts || body || {};
    const summary = `CVMs ${counts.cvms_advanced ?? 0} · Security CVMs ${counts.security_cvms_advanced ?? 0} · orphans ${counts.orphans_cleaned ?? 0}`;
    UI.toast("Reconciled — " + summary, "ok");
  }

  async function runRotate(panel) {
    const newKid = panel.querySelector("[data-rot-kid]").value.trim();
    const retireRaw = panel.querySelector("[data-rot-retire]").value.trim();
    const retireSeconds = retireRaw ? Number(retireRaw) : 3600;
    if (!Number.isInteger(retireSeconds) || retireSeconds < 0 || retireSeconds > 86400) {
      UI.toast("Retire window must be 0–86400 seconds", "err");
      return;
    }
    const ok = await UI.strongConfirm({
      title: "Rotate JWT signing keys",
      body: `New tokens will be signed with ${newKid || "an auto-generated key"}; old tokens stay valid for ${retireSeconds} more seconds. Type ROTATE to confirm.`,
      confirmWord: "ROTATE",
      primary: "Rotate keys",
      danger: false,
    });
    if (!ok) return;
    const body = { retire_old_after_seconds: retireSeconds };
    if (newKid) body.new_kid = newKid;
    const response = await A.api("/api/v1/admin/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify(body),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return; }
    const res = await response.json();
    UI.dialog({
      title: "Keys rotated",
      body: `
        <div class="space-y-2 text-sm">
          <div><span class="text-mute">Active key:</span> <span class="font-mono text-ok">${UI.escapeHtml(res.active_kid || "—")}</span></div>
          <div><span class="text-mute">Retiring:</span> <span class="font-mono text-warn">${UI.escapeHtml((res.retiring_kids || []).join(", ") || "—")}</span></div>
          <p class="text-xs text-mute mt-3">Old tokens will be honored until their retire window expires. New tokens are signed with the new key.</p>
        </div>`,
      primary: { label: "Done" },
    });
  }

  async function runRevoke(panel) {
    const user = panel.querySelector("[data-rev-user]").value.trim();
    const entity = panel.querySelector("[data-rev-entity]").value.trim();
    const before = panel.querySelector("[data-rev-before]").value.trim();
    if (!user && !entity && !before) {
      UI.toast("Provide at least one filter to avoid revoking all sessions", "err");
      return;
    }
    const fragments = [];
    if (user) fragments.push(`user_id=${user}`);
    if (entity) fragments.push(`entity_id=${entity}`);
    if (before) fragments.push(`issued_before=${new Date(before).toISOString()}`);
    const ok = await UI.strongConfirm({
      title: "Revoke matching sessions",
      body: `Sessions matching ${fragments.join(" ∩ ")} will be invalidated immediately. Users will need to sign in again. Type REVOKE to confirm.`,
      confirmWord: "REVOKE",
      primary: "Revoke sessions",
      danger: true,
    });
    if (!ok) return;
    const body = {};
    if (user) body.user_id = user;
    if (entity) body.entity_id = entity;
    if (before) body.issued_before = new Date(before).toISOString();
    const response = await A.api("/api/v1/admin/sessions/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify(body),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return; }
    const res = await response.json();
    UI.toast(`${res.revoked_jti_count ?? 0} sessions revoked`, "ok");
  }

  A.Views = A.Views || {};
  A.Views.renderSystem = renderSystem;
})(window.Admin);
