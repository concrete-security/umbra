(function (A) {
  const UI = A.UI;

  async function renderOverview() {
    const panel = A.el("panel-overview");
    if (!panel) return;
    const globalPlatform = A.isPlatform() && A.ctx.viewEntityId === A.ctx.me.entity_id;
    if (globalPlatform) return renderPlatformOverview(panel);
    return renderEntityOverview(panel);
  }

  // -------- Entity Admin overview ----------------------------------------

  async function renderEntityOverview(panel) {
    const [cvms, summary, sc] = await Promise.all([
      A.fetchCvms(),
      A.isPlatform() ? A.fetchEntitySummary() : Promise.resolve(null),
      A.fetchSecurityCvm(),
    ]);

    const running = cvms.filter((c) => c.state === "running").length;
    const errored = cvms.filter((c) => c.state === "error" || c.state === "failed").length;
    const userCount = summary?.user_count ?? "—";
    const profileCount = summary?.profile_count ?? (A.ctx?.me?.profiles?.length ?? "—");
    const entityName = summary?.entity?.name || A.ctx.entityName || "Your entity";
    const canLaunch = A.canActOnCvms() && A.has(A.P.CVM_LAUNCH);

    const scStateTile = sc
      ? UI.statTile({
          icon: "shield",
          label: "Security CVM",
          value: UI.badge(sc.state, sc.state || "—"),
          sub: sc.state === "running" ? "Enforcing policy" : "Not enforcing — provision to start",
          tone: sc.state === "running" ? "ok" : "warn",
          href: "#security",
        })
      : UI.statTile({
          icon: "shield",
          label: "Security CVM",
          value: '<span class="text-warn">Not provisioned</span>',
          sub: "Egress is unavailable until you provision one",
          tone: "warn",
          href: "#security",
        });

    const recentTraffic = (A.pollSnapshot?.recentTraffic || (await A.fetchTrafficLogs({ limit: "10" }))).items || [];
    const auditRecent = await fetchRecentAudit();
    const pendingOps = pendingOpsList();

    panel.innerHTML = `
      <section class="relative overflow-hidden rounded-card border border-line bg-grad-hero p-6 mb-5">
        <div class="absolute inset-0 hero-grid opacity-20 pointer-events-none"></div>
        <div class="relative flex flex-wrap items-start justify-between gap-4">
          <div class="min-w-0">
            <div class="flex items-center gap-2 text-2xs uppercase tracking-[0.18em] text-mute mb-2">
              ${UI.icon("entity", "h-3.5 w-3.5 text-accent")} ${UI.escapeHtml(entityName)}
            </div>
            <h2 class="text-2xl font-semibold tracking-tight text-balance text-ink max-w-2xl">
              Your team's confidential AI sandboxes — <span class="text-accent">governed end-to-end</span>.
            </h2>
            <p class="mt-2 text-sm text-mute max-w-2xl">
              ${running} of ${cvms.length} CVM${cvms.length === 1 ? "" : "s"} running, routing through ${sc?.state === "running" ? "your Security CVM" : "no egress gateway"}.
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            ${canLaunch ? `<button type="button" class="btn btn-primary" id="ov-launch">${UI.icon("plus", "h-4 w-4")} Launch CVM</button>` : ""}
            <button type="button" class="btn btn-ghost" id="ov-cvms">${UI.icon("cvm", "h-4 w-4")} View all CVMs</button>
          </div>
        </div>
      </section>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        ${UI.statTile({ icon: "cvm", label: "Dev CVMs", value: `${running}/${cvms.length}`, sub: `${cvms.length - running} stopped · ${errored} error${errored === 1 ? "" : "s"}`, href: "#cvms" })}
        ${scStateTile}
        ${UI.statTile({ icon: "users", label: "Users", value: userCount, sub: "Active members on this entity", href: "#users" })}
        ${UI.statTile({ icon: "traffic", label: "Egress (last 5m)", value: recentTraffic.length, sub: `${countUniqueHosts(recentTraffic)} hosts contacted`, href: "#traffic" })}
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <section class="card md:col-span-2 overflow-hidden">
          <header class="px-4 py-3 border-b border-line flex items-center justify-between">
            <h3 class="text-sm font-semibold text-ink">Recent activity</h3>
            <span class="text-2xs text-mute">Audit + ops, last 24h</span>
          </header>
          <div class="max-h-[460px] overflow-auto">
            ${renderActivityFeed(auditRecent, pendingOps)}
          </div>
        </section>

        <section class="space-y-4">
          <div class="card card-pad">
            <h3 class="text-sm font-semibold text-ink mb-1">Operations in flight</h3>
            <p class="text-2xs text-mute mb-2">Currently running or pending on your CVMs.</p>
            ${pendingOps.length ? `
              <ul class="space-y-1.5">
                ${pendingOps.map((o) => `
                  <li class="flex items-center justify-between gap-2 text-xs">
                    <span class="flex items-center gap-2 min-w-0">
                      <span class="dot dot-warn dot-pulse"></span>
                      <span class="text-ink truncate">${UI.escapeHtml(o.kind)}</span>
                    </span>
                    <span class="text-2xs text-mute">${UI.escapeHtml(o.progress?.step || "—")}</span>
                  </li>
                `).join("")}
              </ul>
            ` : `<p class="text-xs text-mute italic">Nothing in flight.</p>`}
          </div>

          <div class="card card-pad">
            <h3 class="text-sm font-semibold text-ink mb-1">Quick actions</h3>
            <p class="text-2xs text-mute mb-3">Common admin tasks.</p>
            <div class="space-y-1.5">
              ${A.has(A.P.USER_MANAGE) ? `<button type="button" class="btn btn-sm w-full justify-start" data-action="invite">${UI.icon("plus", "h-3.5 w-3.5")} Invite user</button>` : ""}
              ${A.canManageProfiles() ? `<button type="button" class="btn btn-sm w-full justify-start" data-action="profile">${UI.icon("plus", "h-3.5 w-3.5")} Create profile</button>` : ""}
              ${canLaunch ? `<button type="button" class="btn btn-sm w-full justify-start" data-action="launch">${UI.icon("plus", "h-3.5 w-3.5")} Launch CVM</button>` : ""}
              ${A.has(A.P.AUDIT) ? `<button type="button" class="btn btn-sm w-full justify-start" data-action="audit">${UI.icon("audit", "h-3.5 w-3.5")} Review audit log</button>` : ""}
            </div>
          </div>
        </section>
      </div>`;

    panel.querySelector("#ov-launch")?.addEventListener("click", () => A.openLaunchModal());
    panel.querySelector("#ov-cvms")?.addEventListener("click", () => { location.hash = "cvms"; });
    panel.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const a = btn.dataset.action;
        if (a === "launch") A.openLaunchModal();
        else if (a === "invite") { location.hash = "users"; setTimeout(() => A.el("user-invite")?.click(), 100); }
        else if (a === "profile") { location.hash = "profiles"; setTimeout(() => A.el("profile-create")?.click(), 100); }
        else if (a === "audit") { location.hash = "audit"; }
      });
    });
  }

  // -------- Platform Operator overview -----------------------------------

  async function renderPlatformOverview(panel) {
    const [overviewRes, cvms] = await Promise.all([
      A.api("/api/v1/admin/overview"),
      A.fetchCvms(),
    ]);
    const overview = overviewRes.ok ? await overviewRes.json() : {};
    const c = overview.counts || {};
    const phala = overview.phala_cvms || [];
    const recentTraffic = (A.pollSnapshot?.recentTraffic || { items: [] }).items;
    const auditRecent = await fetchRecentAudit();
    const pendingOps = pendingOpsList();

    const errored = cvms.filter((c) => c.state === "error" || c.state === "failed").length;
    const tone = errored ? "warn" : "ok";

    panel.innerHTML = `
      <section class="relative overflow-hidden rounded-card border border-line bg-grad-hero p-6 mb-5">
        <div class="absolute inset-0 hero-grid opacity-20 pointer-events-none"></div>
        <div class="relative flex flex-wrap items-start justify-between gap-4">
          <div class="min-w-0">
            <div class="flex items-center gap-2 text-2xs uppercase tracking-[0.18em] text-mute mb-2">
              ${UI.icon("system", "h-3.5 w-3.5 text-accent")} Platform overview
            </div>
            <h2 class="text-2xl font-semibold tracking-tight text-balance text-ink max-w-2xl">
              ${c.dev_cvms_running ?? 0} CVMs running across ${c.entities ?? 0} entities,
              ${errored ? `<span class="text-err">${errored} in error</span>` : "<span class='text-ok'>all healthy</span>"}.
            </h2>
            <p class="mt-2 text-sm text-mute max-w-2xl">
              Fleet-wide observability for every tenant on this Concrete deployment.
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <button type="button" class="btn btn-ghost" id="ov-platform">${UI.icon("entity", "h-4 w-4")} Entities</button>
            <button type="button" class="btn btn-ghost" id="ov-system">${UI.icon("system", "h-4 w-4")} System</button>
          </div>
        </div>
      </section>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        ${UI.statTile({ icon: "entity", label: "Entities", value: c.entities ?? "—", sub: "Tenants on this deployment", href: "#entities" })}
        ${UI.statTile({ icon: "cvm", label: "Dev CVMs", value: `${c.dev_cvms_running ?? 0}/${c.dev_cvms ?? 0}`, sub: `${errored} in error`, tone, href: "#cvms" })}
        ${UI.statTile({ icon: "shield", label: "Security CVMs", value: `${c.security_cvms_running ?? 0}/${c.security_cvms ?? 0}`, sub: "running / provisioned" })}
        ${UI.statTile({ icon: "operations", label: "Active ops", value: c.active_operations ?? 0, sub: "Pending + running", href: "#operations" })}
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
        ${UI.statTile({ icon: "traffic", label: "Traffic (5m)", value: c.traffic_events_5m ?? 0, sub: "Egress events in the last 5 minutes" })}
        ${UI.statTile({ icon: "audit", label: "Audit (5m)", value: c.audit_events_5m ?? 0, sub: "Administrative actions in the last 5 minutes" })}
        ${UI.statTile({ icon: "system", label: "Phala CVMs", value: phala.length, sub: phala.length ? `${phala.filter((p) => (p.status || "").toLowerCase().includes("running")).length} running` : "no provider CVMs" })}
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <section class="card md:col-span-2 overflow-hidden">
          <header class="px-4 py-3 border-b border-line flex items-center justify-between">
            <h3 class="text-sm font-semibold text-ink">Cross-tenant activity</h3>
            <span class="text-2xs text-mute">Audit + ops, last 24h</span>
          </header>
          <div class="max-h-[460px] overflow-auto">
            ${renderActivityFeed(auditRecent, pendingOps)}
          </div>
        </section>

        <section class="space-y-4">
          <div class="card card-pad">
            <h3 class="text-sm font-semibold text-ink mb-1">Readiness</h3>
            <p class="text-2xs text-mute mb-2">Subsystem health.</p>
            ${renderReadinessList(overview.readiness)}
          </div>
          <div class="card card-pad">
            <h3 class="text-sm font-semibold text-ink mb-1">Operator actions</h3>
            <p class="text-2xs text-mute mb-3">Run from the System tab.</p>
            <div class="space-y-1.5">
              <button type="button" class="btn btn-sm w-full justify-start" data-action="system">${UI.icon("refresh", "h-3.5 w-3.5")} Reconcile fleet</button>
              <button type="button" class="btn btn-sm w-full justify-start" data-action="system">${UI.icon("key", "h-3.5 w-3.5")} Rotate JWT keys</button>
              <button type="button" class="btn btn-sm w-full justify-start" data-action="system">${UI.icon("alert", "h-3.5 w-3.5")} Revoke sessions</button>
            </div>
          </div>
        </section>
      </div>`;

    panel.querySelector("#ov-platform")?.addEventListener("click", () => { location.hash = "entities"; });
    panel.querySelector("#ov-system")?.addEventListener("click", () => { location.hash = "system"; });
    panel.querySelectorAll("[data-action='system']").forEach((b) => b.addEventListener("click", () => { location.hash = "system"; }));
  }

  // -------- Helpers ------------------------------------------------------

  function pendingOpsList() {
    const all = (A.Ops?.load && A.Ops.load()) || [];
    return all.filter((o) => o.status !== "succeeded" && o.status !== "failed" && o.status !== "cancelled").slice(0, 5);
  }

  function countUniqueHosts(items) {
    const s = new Set();
    (items || []).forEach((t) => { if (t.destination_host) s.add(t.destination_host); });
    return s.size;
  }

  async function fetchRecentAudit() {
    if (!A.has(A.P.AUDIT)) return [];
    const params = new URLSearchParams({ limit: "12" });
    const path = A.isPlatform()
      ? A.adminQuery("audit/events", Object.fromEntries(params))
      : "/api/v1/audit/events?" + params.toString();
    const res = await A.api(path);
    if (!res.ok) return [];
    return (await res.json()).items || [];
  }

  function renderReadinessList(readiness) {
    const entries = Object.entries(readiness || {});
    if (!entries.length) return `<p class="text-xs text-mute italic">No data.</p>`;
    return `
      <ul class="space-y-1.5">
        ${entries.map(([k, v]) => `
          <li class="flex items-center justify-between text-xs">
            <span class="text-mute">${UI.escapeHtml(k)}</span>
            <span class="${v === "ok" ? "text-ok" : "text-err"} font-medium">${UI.escapeHtml(String(v))}</span>
          </li>
        `).join("")}
      </ul>`;
  }

  function renderActivityFeed(audit, ops) {
    const items = [];
    (audit || []).forEach((ev) => items.push({
      type: "audit",
      time: ev.timestamp,
      title: ev.action,
      sub: `${ev.actor_email || "system"}${ev.target?.id ? " · " + String(ev.target.id).slice(0, 10) + "…" : ""}`,
      icon: "audit",
      tone: "info",
      ref: ev,
    }));
    (ops || []).forEach((o) => items.push({
      type: "op",
      time: o.updated_at,
      title: o.kind,
      sub: o.progress?.step || o.status,
      icon: "operations",
      tone: o.status === "failed" ? "err" : "warn",
      ref: o,
    }));
    items.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
    if (!items.length) {
      return `<div class="p-6 text-center text-xs text-mute italic">No recent activity.</div>`;
    }
    return `
      <ul class="divide-y divide-line/60">
        ${items.slice(0, 20).map((it) => {
          const toneCls = it.tone === "err" ? "bg-err/10 text-err" : it.tone === "warn" ? "bg-warn/10 text-warn" : "bg-accent/10 text-accent";
          return `
            <li class="px-4 py-2.5 hover:bg-elev/40 transition-colors">
              <div class="flex items-start gap-3">
                <span class="flex h-7 w-7 items-center justify-center rounded-md ${toneCls} shrink-0">${UI.icon(it.icon, "h-3.5 w-3.5")}</span>
                <div class="min-w-0 flex-1">
                  <div class="flex items-center justify-between gap-2">
                    <span class="text-sm text-ink truncate">${UI.escapeHtml(it.title || "—")}</span>
                    <span class="text-2xs text-mute shrink-0">${UI.relTime(it.time)}</span>
                  </div>
                  <div class="text-2xs text-mute truncate">${UI.escapeHtml(it.sub || "")}</div>
                </div>
              </div>
            </li>`;
        }).join("")}
      </ul>`;
  }

  A.Views = A.Views || {};
  A.Views.renderOverview = renderOverview;
})(window.Admin);
