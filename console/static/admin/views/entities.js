(function (A) {
  const UI = A.UI;

  let entitySearch = "";
  let selectedEntityId = null;
  let entityTab = "summary";

  async function renderEntities() {
    const panel = A.el("panel-entities");
    if (!panel) return;
    if (!A.isPlatform()) {
      panel.innerHTML = UI.pageHeader("Entities", "Cross-tenant inventory.", { icon: "entity" }) +
        UI.emptyV2({ icon: "alert", title: "Operator only", body: "Entity inventory requires PLATFORM_OPERATOR." });
      return;
    }

    const res = await A.api("/api/v1/entities?limit=200");
    if (!res.ok) {
      panel.innerHTML =
        UI.pageHeader("Entities", "Cross-tenant inventory.", { icon: "entity" }) +
        UI.emptyV2({ icon: "alert", title: "Failed to load entities", body: await A.parseError(res) });
      return;
    }
    const items = (await res.json()).items || [];

    let filtered = items.slice();
    if (entitySearch) {
      const q = entitySearch.toLowerCase();
      filtered = filtered.filter((e) =>
        (e.name || "").toLowerCase().includes(q) ||
        (e.domain || "").toLowerCase().includes(q) ||
        (e.id || "").toLowerCase().includes(q)
      );
    }

    const cols = [
      {
        key: "name",
        label: "Entity",
        render: (e) => `
          <div class="flex items-center gap-2 min-w-0">
            <span class="flex h-7 w-7 items-center justify-center rounded-md bg-accent/10 text-accent shrink-0">${UI.icon("entity", "h-3.5 w-3.5")}</span>
            <div class="min-w-0">
              <div class="text-sm font-medium text-ink truncate">${UI.escapeHtml(e.name)}</div>
              <div class="text-2xs text-mute truncate">${UI.escapeHtml(e.domain || "—")}</div>
            </div>
          </div>`,
      },
      { key: "users", label: "Users", render: (e) => UI.escapeHtml(String(e.user_count ?? "—")) },
      { key: "cvms", label: "CVMs", render: (e) => UI.escapeHtml(String(e.cvm_count ?? "—")) },
      { key: "profiles", label: "Profiles", render: (e) => UI.escapeHtml(String(e.profile_count ?? "—")) },
      { key: "id", label: "ID", render: (e) => UI.copyButton(e.id, e.id.slice(0, 12) + "…") },
    ];

    const table = filtered.length
      ? UI.tableV2(cols, filtered, {
          onRowClick: true,
          rowAttr: (e) => `data-entity-id="${UI.escapeHtml(e.id)}"`,
          rowAction: () => `<span class="text-mute">${UI.icon("chevron-right", "h-4 w-4")}</span>`,
        })
      : UI.emptyV2({ icon: "entity", title: "No entities match", body: "Try a different search." });

    panel.innerHTML =
      UI.pageHeader("Entities", "Every tenant on this Umbra deployment. Open an entity to view stats, manage quotas, audit activity, and see its Security CVM.", {
        icon: "entity",
        actions: `<button type="button" class="btn btn-primary" id="entity-create">${UI.icon("plus", "h-4 w-4")} Create entity</button>`,
      }) +
      `<div class="card card-pad mb-4">
        <label class="relative inline-flex items-center w-full max-w-md">
          ${UI.icon("search", "h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute pointer-events-none")}
          <input type="search" class="input input-sm pl-8 w-full" data-search id="entities-search" placeholder="Search by name, domain, or ID…" value="${UI.escapeHtml(entitySearch)}">
        </label>
      </div>
      ${table}`;

    let st;
    panel.querySelector("#entities-search")?.addEventListener("input", (e) => {
      entitySearch = e.target.value;
      clearTimeout(st);
      st = setTimeout(renderEntities, 250);
    });
    panel.querySelector("#entity-create")?.addEventListener("click", openCreate);
    panel.querySelectorAll("[data-entity-id]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-copy]")) return;
        const id = tr.dataset.entityId;
        openEntityDrawer(id);
      });
    });
  }

  function openCreate() {
    UI.dialog({
      title: "Create entity",
      subtitle: "A new tenant on this Umbra deployment. The domain controls which users can join via SSO.",
      primary: { label: "Create entity", run: doCreate },
      body: `
        <div class="space-y-3">
          <div>
            <label class="field-label">Name <span class="text-err">*</span></label>
            <input id="ec-name" class="input" placeholder="Acme Engineering" autocomplete="off">
          </div>
          <div>
            <label class="field-label">Domain <span class="text-err">*</span></label>
            <input id="ec-domain" class="input" placeholder="example.com" autocomplete="off">
            <span class="field-hint">Users with email at this domain can be invited.</span>
          </div>
        </div>`,
      onBind: (o) => o.querySelector("#ec-name").focus(),
    });
  }

  async function doCreate(overlay) {
    const name = overlay.querySelector("#ec-name").value.trim();
    const domain = overlay.querySelector("#ec-domain").value.trim();
    if (!name || !domain) { UI.toast("Name and domain are required", "err"); return false; }
    const r = await A.api("/api/v1/entities", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify({ name, domain }),
    });
    if (!r.ok) { UI.toast(await A.parseError(r), "err"); return false; }
    UI.toast("Entity created", "ok");
    renderEntities();
  }

  async function openEntityDrawer(entityId) {
    selectedEntityId = entityId;
    entityTab = "summary";
    const drawer = A.el("entity-drawer");
    drawer.classList.remove("hidden");
    drawer.setAttribute("aria-hidden", "false");
    A.el("entity-drawer-title").innerHTML = `
      <h2 class="text-base font-semibold text-ink flex items-center gap-2">
        ${UI.icon("entity", "h-5 w-5 text-accent")}
        <span data-entity-name>Entity</span>
      </h2>
      <div class="mt-0.5 text-2xs font-mono text-mute" data-entity-id-text>${UI.escapeHtml(entityId)}</div>`;
    await renderDrawer();
  }

  async function renderDrawer() {
    const body = A.el("entity-drawer-body");
    body.innerHTML = `<div class="text-sm text-mute">Loading…</div>`;

    const sumRes = await A.api("/api/v1/admin/entities/" + selectedEntityId + "/summary");
    const summary = sumRes.ok ? await sumRes.json() : null;
    if (!summary) {
      body.innerHTML = UI.emptyV2({ icon: "alert", title: "Failed to load entity" });
      return;
    }
    const ent = summary.entity || {};
    const titleName = A.el("entity-drawer-title").querySelector("[data-entity-name]");
    if (titleName) titleName.textContent = ent.name || "Entity";

    const tabs = [
      { id: "summary", label: "Summary", icon: "overview" },
      { id: "quotas", label: "Quotas", icon: "system" },
      { id: "security", label: "Security CVM", icon: "shield" },
      { id: "audit", label: "Audit", icon: "audit" },
    ];
    const tabBar = tabs.map((t) =>
      `<button type="button" class="filter-chip${entityTab === t.id ? " active" : ""}" data-ent-tab="${t.id}">${UI.icon(t.icon, "h-3.5 w-3.5")} ${UI.escapeHtml(t.label)}</button>`
    ).join("");

    let tabBody;
    if (entityTab === "summary") tabBody = renderSummaryTab(summary);
    else if (entityTab === "quotas") tabBody = await renderQuotasTab();
    else if (entityTab === "security") tabBody = renderSecurityTab(summary);
    else if (entityTab === "audit") tabBody = await renderAuditTab();

    body.innerHTML = `
      <div class="flex flex-wrap items-center gap-1.5 mb-4">${tabBar}</div>
      <div>${tabBody}</div>`;

    body.querySelectorAll("[data-ent-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        entityTab = btn.dataset.entTab;
        renderDrawer();
      });
    });
    if (entityTab === "quotas") A.QuotasView.bind(body, "entity", selectedEntityId, () => renderDrawer());
  }

  function renderSummaryTab(summary) {
    const ent = summary.entity || {};
    return `
      <div class="grid grid-cols-2 gap-3 mb-4">
        ${UI.statTile({ icon: "users", label: "Users", value: ent.user_count ?? "—" })}
        ${UI.statTile({ icon: "cvm", label: "Dev CVMs", value: `${ent.dev_cvms_running ?? 0} / ${ent.cvm_count ?? 0}`, sub: "running / total" })}
        ${UI.statTile({ icon: "profile", label: "Profiles", value: ent.profile_count ?? "—" })}
        ${UI.statTile({ icon: "shield", label: "Security CVM", value: summary.security_cvm ? UI.badge(summary.security_cvm.state) : '<span class="text-mute">—</span>' })}
      </div>
      <section class="card card-pad text-sm">
        <h4 class="text-sm font-semibold text-ink mb-2">Entity details</h4>
        <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-2xs">
          <div><dt class="text-mute">Name</dt><dd class="text-ink">${UI.escapeHtml(ent.name || "—")}</dd></div>
          <div><dt class="text-mute">Domain</dt><dd class="font-mono text-ink">${UI.escapeHtml(ent.domain || "—")}</dd></div>
          <div><dt class="text-mute">ID</dt><dd>${UI.copyButton(ent.id || "")}</dd></div>
          <div><dt class="text-mute">Created</dt><dd class="text-ink">${UI.escapeHtml(UI.fmtTsFull(ent.created_at))}</dd></div>
        </dl>
      </section>`;
  }

  async function renderQuotasTab() {
    let quotas = [];
    try {
      quotas = await A.QuotasView.fetchQuotas("entity", selectedEntityId);
    } catch (e) {
      return `<p class="text-sm text-err">${UI.escapeHtml(e.message)}</p>`;
    }
    return `
      <section class="card card-pad">
        <header class="mb-3">
          <h4 class="text-sm font-semibold text-ink">Resource quotas</h4>
          <p class="text-xs text-mute">Limits enforced on this entity. Custom limits override the platform defaults.</p>
        </header>
        ${A.QuotasView.renderList(quotas, "entity", selectedEntityId)}
      </section>`;
  }

  function renderSecurityTab(summary) {
    const sc = summary.security_cvm;
    if (!sc) return UI.emptyV2({ icon: "shield", title: "No Security CVM provisioned", body: "Egress is unavailable until one is launched in this entity." });
    return `
      <section class="card card-pad">
        <header class="flex items-center gap-2 mb-3">
          <span class="flex h-7 w-7 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("shield", "h-4 w-4")}</span>
          <div>
            <div class="flex items-center gap-2"><span class="text-sm font-semibold text-ink">Security CVM</span> ${UI.badge(sc.state)}</div>
            ${sc.fqdn ? `<div class="text-2xs font-mono text-mute">${UI.escapeHtml(sc.fqdn)}</div>` : ""}
          </div>
        </header>
        <p class="text-xs text-mute">Switch to this entity from the top bar to manage its Security CVM directly.</p>
      </section>`;
  }

  async function renderAuditTab() {
    const params = new URLSearchParams({ entity_id: selectedEntityId, limit: "20" });
    const res = await A.api("/api/v1/admin/audit/events?" + params.toString());
    if (!res.ok) return `<p class="text-sm text-err">${UI.escapeHtml(await A.parseError(res))}</p>`;
    const items = (await res.json()).items || [];
    if (!items.length) return `<p class="text-xs text-mute italic">No audit events for this entity.</p>`;
    return `
      <section class="card card-pad">
        <h4 class="text-sm font-semibold text-ink mb-2">Recent audit events</h4>
        <ul class="divide-y divide-line/60">
          ${items.map((ev) => `
            <li class="py-2 text-xs">
              <div class="flex items-center justify-between gap-2">
                <span class="text-ink font-mono truncate">${UI.escapeHtml(ev.action || "—")}</span>
                <span class="text-mute">${UI.relTime(ev.timestamp)}</span>
              </div>
              <div class="text-2xs text-mute">${UI.escapeHtml(ev.actor_email || "—")}${ev.target?.id ? " · " + UI.escapeHtml(String(ev.target.id).slice(0, 12)) + "…" : ""}</div>
            </li>
          `).join("")}
        </ul>
      </section>`;
  }

  A.Views = A.Views || {};
  A.Views.renderEntities = renderEntities;
})(window.Admin);
