(function (A) {
  const UI = A.UI;

  let selectedUserId = null;
  let selectedUserEtag = "";
  let userFilter = "all";
  let userSearch = "";
  let userTab = "permissions";

  async function renderUsers() {
    const panel = A.el("panel-users");
    if (!A.has(A.P.USER_MANAGE) && !A.has(A.P.PERM_MANAGE)) {
      panel.innerHTML =
        UI.pageHeader("Users", "Manage the people who can use this entity.", { icon: "users" }) +
        UI.emptyV2({ icon: "users", title: "No permission", body: "Ask an entity admin for USER_MANAGE or PERMISSION_MANAGE access." });
      return;
    }

    const canManage = A.has(A.P.USER_MANAGE) && A.isHomeEntity();

    const res = await A.api("/api/v1/entities/" + A.viewEntityId() + "/users");
    const users = res.ok ? (await res.json()).items || [] : [];

    let filtered = users.slice();
    if (userFilter !== "all") filtered = filtered.filter((u) => u.state === userFilter);
    if (userSearch) {
      const q = userSearch.toLowerCase();
      filtered = filtered.filter((u) => (u.email || "").toLowerCase().includes(q) || (u.name || "").toLowerCase().includes(q));
    }

    if (!selectedUserId && filtered.length) selectedUserId = filtered[0].id;

    const counts = users.reduce((acc, u) => { acc[u.state || "active"] = (acc[u.state || "active"] || 0) + 1; return acc; }, {});
    counts.all = users.length;
    const filterChips = [
      ["all", "All"],
      ["active", "Active"],
      ["deactivated", "Deactivated"],
      ["invited", "Invited"],
    ].map(([id, label]) =>
      `<button type="button" class="filter-chip${userFilter === id ? " active" : ""}" data-user-filter="${id}">${UI.escapeHtml(label)} <span class="text-mute-soft">${counts[id] || 0}</span></button>`
    ).join("");

    const listHtml = filtered.map((u) => `
      <button type="button" class="block w-full text-left px-3 py-2.5 border-b border-line/60 transition-colors ${u.id === selectedUserId ? "bg-elev text-ink" : "hover:bg-elev text-ink"}" data-uid="${UI.escapeHtml(u.id)}">
        <div class="flex items-center justify-between gap-2">
          <span class="text-sm font-medium truncate">${UI.escapeHtml(u.email)}</span>
          ${UI.badge(u.state)}
        </div>
        ${u.name ? `<div class="mt-0.5 text-xs text-mute truncate">${UI.escapeHtml(u.name)}</div>` : ""}
      </button>`).join("");

    let detail = UI.emptyV2({ icon: "user", title: "Select a user", body: filtered.length ? "Pick a user from the list to view permissions, profiles, and quotas." : "No users match these filters." });
    if (selectedUserId) detail = await renderDetail(canManage);

    const inviteBtn = canManage
      ? `<button type="button" class="btn btn-primary" id="user-invite">${UI.icon("plus", "h-4 w-4")} Invite user</button>`
      : "";

    panel.innerHTML =
      UI.pageHeader("Users", "Invite teammates, control what they can do, assign profiles, and set per-user resource limits.", {
        icon: "users",
        actions: inviteBtn,
      }) +
      `<div class="card card-pad mb-4">
        <div class="flex flex-wrap items-center gap-2.5">
          <label class="relative inline-flex items-center w-72">
            ${UI.icon("search", "h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute pointer-events-none")}
            <input type="search" class="input input-sm pl-8 w-full" data-search id="users-search" placeholder="Search by email or name…" value="${UI.escapeHtml(userSearch)}">
          </label>
          <div class="flex flex-wrap items-center gap-1.5">${filterChips}</div>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-4">
        <div class="card overflow-hidden">
          <header class="px-3 py-2 border-b border-line bg-elev/40">
            <h3 class="section-title">${filtered.length} user${filtered.length === 1 ? "" : "s"}</h3>
          </header>
          <div class="max-h-[640px] overflow-auto">
            ${listHtml || UI.emptyV2({ icon: "users", title: "No users", body: "Invite the first one." })}
          </div>
        </div>
        <div>${detail}</div>
      </div>`;

    bindHandlers(panel);
  }

  async function renderDetail(canManage) {
    const uRes = await A.api("/api/v1/entities/" + A.viewEntityId() + "/users/" + selectedUserId);
    if (!uRes.ok) return UI.emptyV2({ icon: "alert", title: "Failed to load user" });
    selectedUserEtag = uRes.headers.get("ETag") || "";
    const u = await uRes.json();

    const tabs = [
      { id: "permissions", label: "Permissions", icon: "shield" },
      { id: "profiles", label: "Profiles", icon: "profile" },
    ];
    if (A.has(A.P.QUOTA_MANAGE)) tabs.push({ id: "quotas", label: "Quotas", icon: "system" });

    const tabBar = tabs.map((t) =>
      `<button type="button" class="filter-chip${userTab === t.id ? " active" : ""}" data-user-tab="${t.id}">${UI.icon(t.icon, "h-3.5 w-3.5")} ${UI.escapeHtml(t.label)}</button>`
    ).join("");

    let tabBody = "";
    if (userTab === "permissions") tabBody = renderPermissionsTab(u, canManage);
    else if (userTab === "profiles") tabBody = await renderProfilesTab(u, canManage);
    else if (userTab === "quotas") tabBody = await renderQuotasTab(u);

    const actions = canManage ? `
      <div class="flex flex-wrap items-center gap-2 mt-3">
        ${u.state === "active" ? `<button type="button" class="btn btn-sm" id="user-deactivate">${UI.icon("x", "h-3.5 w-3.5")} Deactivate</button>` : ""}
        ${u.state === "deactivated" ? `<button type="button" class="btn btn-sm" id="user-reactivate">${UI.icon("refresh", "h-3.5 w-3.5")} Reactivate</button>` : ""}
        ${u.state !== "active" ? `<button type="button" class="btn btn-sm btn-danger" id="user-erase">${UI.icon("x", "h-3.5 w-3.5")} Erase…</button>` : ""}
      </div>` : "";

    return `
      <section class="card card-pad mb-3">
        <header class="flex items-start justify-between gap-3 mb-2">
          <div class="flex items-start gap-3 min-w-0">
            <span class="flex h-10 w-10 items-center justify-center rounded-full bg-accent/10 text-accent shrink-0">${UI.icon("user", "h-5 w-5")}</span>
            <div class="min-w-0">
              <div class="flex items-center gap-2 flex-wrap">
                <h4 class="text-base font-semibold text-ink truncate">${UI.escapeHtml(u.email)}</h4>
                ${UI.badge(u.state)}
              </div>
              <div class="mt-0.5 text-xs text-mute">${UI.escapeHtml(u.name || "—")}</div>
              <div class="mt-2 flex items-center gap-3 text-2xs text-mute">
                <span title="Created">${UI.icon("clock", "h-3 w-3 inline mr-0.5")} Joined ${UI.relTime(u.created_at)}</span>
                ${u.last_login_at ? `<span title="Last login">${UI.icon("refresh", "h-3 w-3 inline mr-0.5")} Active ${UI.relTime(u.last_login_at)}</span>` : ""}
                ${UI.copyButton(u.id, "ID")}
              </div>
            </div>
          </div>
          ${actions}
        </header>
      </section>

      <section class="card card-pad">
        <div class="flex flex-wrap items-center gap-1.5 mb-4">${tabBar}</div>
        ${tabBody}
      </section>`;
  }

  function renderPermissionsTab(u, canManage) {
    const canEdit = canManage && A.has(A.P.PERM_MANAGE);
    const granted = u.permissions || [];
    if (!canEdit) {
      return `
        <header class="mb-2">
          <h4 class="text-sm font-semibold text-ink">Permissions (${granted.length})</h4>
          <p class="text-xs text-mute">Capabilities this user has on the current entity.</p>
        </header>
        <div class="flex flex-wrap gap-1.5">${granted.map((p) => `<span class="chip">${UI.escapeHtml(p)}</span>`).join("") || `<span class="text-xs text-mute italic">No permissions granted.</span>`}</div>`;
    }
    return `
      <header class="mb-3">
        <h4 class="text-sm font-semibold text-ink">Permissions</h4>
        <p class="text-xs text-mute">Pick which capabilities this user has. Save when you're done.</p>
      </header>
      ${UI.permissionGrid({ granted, scope: "entity" })}
      <div class="mt-4 flex items-center gap-2">
        <button type="button" class="btn btn-primary" id="perms-save">${UI.icon("check", "h-3.5 w-3.5")} Save permissions</button>
        <span id="perms-msg" class="text-xs text-mute"></span>
      </div>`;
  }

  async function renderProfilesTab(u, canManage) {
    const [profRes, memberRes] = await Promise.all([
      A.api("/api/v1/entities/" + A.viewEntityId() + "/profiles"),
      A.api("/api/v1/users/" + u.id + "/profiles"),
    ]);
    const allProfiles = profRes.ok ? (await profRes.json()).items || [] : [];
    let memberOf = [];
    if (memberRes.ok) memberOf = (await memberRes.json()).items || [];
    else memberOf = allProfiles.filter((p) => (p.member_ids || []).includes(u.id));

    return `
      <header class="mb-3 flex items-center justify-between">
        <div>
          <h4 class="text-sm font-semibold text-ink">Profiles (${memberOf.length})</h4>
          <p class="text-xs text-mute">Profiles this user can launch CVMs against. Each profile bundles a policy.</p>
        </div>
        ${canManage ? `<button type="button" class="btn btn-sm" id="user-assign-profile">${UI.icon("plus", "h-3.5 w-3.5")} Assign profile</button>` : ""}
      </header>
      ${memberOf.length ? `
        <ul class="divide-y divide-line/60">
          ${memberOf.map((p) => `
            <li class="flex items-center justify-between py-2.5">
              <div class="min-w-0">
                <div class="text-sm text-ink truncate">${UI.escapeHtml(p.name)}</div>
                ${p.description ? `<div class="mt-0.5 text-2xs text-mute truncate">${UI.escapeHtml(p.description)}</div>` : ""}
              </div>
              ${canManage ? `<button type="button" class="btn btn-ghost btn-xs" data-revoke-profile="${UI.escapeHtml(p.id)}" data-revoke-name="${UI.escapeHtml(p.name)}">${UI.icon("x", "h-3.5 w-3.5")} Revoke</button>` : ""}
            </li>
          `).join("")}
        </ul>` : `<p class="text-xs text-mute italic">No profile memberships. Assign one to enable CVM launches.</p>`}`;
  }

  async function renderQuotasTab(u) {
    const res = await A.api("/api/v1/users/" + u.id + "/quotas");
    if (!res.ok) return `<p class="text-sm text-err">${UI.escapeHtml(await A.parseError(res))}</p>`;
    const quotas = (await res.json()).quotas || [];
    return renderQuotaList(quotas, "user", u.id);
  }

  function renderQuotaList(quotas, scope, scopeId) {
    if (!quotas.length) {
      return `<p class="text-xs text-mute italic">No quotas defined. Resources inherit their default limit.</p>`;
    }
    return `
      <header class="mb-3">
        <h4 class="text-sm font-semibold text-ink">Quotas (${quotas.length})</h4>
        <p class="text-xs text-mute">Resource limits enforced server-side. Click the pencil to change a limit; the trash icon resets to default.</p>
      </header>
      <ul class="divide-y divide-line/60">
        ${quotas.map((q) => `
          <li class="flex items-center justify-between py-2.5">
            <div class="min-w-0">
              <div class="text-sm text-ink font-mono">${UI.escapeHtml(q.resource)}</div>
              <div class="mt-0.5 text-2xs text-mute">
                <span class="text-ink">${q.limit_value ?? "—"}</span> limit · used <span class="text-ink">${q.used ?? 0}</span>
                ${q.set_by ? `· set by ${UI.escapeHtml(q.set_by)} ${UI.relTime(q.set_at)}` : "· default"}
              </div>
            </div>
            ${A.has(A.P.QUOTA_MANAGE) ? `
              <div class="flex items-center gap-1">
                <button type="button" class="btn btn-ghost btn-xs" data-edit-quota="${UI.escapeHtml(q.resource)}" data-current="${q.limit_value ?? ""}" data-scope="${scope}" data-scope-id="${UI.escapeHtml(scopeId)}">${UI.icon("refresh", "h-3.5 w-3.5")} Edit</button>
                ${q.set_by ? `<button type="button" class="btn btn-ghost btn-xs btn-danger" data-clear-quota="${UI.escapeHtml(q.resource)}" data-scope="${scope}" data-scope-id="${UI.escapeHtml(scopeId)}">${UI.icon("x", "h-3.5 w-3.5")}</button>` : ""}
              </div>` : ""}
          </li>
        `).join("")}
      </ul>`;
  }

  function bindHandlers(panel) {
    panel.querySelectorAll("[data-uid]").forEach((btn) => {
      btn.addEventListener("click", () => {
        selectedUserId = btn.dataset.uid;
        renderUsers();
      });
    });
    panel.querySelectorAll("[data-user-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        userTab = btn.dataset.userTab;
        renderUsers();
      });
    });
    panel.querySelectorAll("[data-user-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        userFilter = btn.dataset.userFilter;
        selectedUserId = null;
        renderUsers();
      });
    });
    let st;
    panel.querySelector("#users-search")?.addEventListener("input", (e) => {
      userSearch = e.target.value;
      clearTimeout(st);
      st = setTimeout(renderUsers, 250);
    });
    panel.querySelector("#user-invite")?.addEventListener("click", openInviteModal);
    panel.querySelector("#user-deactivate")?.addEventListener("click", () => userAction("deactivate", "Deactivate user", "The user keeps existing CVMs but cannot perform new actions. Their session is invalidated."));
    panel.querySelector("#user-reactivate")?.addEventListener("click", () => userAction("reactivate", "Reactivate user", "Restore login and all previous permissions for this user."));
    panel.querySelector("#user-erase")?.addEventListener("click", eraseUser);
    panel.querySelector("#perms-save")?.addEventListener("click", savePermissions);
    panel.querySelector("#user-assign-profile")?.addEventListener("click", openAssignProfileModal);
    panel.querySelectorAll("[data-revoke-profile]").forEach((btn) => {
      btn.addEventListener("click", () => revokeProfile(btn.dataset.revokeProfile, btn.dataset.revokeName));
    });
    panel.querySelectorAll("[data-edit-quota]").forEach((btn) => {
      btn.addEventListener("click", () => editQuota(btn.dataset.editQuota, btn.dataset.current, btn.dataset.scope, btn.dataset.scopeId));
    });
    panel.querySelectorAll("[data-clear-quota]").forEach((btn) => {
      btn.addEventListener("click", () => clearQuota(btn.dataset.clearQuota, btn.dataset.scope, btn.dataset.scopeId));
    });
  }

  function openInviteModal() {
    UI.dialog({
      title: "Invite user",
      subtitle: "Invites the user to this entity. They will sign in with the same Google identity used for that email.",
      wide: true,
      primary: { label: "Send invite", run: doInvite },
      body: `
        <div class="space-y-4">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label class="field-label">Email <span class="text-err">*</span></label>
              <input id="iv-email" class="input" type="email" placeholder="alice@acme.com" autocomplete="off">
            </div>
            <div>
              <label class="field-label">Display name</label>
              <input id="iv-name" class="input" placeholder="Alice Walker" autocomplete="off">
            </div>
          </div>
          ${A.has(A.P.PERM_MANAGE) ? `
            <div>
              <label class="field-label">Initial permissions <span class="font-normal text-mute normal-case tracking-normal">(optional)</span></label>
              <p class="field-hint mb-2">Pick what the user can do immediately. You can also grant or revoke later.</p>
              ${UI.permissionGrid({ granted: [], scope: "entity" })}
            </div>
          ` : `<p class="text-xs text-mute italic">Permissions can be granted separately once the user joins.</p>`}
        </div>`,
      onBind: (overlay) => overlay.querySelector("#iv-email").focus(),
    });
  }

  async function doInvite(overlay) {
    const email = overlay.querySelector("#iv-email").value.trim();
    const name = overlay.querySelector("#iv-name").value.trim();
    if (!email) { UI.toast("Email is required", "err"); return false; }
    const permissions = Array.from(overlay.querySelectorAll("[data-perm]:checked")).map((c) => c.dataset.perm);
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/users", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify({ email, name, permissions }),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return false; }
    const u = await response.json();
    selectedUserId = u.id;
    UI.toast("Invite sent", "ok");
    renderUsers();
  }

  async function userAction(action, title, body) {
    const ok = await UI.confirm({
      title,
      message: body,
      okLabel: action.charAt(0).toUpperCase() + action.slice(1),
      danger: action === "deactivate",
    });
    if (!ok) return;
    const response = await A.api(
      "/api/v1/entities/" + A.viewEntityId() + "/users/" + selectedUserId + "/actions/" + action,
      { method: "POST", headers: { "Idempotency-Key": A.newIdempotencyKey() } }
    );
    if (response.ok) {
      UI.toast("User " + action + "d", "ok");
      renderUsers();
    } else UI.toast(await A.parseError(response), "err");
  }

  async function eraseUser() {
    const ok = await UI.strongConfirm({
      title: "Erase user",
      body: "Permanently removes this user and revokes all their permissions. Audit records remain. This cannot be undone. Type ERASE to confirm.",
      confirmWord: "ERASE",
      primary: "Erase",
      danger: true,
    });
    if (!ok) return;
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/users/" + selectedUserId, {
      method: "DELETE",
    });
    if (response.status === 204 || response.ok) {
      selectedUserId = null;
      UI.toast("User erased", "ok");
      renderUsers();
    } else UI.toast(await A.parseError(response), "err");
  }

  async function savePermissions() {
    const panel = A.el("panel-users");
    const desired = Array.from(panel.querySelectorAll("[data-perm]:checked")).map((c) => c.dataset.perm);
    const uRes = await A.api("/api/v1/entities/" + A.viewEntityId() + "/users/" + selectedUserId);
    if (!uRes.ok) { UI.toast("Failed to fetch user", "err"); return; }
    const u = await uRes.json();
    const etag = uRes.headers.get("ETag") || "";
    const current = new Set(u.permissions || []);
    const desiredSet = new Set(desired);
    const toGrant = desired.filter((p) => !current.has(p));
    const toRevoke = Array.from(current).filter((p) => !desiredSet.has(p));
    let ok = true;
    if (toGrant.length) {
      const r = await A.api("/api/v1/users/" + selectedUserId + "/permissions", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(etag ? { "If-Match": etag } : {}) },
        body: JSON.stringify({ permissions: toGrant }),
      });
      if (!r.ok) { UI.toast(await A.parseError(r), "err"); ok = false; }
    }
    if (ok) {
      for (const p of toRevoke) {
        const r = await A.api("/api/v1/users/" + selectedUserId + "/permissions/" + p, {
          method: "DELETE",
          headers: etag ? { "If-Match": etag } : {},
        });
        if (!r.ok && r.status !== 204) { UI.toast(await A.parseError(r), "err"); ok = false; break; }
      }
    }
    if (ok) {
      UI.toast(`Permissions updated (+${toGrant.length} / -${toRevoke.length})`, "ok");
      renderUsers();
    }
  }

  async function openAssignProfileModal() {
    const [profRes, memberRes] = await Promise.all([
      A.api("/api/v1/entities/" + A.viewEntityId() + "/profiles"),
      A.api("/api/v1/users/" + selectedUserId + "/profiles"),
    ]);
    const all = profRes.ok ? (await profRes.json()).items || [] : [];
    const memberOf = memberRes.ok ? (await memberRes.json()).items || [] : [];
    const memberIds = new Set(memberOf.map((p) => p.id));
    const candidates = all.filter((p) => !memberIds.has(p.id));
    if (!candidates.length) { UI.toast("User is already a member of every profile", "info"); return; }
    UI.dialog({
      title: "Assign profile",
      subtitle: "Adds the user to a profile so they can launch CVMs bound to it.",
      primary: { label: "Assign profile", run: doAssignProfile },
      body: `
        <div class="max-h-80 overflow-auto rounded-input border border-line">
          ${candidates.map((p) => `
            <label class="flex items-start gap-2 px-3 py-2 border-b border-line/60 hover:bg-elev cursor-pointer last:border-b-0">
              <input type="radio" name="prof-pick" value="${UI.escapeHtml(p.id)}" class="mt-0.5 accent-accent">
              <span class="min-w-0">
                <span class="block text-sm text-ink truncate">${UI.escapeHtml(p.name)}</span>
                ${p.description ? `<span class="block text-2xs text-mute truncate">${UI.escapeHtml(p.description)}</span>` : ""}
              </span>
            </label>
          `).join("")}
        </div>`,
    });
  }

  async function doAssignProfile(overlay) {
    const pick = overlay.querySelector("input[name=prof-pick]:checked");
    if (!pick) { UI.toast("Pick a profile", "err"); return false; }
    const profileId = pick.value;
    const pRes = await A.api("/api/v1/profiles/" + profileId);
    if (!pRes.ok) { UI.toast(await A.parseError(pRes), "err"); return false; }
    const etag = pRes.headers.get("ETag") || "";
    const response = await A.api("/api/v1/profiles/" + profileId + "/users", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey(), ...(etag ? { "If-Match": etag } : {}) },
      body: JSON.stringify({ user_id: selectedUserId }),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return false; }
    UI.toast("Profile assigned", "ok");
    renderUsers();
  }

  async function revokeProfile(profileId, name) {
    const ok = await UI.confirm({
      title: "Revoke profile",
      message: `Remove this user from "${name}"? They will lose the ability to launch CVMs that bind this profile.`,
      okLabel: "Revoke",
      danger: true,
    });
    if (!ok) return;
    const pRes = await A.api("/api/v1/profiles/" + profileId);
    if (!pRes.ok) { UI.toast(await A.parseError(pRes), "err"); return; }
    const etag = pRes.headers.get("ETag") || "";
    const response = await A.api("/api/v1/profiles/" + profileId + "/users/" + selectedUserId, {
      method: "DELETE",
      headers: etag ? { "If-Match": etag } : {},
    });
    if (response.status === 204 || response.ok) {
      UI.toast("Profile membership revoked", "ok");
      renderUsers();
    } else UI.toast(await A.parseError(response), "err");
  }

  async function editQuota(resource, current, scope, scopeId) {
    const path = scope === "entity"
      ? `/api/v1/entities/${scopeId}/quotas/${resource}`
      : `/api/v1/users/${scopeId}/quotas/${resource}`;
    UI.dialog({
      title: `Edit quota — ${resource}`,
      subtitle: "Set the maximum value for this resource. Leave blank to keep the default.",
      primary: {
        label: "Save quota",
        async run(overlay) {
          const raw = overlay.querySelector("[data-quota-input]").value.trim();
          if (raw === "") { UI.toast("Enter a number or use Clear to reset", "err"); return false; }
          const v = Number(raw);
          if (!Number.isInteger(v) || v < 0) { UI.toast("Limit must be a non-negative integer", "err"); return false; }
          const r = await A.api(path, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ limit_value: v }),
          });
          if (!r.ok) { UI.toast(await A.parseError(r), "err"); return false; }
          UI.toast("Quota updated", "ok");
          renderUsers();
        },
      },
      body: `
        <label class="field-label">Limit</label>
        <input class="input font-mono" data-quota-input value="${UI.escapeHtml(current || "")}" type="number" min="0" step="1" inputmode="numeric">
        <span class="field-hint">Resource: <span class="font-mono text-ink">${UI.escapeHtml(resource)}</span></span>`,
      onBind: (overlay) => overlay.querySelector("[data-quota-input]").focus(),
    });
  }

  async function clearQuota(resource, scope, scopeId) {
    const ok = await UI.confirm({
      title: `Clear quota — ${resource}`,
      message: "Removes the custom limit. The resource will inherit its default.",
      okLabel: "Clear",
      danger: true,
    });
    if (!ok) return;
    const path = scope === "entity"
      ? `/api/v1/entities/${scopeId}/quotas/${resource}`
      : `/api/v1/users/${scopeId}/quotas/${resource}`;
    const r = await A.api(path, { method: "DELETE" });
    if (r.ok || r.status === 204) {
      UI.toast("Quota cleared", "ok");
      renderUsers();
    } else UI.toast(await A.parseError(r), "err");
  }

  A.Views = A.Views || {};
  A.Views.renderUsers = renderUsers;
  // Deep-link target: focus a specific user (e.g. from the CVM detail drawer).
  A.Views.selectUser = function (id) {
    selectedUserId = id;
    userFilter = "all";
    userSearch = "";
  };
})(window.Admin);
