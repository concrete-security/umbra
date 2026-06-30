(function (A) {
  const UI = A.UI;

  const STATE_FILTERS = [
    ["all", "All"],
    ["running", "Running"],
    ["stopped", "Stopped"],
    ["error", "Error"],
    ["terminated", "Terminated"],
  ];

  function ensureState() {
    A.cvmsState = A.cvmsState || {
      sort: { col: "updated_at", dir: "desc" },
      selected: new Set(),
      ownerFilter: "",
      entityFilter: "",
    };
    return A.cvmsState;
  }

  function compareRows(a, b, col, dir) {
    const dirMul = dir === "asc" ? 1 : -1;
    const av = pickSortValue(a, col);
    const bv = pickSortValue(b, col);
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (av < bv) return -1 * dirMul;
    if (av > bv) return 1 * dirMul;
    return 0;
  }

  function pickSortValue(c, col) {
    if (col === "state") return String(c.state || "").toLowerCase();
    if (col === "owner") return String(c.owner?.email || c.owner_email || "").toLowerCase();
    if (col === "entity") return String(c.entity_name || "").toLowerCase();
    if (col === "fqdn") return String(c.fqdn || "").toLowerCase();
    if (col === "region") return String(c.region || "").toLowerCase();
    if (col === "profiles") return (c.profiles || []).length;
    if (col === "updated_at") return c.updated_at || "";
    return "";
  }

  function needsSecurityCvmRebind(cvm) {
    return cvm?.error_reason === "SECURITY_CVM_REBIND_REQUIRED";
  }

  function updateActionLabel(cvm) {
    return needsSecurityCvmRebind(cvm) ? "Rebind Security CVM trust" : "Update image";
  }

  function updateConfirmBody(cvm) {
    if (needsSecurityCvmRebind(cvm)) {
      return "Refresh this CVM's measured Security CVM CA and aTLS material. Use this after a Security CVM update reports CA rotation.";
    }
    return "Update this CVM to the latest measured image/config and re-attest it. Named volumes are preserved.";
  }

  function filterCvms(items, st) {
    let list = items.slice();
    if (A.fleetFilter && A.fleetFilter !== "all") {
      list = list.filter((c) => String(c.state).toLowerCase() === A.fleetFilter);
    }
    if (A.fleetSearch) {
      const q = A.fleetSearch.toLowerCase();
      list = list.filter(
        (c) =>
          (c.fqdn || "").toLowerCase().includes(q) ||
          (c.owner?.email || c.owner_email || "").toLowerCase().includes(q) ||
          (c.id || "").toLowerCase().includes(q) ||
          (c.entity_name || "").toLowerCase().includes(q)
      );
    }
    if (st.ownerFilter) list = list.filter((c) => (c.owner?.email || c.owner_email || "") === st.ownerFilter);
    if (st.entityFilter) list = list.filter((c) => (c.entity_id || "") === st.entityFilter);
    list.sort((a, b) => compareRows(a, b, st.sort.col, st.sort.dir));
    return list;
  }

  function renderRowKebab(c, st) {
    const canAct = A.canActOnCvms() && A.has(A.P.CVM_MANAGE);
    const state = String(c.state || "").toLowerCase();
    const items = [{ id: "open", label: "Open detail", icon: "external" }];
    if (canAct) {
      if (state === "stopped" || state === "error") items.push({ id: "start", label: "Start", icon: "refresh" });
      if (state === "running") items.push({ id: "stop", label: "Stop", icon: "x" });
      if (state === "running" || state === "stopped") items.push({ id: "update", label: updateActionLabel(c), icon: "refresh" });
    }
    items.push({ id: "copy-id", label: "Copy ID", icon: "copy" });
    if (c.fqdn) items.push({ id: "copy-ssh", label: "Copy SSH command", icon: "terminal" });
    if (canAct && state !== "terminated") items.push({ id: "terminate", label: "Terminate", icon: "x", danger: true });
    return UI.kebabMenu(items);
  }

  function actionsBar(st) {
    if (!st.selected.size || !A.canActOnCvms()) return "";
    const n = st.selected.size;
    return `
      <div class="card card-pad mb-3 flex flex-wrap items-center gap-2 border-accent/30 bg-accent/5">
        <span class="text-sm text-ink font-medium">${n} selected</span>
        <span class="flex-1"></span>
        <button type="button" class="btn btn-xs" data-bulk="start">${UI.icon("refresh", "h-3.5 w-3.5")} Start</button>
        <button type="button" class="btn btn-xs" data-bulk="stop">${UI.icon("x", "h-3.5 w-3.5")} Stop</button>
        <button type="button" class="btn btn-xs" data-bulk="update">${UI.icon("refresh", "h-3.5 w-3.5")} Update</button>
        <button type="button" class="btn btn-xs btn-danger" data-bulk="terminate">${UI.icon("x", "h-3.5 w-3.5")} Terminate</button>
        <button type="button" class="btn btn-xs btn-ghost" data-bulk="clear">Clear</button>
      </div>`;
  }

  function rowCheckbox(c, st) {
    const checked = st.selected.has(c.id) ? "checked" : "";
    return `<label class="inline-flex items-center" onclick="event.stopPropagation()">
      <input type="checkbox" data-cvm-select="${UI.escapeHtml(c.id)}" class="accent-accent h-3.5 w-3.5" ${checked}>
    </label>`;
  }

  async function renderCvms() {
    const panel = A.el("panel-cvms");
    if (!panel) return;
    const st = ensureState();
    const isPlatform = A.isPlatform();
    const canLaunch = A.canActOnCvms() && A.has(A.P.CVM_LAUNCH);

    if (!A.firstLoad) A.firstLoad = {};
    const firstLoad = !A.firstLoad.cvms;
    A.firstLoad.cvms = true;

    if (firstLoad) {
      panel.innerHTML =
        UI.pageHeader("Confidential VMs", "Each CVM is an attested sandbox running your AI agents. Launch new ones, attach policy profiles, and start or stop on demand — the same controls available from the CLI.", {
          icon: "cvm",
          actions: canLaunch ? `<button type="button" class="btn btn-primary" id="cvms-launch">${UI.icon("plus", "h-4 w-4")} Launch CVM</button>` : "",
        }) +
        UI.skeletonTable(6, 5);
    }

    const cvms = await A.fetchCvms();
    const fleet = filterCvms(cvms, st);

    // Counts for state chips
    const counts = cvms.reduce((acc, c) => {
      const k = String(c.state || "").toLowerCase();
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {});
    counts.all = cvms.length;
    const filterChips = STATE_FILTERS.map(([id, label]) =>
      `<button type="button" class="filter-chip${A.fleetFilter === id ? " active" : ""}" data-fleet-filter="${id}">
        ${UI.escapeHtml(label)} <span class="text-mute-soft">${counts[id] || 0}</span>
      </button>`
    ).join("");

    // Owner filter values (when platform)
    let ownerFilterUi = "";
    if (isPlatform) {
      const owners = Array.from(new Set(cvms.map((c) => c.owner?.email || c.owner_email).filter(Boolean))).sort();
      ownerFilterUi = `
        <select class="input input-sm w-44" data-owner-filter>
          <option value="">All owners</option>
          ${owners.map((o) => `<option value="${UI.escapeHtml(o)}" ${o === st.ownerFilter ? "selected" : ""}>${UI.escapeHtml(o)}</option>`).join("")}
        </select>`;
    }

    const cols = [
      {
        key: "select",
        label: "",
        sortable: false,
        cellClass: "w-8",
        render: (c) => A.canActOnCvms() ? rowCheckbox(c, st) : "",
      },
      {
        key: "state",
        label: "State",
        render: (c) => {
          const pending = A.Ops.pendingForCvm(c.id).length;
          const op = pending ? ` <span class="badge badge-pending">${UI.icon("clock", "h-3 w-3")} op</span>` : "";
          const rebind = needsSecurityCvmRebind(c)
            ? ` <span class="badge badge-warn">${UI.icon("alert", "h-3 w-3")} SC rebind</span>`
            : "";
          return UI.badge(c.state) + rebind + op;
        },
      },
      {
        key: "owner",
        label: "Owner",
        render: (c) => UI.escapeHtml(c.owner?.email || c.owner_email || "—"),
      },
    ];
    if (isPlatform) {
      cols.push({ key: "entity", label: "Entity", render: (c) => UI.escapeHtml(c.entity_name || "—") });
    }
    cols.push(
      { key: "fqdn", label: "FQDN", render: (c) => c.fqdn ? UI.copyButton(c.fqdn) : '<span class="text-mute">—</span>' },
      { key: "region", label: "Region", render: (c) => UI.escapeHtml(c.region || "—") },
      {
        key: "profiles",
        label: "Profiles",
        render: (c) => {
          const ps = c.profiles || [];
          if (!ps.length) return '<span class="text-mute">—</span>';
          return ps.map((p) => `<span class="chip chip-accent mr-1">${UI.escapeHtml(p.name)}</span>`).join("");
        },
      },
      { key: "updated_at", label: "Updated", render: (c) => `<span class="text-mute" title="${UI.escapeHtml(UI.fmtTsFull(c.updated_at))}">${UI.relTime(c.updated_at)}</span>` },
    );

    const table = fleet.length
      ? UI.tableV2(cols, fleet, {
          sort: st.sort,
          onSort: true,
          onRowClick: true,
          rowAttr: (c) => `data-cvm-id="${UI.escapeHtml(c.id)}"`,
          rowAction: (c) => renderRowKebab(c, st),
          tall: true,
        })
      : UI.emptyV2({
          icon: "cvm",
          title: A.fleetSearch || A.fleetFilter !== "all" ? "No CVMs match these filters" : "Launch your first CVM",
          body: A.fleetSearch || A.fleetFilter !== "all"
            ? "Clear the search and filters to see every CVM in this entity."
            : "Each CVM is a confidential, attested sandbox. Once launched, attach a profile and SSH in from the CLI.",
          ctaLabel: canLaunch && !(A.fleetSearch || A.fleetFilter !== "all") ? "Launch CVM" : null,
          ctaId: "cvms-empty-launch",
        });

    panel.innerHTML =
      UI.pageHeader("Confidential VMs", "Each CVM is an attested sandbox running your AI agents. Launch new ones, attach policy profiles, and start or stop on demand — the same controls available from the CLI.", {
        icon: "cvm",
        actions: canLaunch
          ? `<button type="button" class="btn btn-primary" id="cvms-launch">${UI.icon("plus", "h-4 w-4")} Launch CVM</button>`
          : "",
      }) +
      `<div class="card card-pad mb-4">
        <div class="flex flex-wrap items-center gap-2.5">
          <label class="relative inline-flex items-center w-72">
            ${UI.icon("search", "h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-mute pointer-events-none")}
            <input type="search" class="input input-sm pl-8 w-full" data-search id="cvms-search" placeholder="Search FQDN, owner, ID, entity…" value="${UI.escapeHtml(A.fleetSearch)}">
          </label>
          <div class="flex flex-wrap items-center gap-1.5">${filterChips}</div>
          ${ownerFilterUi}
        </div>
      </div>
      ${actionsBar(st)}
      ${table}`;

    bindHandlers(panel, fleet, st);
  }

  function bindHandlers(panel, fleet, st) {
    panel.querySelector("#cvms-launch")?.addEventListener("click", () => A.openLaunchModal());
    panel.querySelector("#cvms-empty-launch")?.addEventListener("click", () => A.openLaunchModal());

    let searchTimer;
    panel.querySelector("#cvms-search")?.addEventListener("input", (e) => {
      A.fleetSearch = e.target.value;
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => renderCvms(), 250);
    });

    panel.querySelectorAll("[data-fleet-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        A.fleetFilter = btn.dataset.fleetFilter;
        st.selected.clear();
        renderCvms();
      });
    });

    panel.querySelector("[data-owner-filter]")?.addEventListener("change", (e) => {
      st.ownerFilter = e.target.value;
      renderCvms();
    });

    panel.querySelectorAll("[data-sort-col]").forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.dataset.sortCol;
        if (st.sort.col === col) st.sort.dir = st.sort.dir === "asc" ? "desc" : "asc";
        else { st.sort.col = col; st.sort.dir = "asc"; }
        renderCvms();
      });
    });

    panel.querySelectorAll("[data-row-idx]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("[data-kebab]") || e.target.closest("input[type=checkbox]") || e.target.closest("[data-copy]")) return;
        const id = tr.dataset.cvmId;
        const cvm = fleet.find((c) => c.id === id);
        if (cvm) A.Drawer.openCvm(cvm, "summary");
      });
      tr.querySelectorAll("[data-kebab-action]").forEach((btn) => {
        btn.addEventListener("click", async (e) => {
          e.stopPropagation();
          const id = tr.dataset.cvmId;
          const cvm = fleet.find((c) => c.id === id);
          if (!cvm) return;
          panel.querySelectorAll("[data-kebab-panel]").forEach((p) => p.classList.add("hidden"));
          await handleRowAction(btn.dataset.kebabAction, cvm);
        });
      });
    });

    panel.querySelectorAll("[data-cvm-select]").forEach((cb) => {
      cb.addEventListener("change", () => {
        const id = cb.dataset.cvmSelect;
        if (cb.checked) st.selected.add(id);
        else st.selected.delete(id);
        renderCvms();
      });
    });

    panel.querySelectorAll("[data-bulk]").forEach((btn) => {
      btn.addEventListener("click", () => handleBulk(btn.dataset.bulk, fleet, st));
    });
  }

  async function handleRowAction(action, cvm) {
    if (action === "open") return A.Drawer.openCvm(cvm, "summary");
    if (action === "copy-id") { navigator.clipboard?.writeText(cvm.id); return A.UI.toast("CVM ID copied", "ok"); }
    if (action === "copy-ssh") { navigator.clipboard?.writeText(`concrete ssh ${cvm.id}`); return A.UI.toast("SSH command copied", "ok"); }
    if (action === "start") return runCvmAction(cvm, "start", "Start CVM", "Boot this CVM and reconnect its profile bindings.");
    if (action === "stop") return runCvmAction(cvm, "stop", "Stop CVM", "Suspend this CVM. Disk state is preserved. You can restart it later.");
    if (action === "update") return runCvmAction(cvm, "update", updateActionLabel(cvm), updateConfirmBody(cvm));
    if (action === "terminate") {
      const ok = await A.UI.strongConfirm({
        title: "Terminate " + (cvm.fqdn || cvm.id),
        body: "This destroys the CVM and its data. Volumes are not recoverable. Type TERMINATE to confirm.",
        confirmWord: "TERMINATE",
        primary: "Terminate",
        danger: true,
      });
      if (ok) await runCvmAction(cvm, "terminate", null, null, true);
    }
  }

  async function runCvmAction(cvm, action, confirmTitle, confirmBody, skipConfirm) {
    if (!skipConfirm && confirmTitle) {
      const ok = await A.UI.confirm({ title: confirmTitle, message: confirmBody, okLabel: action.charAt(0).toUpperCase() + action.slice(1) });
      if (!ok) return;
    }
    const response = await A.api(`/api/v1/cvms/${cvm.id}/actions/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: "{}",
    });
    if (!response.ok) { A.UI.toast(await A.parseError(response), "err"); return; }
    const label = action.charAt(0).toUpperCase() + action.slice(1);
    // start/stop are synchronous and return the CVM resource; update/terminate
    // return a 202 operation we poll to completion.
    if (action === "start" || action === "stop") {
      A.UI.toast(`${label} accepted`, "ok");
      await A.refreshActivePanel();
      return;
    }
    const op = await response.json();
    A.Ops.track(op);
    A.UI.toast(`${label} started`, "ok");
    try {
      await A.Ops.poll(op.id);
      await A.refreshActivePanel();
    } catch (e) {
      A.UI.toast(e.message || "Action failed", "err");
    }
  }

  async function handleBulk(action, fleet, st) {
    if (action === "clear") { st.selected.clear(); renderCvms(); return; }
    const targets = fleet.filter((c) => st.selected.has(c.id));
    if (!targets.length) return;
    if (action === "terminate") {
      const ok = await A.UI.strongConfirm({
        title: `Terminate ${targets.length} CVM${targets.length > 1 ? "s" : ""}`,
        body: `This destroys ${targets.length} CVM${targets.length > 1 ? "s" : ""} and their data. Volumes are not recoverable. Type TERMINATE to confirm.`,
        confirmWord: "TERMINATE",
        primary: "Terminate all",
        danger: true,
      });
      if (!ok) return;
    } else {
      const rebindCount = targets.filter(needsSecurityCvmRebind).length;
      const ok = await A.UI.confirm({
        title: `${action.charAt(0).toUpperCase() + action.slice(1)} ${targets.length} CVM${targets.length > 1 ? "s" : ""}`,
        message: action === "update" && rebindCount
          ? `Update all selected CVMs? ${rebindCount} need Security CVM trust rebinding after CA rotation.`
          : `Apply ${action} to all selected CVMs?`,
        okLabel: action.charAt(0).toUpperCase() + action.slice(1),
      });
      if (!ok) return;
    }
    let okCount = 0;
    for (const cvm of targets) {
      try {
        await runCvmAction(cvm, action, null, null, true);
        okCount += 1;
      } catch (_) {}
    }
    st.selected.clear();
    A.UI.toast(`${okCount}/${targets.length} ${action} actions started`, okCount === targets.length ? "ok" : "err");
    renderCvms();
  }

  A.Views = A.Views || {};
  A.Views.renderCvms = renderCvms;
})(window.Admin);
