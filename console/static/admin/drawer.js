(function (A) {
  const UI = A.UI;
  const Drawer = {
    closeAll() {
      A.selectedCvm = null;
      A.selectedSc = null;
      A.drawerKind = null;
      A.egressCursor = null;
      if (!location.hash.startsWith("#modal")) location.hash = "";
      ["cvm-drawer", "sc-drawer", "entity-drawer"].forEach((id) => {
        const el = A.el(id);
        if (!el) return;
        el.classList.add("hidden");
        el.setAttribute("aria-hidden", "true");
      });
    },

    bind() {
      document.querySelectorAll("[data-close-drawer]").forEach((node) => {
        node.addEventListener("click", () => Drawer.closeAll());
      });
    },

    async openCvm(cvmOrId, tab) {
      let cvm = typeof cvmOrId === "string" ? await A.fetchCvmDetail(cvmOrId) : cvmOrId;
      if (!cvm) return;
      A.selectedCvm = cvm;
      A.selectedSc = null;
      A.drawerKind = "cvm";
      A.egressCursor = null;
      A.drawerTab = tab || (A.has(A.P.TRAFFIC) ? "egress" : "summary");
      location.hash = "cvm/" + cvm.id;
      const drawer = A.el("cvm-drawer");
      drawer.classList.remove("hidden");
      drawer.setAttribute("aria-hidden", "false");
      A.el("sc-drawer").classList.add("hidden");
      A.el("drawer-title").innerHTML =
        "<h2>" +
        UI.badge(cvm.state) +
        " " +
        UI.escapeHtml(cvm.fqdn || cvm.id) +
        '</h2><div class="sub mono">' +
        UI.escapeHtml(cvm.id) +
        "</div>";
      await Drawer.renderCvmBody();
    },

    async openSc(scOrId, tab) {
      let sc = typeof scOrId === "object" ? scOrId : await A.fetchSecurityCvm();
      if (!sc) return;
      A.selectedSc = sc;
      A.selectedCvm = null;
      A.drawerKind = "sc";
      A.egressCursor = null;
      A.drawerTab = tab || (A.has(A.P.TRAFFIC) ? "egress" : "summary");
      location.hash = "sc/" + sc.id;
      A.el("cvm-drawer").classList.add("hidden");
      const drawer = A.el("sc-drawer");
      drawer.classList.remove("hidden");
      drawer.setAttribute("aria-hidden", "false");
      A.el("sc-drawer-title").innerHTML =
        "<h2>" +
        UI.badge(sc.state, "Security CVM") +
        " " +
        UI.escapeHtml(sc.fqdn || sc.id) +
        '</h2><div class="sub mono">' +
        UI.escapeHtml(sc.id) +
        "</div>";
      await Drawer.renderScBody();
    },

    async renderActive() {
      if (A.drawerKind === "cvm" && A.selectedCvm) await Drawer.renderCvmBody();
      if (A.drawerKind === "sc" && A.selectedSc) await Drawer.renderScBody();
    },

    cvmTabs() {
      const tabs = [];
      if (A.has(A.P.TRAFFIC)) tabs.push(["egress", "Egress"]);
      tabs.push(["summary", "Summary"]);
      if (A.has(A.P.AUDIT)) tabs.push(["audit", "Audit"]);
      if (A.canActOnCvms() && A.selectedCvm?.state !== "terminated") tabs.push(["actions", "Actions"]);
      return tabs;
    },

    tabBar(tabs, active) {
      return (
        '<div class="drawer-tabs">' +
        tabs
          .map(
            ([id, label]) =>
              '<button type="button" data-dtab="' +
              id +
              '"' +
              (active === id ? ' class="active"' : "") +
              ">" +
              label +
              "</button>"
          )
          .join("") +
        "</div>"
      );
    },

    async renderCvmBody() {
      const cvm = A.selectedCvm;
      if (!cvm) return;
      const body = A.el("drawer-body");
      const tabs = Drawer.cvmTabs();
      let html = Drawer.tabBar(tabs, A.drawerTab);

      if (A.drawerTab === "egress" && A.has(A.P.TRAFFIC)) {
        html += await Drawer.renderEgressPanel(cvm.id, false);
      } else if (A.drawerTab === "summary") {
        html += Drawer.renderCvmSummary(cvm);
      } else if (A.drawerTab === "audit" && A.has(A.P.AUDIT)) {
        html += await Drawer.renderCvmAudit(cvm.id);
      } else if (A.drawerTab === "actions") {
        html += await Drawer.renderCvmActions(cvm);
      } else {
        html += '<p class="muted">No permission for this tab.</p>';
      }

      body.innerHTML = html;
      Drawer.bindCvmBody(body, cvm);
    },

    renderCvmSummary(cvm) {
      const profiles = (cvm.profiles || [])
        .map((p) => '<span class="chip">' + UI.escapeHtml(p.name) + "</span>")
        .join("");
      let html =
        '<div class="card"><h3>Instance</h3>' +
        "<p>Owner: " +
        UI.escapeHtml(cvm.owner?.email || cvm.owner_email || "—") +
        "</p>" +
        "<p>Region: " +
        UI.escapeHtml(cvm.region || "—") +
        " · Type: " +
        UI.escapeHtml(cvm.instance_type || "—") +
        "</p>";
      if (cvm.image_measurement) {
        html += '<p class="mono muted">Measurement: ' + UI.escapeHtml(cvm.image_measurement.slice(0, 24)) + "…</p>";
      }
      if (cvm.phala_status) {
        html += "<p>Phala: " + UI.escapeHtml(cvm.phala_status) + " " + UI.escapeHtml(cvm.phala_uptime || "") + "</p>";
      }
      if (cvm.error_reason) html += '<p class="err">' + UI.escapeHtml(cvm.error_reason) + "</p>";
      html +=
        "<h3>Profiles</h3><div class=\"chips\">" +
        (profiles || '<span class="muted">none</span>') +
        "</div></div>";
      const pending = A.Ops.pendingForCvm(cvm.id);
      if (pending.length) {
        html += '<div class="card"><h3>In progress</h3><p class="state-warn">' + pending.map((o) => o.kind).join(", ") + "</p></div>";
      }
      return html;
    },

    async renderEgressPanel(cvmId, isSc) {
      const sc = await A.fetchEntitySc();
      const f = A.egressFilters;
      const params = { limit: "50" };
      if (isSc && sc) params.security_cvm_id = sc.id;
      else params.cvm_id = cvmId;
      if (f.window && f.window !== "all") {
        const from = A.trafficFromIso(f.window);
        if (from) params.from = from;
      }
      if (A.egressCursor) params.cursor = A.egressCursor;
      const body = await A.fetchTrafficLogs(params);
      let items = body.items || [];
      if (f.host) {
        const h = f.host.toLowerCase();
        items = items.filter((t) => (t.destination_host || "").toLowerCase().includes(h));
      }
      if (f.code === "2xx") items = items.filter((t) => t.response_code >= 200 && t.response_code < 300);
      else if (f.code === "4xx") items = items.filter((t) => t.response_code >= 400);

      const scLabel = sc?.fqdn ? UI.escapeHtml(sc.fqdn) : "entity Security CVM";
      let html =
        '<div class="card"><p class="muted egress-via">Egress via ' +
        scLabel +
        '</p><div class="toolbar egress-filters">' +
        '<input type="search" id="egress-host" placeholder="Filter host" value="' +
        UI.escapeHtml(f.host) +
        '">' +
        '<select id="egress-code"><option value="">All codes</option><option value="2xx"' +
        (f.code === "2xx" ? " selected" : "") +
        '>2xx</option><option value="4xx"' +
        (f.code === "4xx" ? " selected" : "") +
        '>4xx+</option></select>' +
        '<select id="egress-window"><option value="15m"' +
        (f.window === "15m" ? " selected" : "") +
        '>15m</option><option value="1h"' +
        (f.window === "1h" ? " selected" : "") +
        '>1h</option><option value="24h"' +
        (f.window === "24h" ? " selected" : "") +
        '>24h</option><option value="all"' +
        (f.window === "all" ? " selected" : "") +
        '>All</option></select></div>';

      const rows = items.map((t, idx) => [
        UI.fmtTs(t.timestamp),
        UI.escapeHtml(t.method || "—"),
        UI.escapeHtml(t.destination_host || "—"),
        UI.escapeHtml((t.path || "—").slice(0, 48)),
        '<span class="' + UI.codeClass(t.response_code) + '">' + (t.response_code ?? "—") + "</span>",
        String(t.bytes_transferred ?? 0),
        '<button type="button" class="btn ghost btn-xs" data-expand="' + idx + '">+</button>',
      ]);
      html +=
        UI.tableHtml(["Time", "Method", "Host", "Path", "Code", "Bytes", ""], rows, { clickable: false, tall: true }) +
        (body.next_cursor
          ? '<button type="button" class="btn" id="egress-more">Load more</button>'
          : "") +
        "</div>";
      html += '<div id="egress-detail" class="card hidden"></div>';
      A._egressItems = items;
      A._egressNext = body.next_cursor;
      return html;
    },

    async renderCvmAudit(cvmId) {
      const q = new URLSearchParams({
        target_type: "cvm",
        target_id: cvmId,
        limit: "40",
      });
      const path = A.isPlatform()
        ? A.adminQuery("audit/events", Object.fromEntries(q))
        : "/api/v1/audit/events?" + q.toString();
      const res = await A.api(path);
      const items = res.ok ? (await res.json()).items || [] : [];
      const rows = items.map((a) => [
        UI.fmtTs(a.timestamp),
        UI.escapeHtml(a.action),
        UI.escapeHtml(a.actor_email || "—"),
      ]);
      return '<div class="card"><h3>Audit</h3>' + UI.tableHtml(["Time", "Action", "Actor"], rows) + "</div>";
    },

    async renderCvmActions(cvm) {
      const canManage = A.isHomeEntity() && A.has(A.P.CVM_MANAGE);
      let html = '<div class="card"><h3>Lifecycle</h3><div class="toolbar">';
      if (canManage && cvm.state !== "terminated") {
        if (cvm.state === "running") html += '<button type="button" class="btn" id="cvm-stop">Stop</button>';
        else html += '<button type="button" class="btn" id="cvm-start">Start</button>';
        html += '<button type="button" class="btn" id="cvm-update">Update</button>';
        html += '<button type="button" class="btn danger" id="cvm-terminate">Terminate</button>';
      }
      html += "</div><div id=\"cvm-action-msg\" class=\"msg\"></div></div>";

      if (canManage && cvm.state !== "terminated") {
        const profRes = await A.api("/api/v1/entities/" + A.viewEntityId() + "/profiles");
        const profiles = profRes.ok ? (await profRes.json()).items || [] : [];
        const attached = new Set((cvm.profiles || []).map((p) => p.id));
        html +=
          '<div class="card"><h3>Profiles</h3><div class="chips">' +
          (cvm.profiles || [])
            .map(
              (p) =>
                '<span class="chip">' +
                UI.escapeHtml(p.name) +
                ' <button type="button" class="chip-x" data-detach="' +
                p.id +
                '">×</button></span>'
            )
            .join("") +
          '</div><div class="field"><label>Attach profile</label><select id="attach-profile"><option value="">—</option>' +
          profiles
            .filter((p) => !attached.has(p.id))
            .map((p) => '<option value="' + p.id + '">' + UI.escapeHtml(p.name) + "</option>")
            .join("") +
          '</select></div><button type="button" class="btn" id="cvm-attach">Attach</button></div>';
      }
      return html;
    },

    bindCvmBody(body, cvm) {
      body.querySelectorAll("[data-dtab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          A.drawerTab = btn.dataset.dtab;
          if (A.drawerTab !== "egress") A.egressCursor = null;
          Drawer.renderCvmBody();
        });
      });
      const applyEgressFilter = () => {
        A.egressFilters.host = body.querySelector("#egress-host")?.value || "";
        A.egressFilters.code = body.querySelector("#egress-code")?.value || "";
        A.egressFilters.window = body.querySelector("#egress-window")?.value || "15m";
        A.egressCursor = null;
        Drawer.renderCvmBody();
      };
      body.querySelector("#egress-host")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-code")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-window")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-more")?.addEventListener("click", () => {
        A.egressCursor = A._egressNext;
        Drawer.renderCvmBody();
      });
      body.querySelectorAll("[data-expand]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const t = A._egressItems[Number(btn.dataset.expand)];
          if (!t) return;
          const detail = body.querySelector("#egress-detail");
          detail.classList.remove("hidden");
          detail.innerHTML =
            "<h3>Request detail</h3><pre class=\"mono\">" +
            UI.escapeHtml(
              JSON.stringify(
                {
                  source_ip: t.source_ip,
                  destination_ip: t.destination_ip,
                  protocol: t.protocol,
                  port: t.port,
                  path: t.path,
                },
                null,
                2
              )
            ) +
            "</pre>";
        });
      });
      body.querySelector("#cvm-start")?.addEventListener("click", () => Drawer.cvmSyncAction("start"));
      body.querySelector("#cvm-stop")?.addEventListener("click", () => Drawer.cvmSyncAction("stop"));
      body.querySelector("#cvm-update")?.addEventListener("click", () => Drawer.cvmAsyncAction("update"));
      body.querySelector("#cvm-terminate")?.addEventListener("click", () => Drawer.cvmAsyncAction("terminate"));
      body.querySelector("#cvm-attach")?.addEventListener("click", () => Drawer.attachProfile(cvm));
      body.querySelectorAll("[data-detach]").forEach((btn) => {
        btn.addEventListener("click", () => Drawer.detachProfile(cvm.id, btn.dataset.detach));
      });
    },

    async cvmSyncAction(action) {
      const msg = A.el("cvm-action-msg") || A.el("drawer-body").querySelector("#cvm-action-msg");
      if (!A.selectedCvm || !msg) return;
      msg.textContent = "Sending…";
      const response = await A.api("/api/v1/cvms/" + A.selectedCvm.id + "/actions/" + action, {
        method: "POST",
        headers: { "Idempotency-Key": A.newIdempotencyKey() },
      });
      if (response.ok) {
        UI.toast(action + " accepted", "ok");
        A.selectedCvm = await A.fetchCvmDetail(A.selectedCvm.id);
        await Drawer.renderCvmBody();
        A.refreshActivePanel();
      } else {
        msg.textContent = await A.parseError(response);
        msg.className = "msg err";
      }
    },

    async cvmAsyncAction(action) {
      const cvm = A.selectedCvm;
      if (!cvm) return;
      const labels = { update: "Update this CVM?", terminate: "Terminate this CVM? This cannot be undone." };
      const ok = await UI.confirm({
        title: action === "terminate" ? "Terminate CVM" : "Update CVM",
        message: labels[action] || "Continue?",
        danger: action === "terminate",
        okLabel: action === "terminate" ? "Terminate" : "Update",
      });
      if (!ok) return;
      const response = await A.api("/api/v1/cvms/" + cvm.id + "/actions/" + action, {
        method: "POST",
        headers: { "Idempotency-Key": A.newIdempotencyKey() },
      });
      if (!response.ok) {
        UI.toast(await A.parseError(response), "err");
        return;
      }
      const op = await response.json();
      A.Ops.track(op);
      UI.toast(action + " started", "ok");
      try {
        await A.Ops.poll(op.id, () => Drawer.renderCvmBody());
        A.selectedCvm = await A.fetchCvmDetail(cvm.id);
        UI.toast(action + " " + (A.selectedCvm?.state || "done"), "ok");
        await Drawer.renderCvmBody();
        A.refreshActivePanel();
      } catch (e) {
        UI.toast(e.message || "Operation failed", "err");
      }
    },

    async attachProfile(cvm) {
      const sel = A.el("drawer-body").querySelector("#attach-profile");
      const profileId = sel?.value;
      if (!profileId) return;
      const response = await A.api("/api/v1/cvms/" + cvm.id + "/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile_id: profileId }),
      });
      if (response.ok) {
        UI.toast("Profile attached", "ok");
        A.selectedCvm = await A.fetchCvmDetail(cvm.id);
        await Drawer.renderCvmBody();
      } else UI.toast(await A.parseError(response), "err");
    },

    async detachProfile(cvmId, profileId) {
      const ok = await UI.confirm({ title: "Detach profile", message: "Remove this profile from the CVM?" });
      if (!ok) return;
      const response = await A.api("/api/v1/cvms/" + cvmId + "/profiles/" + profileId, { method: "DELETE" });
      if (response.ok) {
        UI.toast("Profile detached", "ok");
        A.selectedCvm = await A.fetchCvmDetail(cvmId);
        await Drawer.renderCvmBody();
      } else UI.toast(await A.parseError(response), "err");
    },

    async renderScBody() {
      const sc = A.selectedSc;
      if (!sc) return;
      const body = A.el("sc-drawer-body");
      const tabs = [
        ...(A.has(A.P.TRAFFIC) ? [["egress", "Egress"]] : []),
        ["summary", "Summary"],
      ];
      let html = Drawer.tabBar(tabs, A.drawerTab);
      if (A.drawerTab === "egress" && A.has(A.P.TRAFFIC)) {
        html += await Drawer.renderEgressPanel(null, true);
      } else {
        html += '<div class="card"><p>FQDN: <span class="mono">' + UI.escapeHtml(sc.fqdn || "—") + "</span></p>";
        html += "<p>State: " + UI.badge(sc.state) + "</p></div>";
        if ((A.has(A.P.USER_MANAGE) || A.isPlatform()) && A.isHomeEntity()) {
          const att = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm/attestation");
          if (att.ok) {
            const a = await att.json();
            html +=
              '<div class="card"><h3>Attestation</h3><p class="mono muted">Image: ' +
              UI.escapeHtml((a.image_measurement || "—").slice(0, 32)) +
              '…</p><p class="mono muted">Verified: ' +
              UI.escapeHtml(a.attestation_verified_at || "—") +
              "</p></div>";
          }
        }
      }
      body.innerHTML = html;
      body.querySelectorAll("[data-dtab]").forEach((btn) => {
        btn.addEventListener("click", () => {
          A.drawerTab = btn.dataset.dtab;
          A.egressCursor = null;
          Drawer.renderScBody();
        });
      });
      const applyEgressFilter = () => {
        A.egressFilters.host = body.querySelector("#egress-host")?.value || "";
        A.egressFilters.code = body.querySelector("#egress-code")?.value || "";
        A.egressFilters.window = body.querySelector("#egress-window")?.value || "15m";
        A.egressCursor = null;
        Drawer.renderScBody();
      };
      body.querySelector("#egress-host")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-code")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-window")?.addEventListener("change", applyEgressFilter);
      body.querySelector("#egress-more")?.addEventListener("click", () => {
        A.egressCursor = A._egressNext;
        Drawer.renderScBody();
      });
    },
  };

  A.Drawer = Drawer;
})(window.Admin);
