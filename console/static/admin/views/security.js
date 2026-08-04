(function (A) {
  const UI = A.UI;

  function devCvmUpdateList(ids) {
    if (!ids || !ids.length) return "";
    return `
      <div class="rounded-input border border-line bg-elev/40 p-3 mt-3">
        <div class="text-2xs uppercase tracking-wider text-mute mb-2">Dev CVMs requiring update</div>
        <ul class="space-y-1.5">
          ${ids.map((id) => `
            <li class="flex items-center justify-between gap-2 text-xs">
              <span class="font-mono text-ink-dim break-all">${UI.escapeHtml(id)}</span>
              <span>${UI.copyButton(`umbra cvm update ${id}`, "Copy CLI command")}</span>
            </li>
          `).join("")}
        </ul>
      </div>`;
  }

  function measurementFromSecurityCvm(sc, attestation) {
    const verdict = attestation?.verdict || {};
    const expected = attestation?.expected_image_measurement || sc?.expected_image_measurement;
    const seen = verdict.image_measurement_seen || sc?.image_measurement;
    const rtmr3 = verdict.rtmr3_digest_seen || sc?.rtmr3_digest;
    const verifiedAt = verdict.verified_at || sc?.attestation_verified_at;
    const inferredVerified = expected && seen && expected === seen && rtmr3 && verifiedAt;
    return {
      expected_image_measurement: expected,
      image_measurement: seen,
      rtmr3_digest: rtmr3,
      attestation_verified_at: verifiedAt,
      verified: verdict.verified ?? (inferredVerified ? true : undefined),
      failure_reason: verdict.failure_reason || null,
      hasAny: !!(expected || seen || rtmr3 || verifiedAt),
    };
  }

  function measurementChip(measurement) {
    const expected = measurement?.expected_image_measurement;
    const seen = measurement?.image_measurement;
    const verifiedAt = measurement?.attestation_verified_at;
    const mismatch = expected && seen && expected !== seen;
    if (measurement?.failure_reason || mismatch) {
      return `<span class="chip chip-warn">${UI.icon("alert", "h-3 w-3")} Attestation drift</span>`;
    }
    if (measurement?.verified === true || (measurement?.verified !== false && expected && seen && verifiedAt)) {
      return `<span class="chip chip-ok">${UI.icon("check", "h-3 w-3")} Verified${verifiedAt ? " " + UI.escapeHtml(UI.relTime(verifiedAt)) : ""}</span>`;
    }
    if (expected && seen) {
      return `<span class="chip chip-ok">${UI.icon("check", "h-3 w-3")} Matches expected</span>`;
    }
    if (seen) {
      return `<span class="chip chip-ok">${UI.icon("check", "h-3 w-3")} Image seen</span>`;
    }
    if (expected) {
      return '<span class="chip chip-warn">Awaiting attestation</span>';
    }
    return '<span class="chip chip-warn">Not measured</span>';
  }

  function measurementTile(label, content, hint) {
    return `
      <div class="rounded-input border border-line bg-bg/40 p-3">
        <div class="flex items-center gap-1.5 text-2xs uppercase tracking-wider text-mute mb-1">
          ${UI.escapeHtml(label)}${hint ? " " + UI.helpHint(hint) : ""}
        </div>
        <div class="font-mono text-2xs text-ink-dim break-all">${content}</div>
      </div>`;
  }

  function measurementGrid(measurement) {
    const verifiedAt = measurement?.attestation_verified_at;
    const verifiedAtHtml = verifiedAt
      ? `<span title="${UI.escapeHtml(UI.fmtTsFull(verifiedAt))}">${UI.escapeHtml(UI.fmtTsFull(verifiedAt))}</span>`
      : '<span class="text-mute">—</span>';
    return `
      <div class="relative mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        ${measurementTile("Expected image", UI.digestCopy(measurement?.expected_image_measurement), "Console's expected guest image measurement.")}
        ${measurementTile("Image seen", UI.digestCopy(measurement?.image_measurement), "Guest image measurement reported by attestation; this is not the app container digest.")}
        ${measurementTile("RTMR3 digest", UI.digestCopy(measurement?.rtmr3_digest), "Runtime configuration binding digest reported by attestation.")}
        ${measurementTile("Attested", verifiedAtHtml)}
      </div>
      ${measurement?.failure_reason ? `<p class="relative mt-2 text-xs text-warn">${UI.escapeHtml(measurement.failure_reason)}</p>` : ""}`;
  }

  async function renderSecurity() {
    const panel = A.el("panel-security");
    const sc = await A.fetchSecurityCvm();
    A.entityScCache = sc;
    const canConfig = A.isHomeEntity() && A.has(A.P.SC_CONFIG);

    if (!sc) {
      panel.innerHTML =
        UI.pageHeader("Security CVM", "The egress gateway your Dev CVMs route through. It enforces your egress policy, injects secrets at the boundary, and produces tamper-evident traffic logs.", { icon: "shield" }) +
        UI.emptyV2({
          icon: "shield",
          title: "No Security CVM provisioned",
          body: "Without a Security CVM, Dev CVMs cannot reach the network. Provision one to enable egress and start governing traffic for this entity.",
          ctaLabel: canConfig ? "Provision Security CVM" : null,
          ctaId: "sc-provision-cta",
        });
      panel.querySelector("#sc-provision-cta")?.addEventListener("click", () => provisionSc());
      return;
    }

    let attestation = null;
    const canProbe = A.isHomeEntity() && (A.has(A.P.USER_MANAGE) || A.isPlatform());
    if (canProbe) {
      const att = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm/attestation");
      if (att.ok) attestation = await att.json();
    }

    const stateLower = String(sc.state || "").toLowerCase();
    const isLive = stateLower === "running";
    const measurement = measurementFromSecurityCvm(sc, attestation);

    panel.innerHTML =
      UI.pageHeader("Security CVM", "The egress gateway your Dev CVMs route through. It enforces your egress policy, injects secrets at the boundary, and produces tamper-evident traffic logs.", { icon: "shield" }) +

      // Hero attestation card
      `<section class="card card-pad mb-4 relative overflow-hidden">
        <div class="absolute inset-0 pointer-events-none" style="background: radial-gradient(600px 220px at 0% 0%, rgba(70,195,123,0.06), transparent 60%);"></div>
        <div class="relative flex flex-wrap items-start justify-between gap-4">
          <div class="flex items-start gap-4 min-w-0">
            <span class="flex h-14 w-14 items-center justify-center rounded-full ${isLive ? "bg-ok/10 text-ok" : "bg-warn/10 text-warn"} shrink-0">
              ${UI.icon("shield", "h-7 w-7")}
            </span>
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-2xs uppercase tracking-wider text-mute">Attestation</span>
                ${measurementChip(measurement)}
              </div>
              <h3 class="mt-1 text-2xl font-semibold text-ink tracking-tight">${isLive ? "Live and enforcing policy" : `Security CVM is ${UI.escapeHtml(sc.state)}`}</h3>
              <p class="mt-1.5 text-sm text-mute max-w-2xl">
                Every outbound request from your Dev CVMs is routed through this gateway. Policy is fetched from Console, attestation is verified continuously, and secrets stay outside the developer sandbox.
              </p>
              <div class="mt-3 flex flex-wrap items-center gap-3 text-xs">
                <span class="inline-flex items-center gap-1.5 text-mute">${UI.icon("entity", "h-3.5 w-3.5")} ${UI.escapeHtml(sc.entity_name || A.ctx?.entityName || "—")}</span>
                ${sc.fqdn ? `<span class="inline-flex items-center gap-1.5">${UI.icon("external", "h-3.5 w-3.5 text-mute")} ${UI.copyButton(sc.fqdn)}</span>` : ""}
                ${sc.region ? `<span class="inline-flex items-center gap-1.5 text-mute">${UI.icon("system", "h-3.5 w-3.5")} ${UI.escapeHtml(sc.region)}</span>` : ""}
              </div>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            ${canProbe && canConfig ? `<button type="button" class="btn btn-sm" id="sc-refresh-attest">${UI.icon("refresh", "h-3.5 w-3.5")} Re-attest</button>` : ""}
            ${A.has(A.P.TRAFFIC) ? `<button type="button" class="btn btn-sm" id="sc-view-egress">${UI.icon("traffic", "h-3.5 w-3.5")} View egress</button>` : ""}
          </div>
        </div>

        ${measurementGrid(measurement)}
      </section>` +

      // Lifecycle card
      (canConfig ? `
        <section class="card card-pad mb-4">
          <header class="flex items-center gap-2 mb-2">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("system", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink">Lifecycle</h4>
          </header>
          <p class="text-xs text-mute mb-3">Update the Security CVM image to roll out a new measured release. Dev CVM forwarders pull the current aTLS policy and CA automatically; a CA rotation may cause brief egress errors while runtime polling converges.</p>
          <div class="flex flex-wrap items-center gap-2">
            <button type="button" class="btn" id="sc-update">${UI.icon("refresh", "h-4 w-4")} Update image</button>
            <button type="button" class="btn btn-danger" id="sc-decommission">${UI.icon("x", "h-4 w-4")} Decommission…</button>
          </div>
        </section>` : "") +

      // Recent egress preview
      (A.has(A.P.TRAFFIC) ? `
        <section class="card card-pad">
          <header class="flex items-center justify-between mb-2">
            <div class="flex items-center gap-2">
              <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("traffic", "h-3.5 w-3.5")}</span>
              <h4 class="text-sm font-semibold text-ink">Recent egress</h4>
            </div>
            <button type="button" class="btn btn-sm btn-ghost" id="sc-view-egress-2">View all ${UI.icon("chevron-right", "h-3.5 w-3.5")}</button>
          </header>
          <div id="sc-egress-snapshot" class="text-sm text-mute">Loading…</div>
        </section>` : "");

    bindHandlers(panel, sc);
    if (A.has(A.P.TRAFFIC)) loadEgressSnapshot(panel, sc);
  }

  function bindHandlers(panel, sc) {
    panel.querySelector("#sc-view-egress")?.addEventListener("click", () => A.Drawer.openSc(sc, "egress"));
    panel.querySelector("#sc-view-egress-2")?.addEventListener("click", () => A.Drawer.openSc(sc, "egress"));
    panel.querySelector("#sc-refresh-attest")?.addEventListener("click", refreshAttestation);
    panel.querySelector("#sc-update")?.addEventListener("click", updateSc);
    panel.querySelector("#sc-decommission")?.addEventListener("click", decommissionSc);
  }

  async function loadEgressSnapshot(panel, sc) {
    const target = panel.querySelector("#sc-egress-snapshot");
    if (!target) return;
    const fromIso = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const params = new URLSearchParams({ security_cvm_id: sc.id, from: fromIso, limit: "10" });
    const path = A.isPlatform()
      ? A.adminQuery("traffic-logs", Object.fromEntries(params))
      : "/api/v1/traffic-logs?" + params.toString();
    const res = await A.api(path);
    if (!res.ok) { target.innerHTML = `<p class="text-sm text-err">${UI.escapeHtml(await A.parseError(res))}</p>`; return; }
    const body = await res.json();
    const items = body.items || [];
    if (!items.length) {
      target.innerHTML = `<p class="text-xs text-mute italic">No egress in the last hour.</p>`;
      return;
    }
    const rows = items.slice(0, 10).map((t) => `
      <tr>
        <td class="text-mute">${UI.fmtTs(t.timestamp)}</td>
        <td class="font-mono">${UI.escapeHtml(t.destination_host || "—")}</td>
        <td>${UI.escapeHtml(t.method || "—")}</td>
        <td><span class="${UI.codeClass(t.response_code)}">${t.response_code ?? "—"}</span></td>
      </tr>`).join("");
    target.innerHTML = `
      <div class="overflow-auto rounded-input border border-line">
        <table class="data-table">
          <thead><tr><th>Time</th><th>Host</th><th>Method</th><th>Status</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  async function refreshAttestation() {
    const res = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm/attestation?probe=true");
    if (res.ok) {
      UI.toast("Attestation refreshed", "ok");
      renderSecurity();
    } else UI.toast(await A.parseError(res), "err");
  }

  async function provisionSc() {
    UI.dialog({
      title: "Provision Security CVM",
      subtitle: "Launches the egress gateway for this entity. Dev CVMs cannot reach the network until this completes.",
      primary: { label: "Start provisioning", run: doProvision },
      body: `<p class="text-sm text-mute">This may take several minutes. The operation will continue in the background; you can leave this screen and return.</p>`,
    });
  }

  async function doProvision() {
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify({}),
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return false; }
    const op = await response.json();
    A.Ops.track(op);
    UI.toast("Provisioning started", "ok");
    queueMicrotask(async () => {
      try {
        await A.Ops.poll(op.id);
        A.entityScCache = null;
        renderSecurity();
      } catch (e) { UI.toast(e.message, "err"); }
    });
  }

  async function updateSc() {
    UI.dialog({
      title: "Update Security CVM image",
      subtitle: "Restarts the gateway on the latest measured image. Egress is briefly unavailable while it re-attests.",
      primary: { label: "Start update", run: doUpdate },
      body: `
        <p class="text-sm text-mute mb-2">Dev CVMs may see brief egress errors during the rollover while forwarders fetch the current aTLS policy and CA from Console.</p>
        <p class="text-sm text-mute">CA rotation recovers automatically. Processes that cache CA files at startup may need a restart after propagation.</p>
      `,
    });
  }

  async function doUpdate() {
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm/actions/update", {
      method: "POST",
      headers: { "Idempotency-Key": A.newIdempotencyKey() },
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return false; }
    const op = await response.json();
    A.Ops.track(op);
    UI.toast("Update started", "ok");
    queueMicrotask(async () => {
      try {
        const finalOp = await A.Ops.poll(op.id);
        if (finalOp.status !== "succeeded") {
          throw new Error(finalOp.error?.message || finalOp.error?.code || "Security CVM update failed");
        }
        A.entityScCache = null;
        showUpdateResult(finalOp);
        renderSecurity();
      } catch (e) { UI.toast(e.message, "err"); }
    });
  }

  function showUpdateResult(op) {
    const ids = op?.result?.dev_cvms_requiring_update || [];
    if (!ids.length) {
      const caChanged = op?.result?.ca_changed === true;
      UI.toast(
        caChanged
          ? "Security CVM updated; Dev CVM policy and CA refresh will converge automatically."
          : "Security CVM updated; Dev CVM policy refresh will converge automatically.",
        "ok"
      );
      return;
    }
    UI.dialog({
      title: "Dev CVM update required",
      subtitle: "Launch-bound Security CVM material changed during this operation.",
      primary: { label: "Open CVMs", run: () => { location.hash = "cvms"; } },
      secondary: { label: "Close" },
      body: `
        <p class="text-sm text-mute">Update only the listed Dev CVMs to refresh their launch-bound Security CVM identity, bearer, or RTMR material. CA-only rotation does not populate this list.</p>
        ${devCvmUpdateList(ids)}
      `,
    });
  }

  async function decommissionSc() {
    const ok = await UI.strongConfirm({
      title: "Decommission Security CVM",
      body: "Destroys the egress gateway. All Dev CVM traffic will fail until you re-provision. Type DECOMMISSION to confirm.",
      confirmWord: "DECOMMISSION",
      primary: "Decommission",
      danger: true,
    });
    if (!ok) return;
    const response = await A.api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm", {
      method: "DELETE",
      headers: { "Idempotency-Key": A.newIdempotencyKey() },
    });
    if (!response.ok) { UI.toast(await A.parseError(response), "err"); return; }
    const op = await response.json();
    A.Ops.track(op);
    UI.toast("Decommission started", "ok");
    try {
      await A.Ops.poll(op.id);
      A.entityScCache = null;
      renderSecurity();
    } catch (e) { UI.toast(e.message, "err"); }
  }

  A.Views = A.Views || {};
  A.Views.renderSecurity = renderSecurity;
})(window.Admin);
