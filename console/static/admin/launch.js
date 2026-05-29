(function (A) {
  const UI = A.UI;

  async function openLaunchModal() {
    if (!A.isHomeEntity() || !A.has(A.P.CVM_LAUNCH)) {
      UI.toast("Launching requires CVM_LAUNCH on your home entity", "err");
      return;
    }

    UI.dialog({
      title: "Launch a Confidential VM",
      subtitle: "A CVM is a sandboxed environment that runs your AI agents. It boots on attested hardware, attaches the profiles you select, and routes all egress through your Security CVM.",
      wide: true,
      primary: { label: "Launch CVM", run: submit },
      onBind: (overlay) => populate(overlay).catch((err) => UI.toast(err.message || "Failed to load options", "err")),
      body: `<div data-launch-body><div class="text-mute text-sm">Loading options…</div></div>`,
    });
  }

  async function populate(overlay) {
    const body = overlay.querySelector("[data-launch-body]");
    const [profRes, keysRes] = await Promise.all([
      A.api("/api/v1/entities/" + A.viewEntityId() + "/profiles"),
      A.api("/api/v1/me/keys"),
    ]);
    const profiles = profRes.ok ? (await profRes.json()).items || [] : [];
    const keys = keysRes.ok ? (await keysRes.json()).items || [] : [];
    const myProfiles = profiles.filter((p) => p.assigned !== false);
    const usable = myProfiles.length ? myProfiles : profiles;

    if (!keys.length) {
      body.innerHTML = UI.emptyV2({
        icon: "key",
        title: "No SSH keys registered",
        body: "Add an SSH key from the CLI (concrete key add) so you can connect to this CVM once it boots.",
      });
      const okBtn = overlay.querySelector("[data-dlg-ok]");
      if (okBtn) okBtn.disabled = true;
      return;
    }

    body.innerHTML = `
      <div class="space-y-5">
        <section>
          <header class="mb-2 flex items-center gap-2">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("profile", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink">Profiles</h4>
            ${UI.helpHint("Profiles bundle the egress policy, secret bindings, and DLP rules that govern what this CVM can do.")}
          </header>
          <p class="text-xs text-mute mb-2">Pick one or more. Console merges the selected profiles into the effective policy the Security CVM pulls.</p>
          ${usable.length ? `
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2" data-profiles>
              ${usable.map((p) => `
                <label class="flex items-start gap-2 rounded-input border border-line-soft p-2.5 hover:border-accent-dim cursor-pointer transition-colors">
                  <input type="checkbox" data-profile-id="${UI.escapeHtml(p.id)}" class="mt-0.5 accent-accent">
                  <span class="min-w-0">
                    <span class="block text-sm font-medium text-ink truncate">${UI.escapeHtml(p.name)}</span>
                    ${p.description ? `<span class="block text-2xs text-mute mt-0.5 line-clamp-2">${UI.escapeHtml(p.description)}</span>` : ""}
                  </span>
                </label>
              `).join("")}
            </div>
          ` : `<p class="text-sm text-warn">No profiles available on this entity. Create one from the Profiles tab first.</p>`}
        </section>

        <section>
          <header class="mb-2 flex items-center gap-2">
            <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/10 text-accent">${UI.icon("key", "h-3.5 w-3.5")}</span>
            <h4 class="text-sm font-semibold text-ink">SSH keys</h4>
            ${UI.helpHint("Public keys that will be authorized inside the CVM. Use 'concrete ssh' or any standard SSH client to connect.")}
          </header>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2" data-keys>
            ${keys.map((k) => `
              <label class="flex items-start gap-2 rounded-input border border-line-soft p-2.5 hover:border-accent-dim cursor-pointer transition-colors">
                <input type="checkbox" data-key-id="${UI.escapeHtml(k.id)}" class="mt-0.5 accent-accent">
                <span class="min-w-0">
                  <span class="block text-sm font-medium text-ink truncate">${UI.escapeHtml(k.label || k.name || "Key")}</span>
                  <span class="block text-2xs text-mute font-mono mt-0.5 truncate">${UI.escapeHtml(k.fingerprint || k.id)}</span>
                </span>
              </label>
            `).join("")}
          </div>
        </section>

        <section class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="field-label">Region</label>
            <input class="input" data-launch-region placeholder="default" autocomplete="off">
            <span class="field-hint">Leave blank to use the entity default.</span>
          </div>
          <div>
            <label class="field-label">Instance type</label>
            <input class="input" data-launch-type placeholder="default" autocomplete="off">
            <span class="field-hint">Optional override. Otherwise the provider picks a sensible default.</span>
          </div>
        </section>

        <div data-launch-msg class="text-sm"></div>
      </div>`;
  }

  async function submit(overlay) {
    const profile_ids = Array.from(overlay.querySelectorAll("[data-profile-id]:checked")).map((c) => c.dataset.profileId);
    const ssh_key_ids = Array.from(overlay.querySelectorAll("[data-key-id]:checked")).map((c) => c.dataset.keyId);
    const msg = overlay.querySelector("[data-launch-msg]");
    if (!profile_ids.length) {
      msg.innerHTML = `<span class="text-err">Select at least one profile.</span>`;
      return false;
    }
    if (!ssh_key_ids.length) {
      msg.innerHTML = `<span class="text-err">Select at least one SSH key.</span>`;
      return false;
    }
    const region = overlay.querySelector("[data-launch-region]")?.value.trim();
    const instance_type = overlay.querySelector("[data-launch-type]")?.value.trim();
    const body = { profile_ids, ssh_key_ids };
    if (region) body.region = region;
    if (instance_type) body.instance_type = instance_type;
    msg.innerHTML = `<span class="text-mute">Launching…</span>`;
    const response = await A.api("/api/v1/cvms", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": A.newIdempotencyKey() },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const text = await A.parseError(response);
      msg.innerHTML = `<span class="text-err">${UI.escapeHtml(text)}</span>`;
      return false;
    }
    const op = await response.json();
    A.Ops.track(op);
    UI.toast("Launch started — operation tracked in the background", "ok");
    queueMicrotask(async () => {
      try {
        const final = await A.Ops.poll(op.id);
        const cvmId = final.target?.id || final.result?.cvm?.id;
        A.entityScCache = null;
        await A.refreshActivePanel();
        if (cvmId) await A.Drawer.openCvm(cvmId, "summary");
      } catch (e) {
        UI.toast(e.message || "Launch failed", "err");
      }
    });
    return true;
  }

  A.openLaunchModal = openLaunchModal;
})(window.Admin);
