/* Self-serve connect wizard. State machine driven solely by
 * GET /api/v1/connect/{integration}; callback query params are display hints
 * only. Auth mirrors the admin SPA: client-side PKCE against the Console's
 * own /api/v1/auth broker, JWT pair in sessionStorage, bearer on API calls.
 * No cookies exist anywhere in the Console. */
(() => {
  "use strict";

  const SESSION_KEY = "umbra_connect_session";
  const PKCE_KEY = "umbra_connect_pkce";
  const CLIENT_ID = "umbra-cli-v1";
  const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

  const el = (id) => document.getElementById(id);
  const statusLine = (text) => {
    el("status").textContent = text;
  };

  function integrationSlug() {
    const parts = window.location.pathname.split("/").filter(Boolean);
    const slug = parts.length === 2 && parts[0] === "connect" ? parts[1] : "";
    return SLUG_RE.test(slug) && slug !== "oauth" && slug !== "assets" ? slug : null;
  }

  function randomUrlSafe(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function pkceChallenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    let binary = "";
    new Uint8Array(digest).forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function loadSession() {
    try {
      return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    } catch {
      return null;
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  async function startLogin(integration) {
    statusLine("Redirecting to Google…");
    const verifier = randomUrlSafe(32);
    const challenge = await pkceChallenge(verifier);
    const state = randomUrlSafe(32);
    sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state, integration }));
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: window.location.origin + "/connect/oauth/callback",
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      scope: "openid email profile",
    });
    window.location.href = "/api/v1/auth/authorize?" + params.toString();
  }

  async function api(path, options = {}) {
    const session = loadSession();
    if (!session || !session.access_token) {
      return { status: 401, body: null };
    }
    const response = await fetch(path, {
      method: options.method || "GET",
      headers: {
        Authorization: "Bearer " + session.access_token,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (response.status === 401) {
      clearSession();
    }
    return { status: response.status, body };
  }

  function banner(kind, text) {
    const node = el("banner");
    node.className = "banner " + kind;
    node.textContent = text;
    node.classList.remove("hidden");
  }

  function renderPanel(html) {
    el("panel").innerHTML = html;
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c]);
  }

  function stepsHtml(state) {
    const steps = [
      ["Sign in", true],
      ["Profile", Boolean(state.profile)],
      ["Authorize", state.secrets.complete],
      ["Attach", state.cvms.some((cvm) => cvm.attached)],
    ];
    let activeSeen = false;
    return (
      '<ol class="steps">' +
      steps
        .map(([label, done]) => {
          let cls = done ? "done" : "";
          if (!done && !activeSeen) {
            cls = "active";
            activeSeen = true;
          }
          return `<li class="${cls}">${done ? "[OK] " : ""}${label}</li>`;
        })
        .join("") +
      "</ol>"
    );
  }

  async function boot() {
    const integration = integrationSlug();
    if (!integration) {
      statusLine("Unknown connect page.");
      return;
    }
    const hints = new URLSearchParams(window.location.search);
    if (hints.get("connected") === "1") {
      banner("ok", "Authorization completed — refreshing status…");
    } else if (hints.get("connect_error")) {
      banner("error", "The last connect attempt failed (" + escapeHtml(hints.get("connect_error")) + "). You can retry below.");
    }

    if (!loadSession()) {
      statusLine(`Connect ${integration} to your Umbra sandbox.`);
      renderPanel('<div class="card"><h2>Sign in</h2><p class="muted">Use your work Google account.</p><button id="login">Sign in with Google</button></div>');
      el("login").addEventListener("click", () => startLogin(integration));
      return;
    }
    await refresh(integration);
  }

  async function refresh(integration) {
    statusLine(`Connect ${integration}`);
    const { status, body } = await api(`/api/v1/connect/${integration}`);
    if (status === 401) {
      renderPanel('<div class="card"><h2>Session expired</h2><button id="login">Sign in again</button></div>');
      el("login").addEventListener("click", () => startLogin(integration));
      return;
    }
    if (status === 404) {
      renderPanel(`<div class="card"><h2>Not configured</h2><p>This connect link isn't configured for your organization. Ask your admin to set up the <code>${escapeHtml(integration)}</code> integration.</p></div>`);
      return;
    }
    if (status !== 200 || !body) {
      renderPanel('<div class="card"><h2>Something went wrong</h2><p class="muted">Try reloading the page.</p></div>');
      return;
    }
    render(integration, body);
  }

  function render(integration, state) {
    if (!state.entitled) {
      renderPanel(
        `<div class="card"><h2>Ask your admin for access</h2>
         <p>Your account exists but has no CVM launch access yet. Send your admin this request:</p>
         <p><code>Please grant me CVM_LAUNCH so I can self-serve the ${escapeHtml(integration)} integration at ${escapeHtml(window.location.origin)}/connect/${escapeHtml(integration)}</code></p></div>`
      );
      return;
    }
    if (!state.profile) {
      renderPanel(stepsHtml(state) + '<div class="card"><h2>Setting up your profile…</h2><p class="muted">Cloning the integration template.</p></div>');
      provision(integration);
      return;
    }
    if (!state.secrets.complete) {
      const err = state.connection.last_error
        ? `<p class="muted">Last attempt: <code>${escapeHtml(state.connection.last_error)}</code></p>`
        : "";
      renderPanel(
        stepsHtml(state) +
          `<div class="card"><h2>Authorize ${escapeHtml(integration)}</h2>
           <p class="muted">You'll approve access in the provider's own window; the credential lands in your Umbra profile — never on this machine or in the sandbox.</p>
           ${err}<button id="authorize">Connect ${escapeHtml(integration)}</button></div>`
      );
      el("authorize").addEventListener("click", () => authorize(integration));
      return;
    }
    renderAttach(integration, state);
  }

  async function provision(integration) {
    const { status, body } = await api(`/api/v1/connect/${integration}/profile`, { method: "POST" });
    if (status === 200 || status === 201 || (body && body.profile_id)) {
      await refresh(integration);
      return;
    }
    if (body && body.error && body.error.details && body.error.details.state === "template_missing") {
      renderPanel(`<div class="card"><h2>Not ready</h2><p>The ${escapeHtml(integration)} integration has no profile template yet — ask your admin to add one.</p></div>`);
      return;
    }
    renderPanel(`<div class="card"><h2>Could not set up your profile</h2><p class="muted">${escapeHtml((body && body.error && body.error.message) || "unknown error")}</p></div>`);
  }

  async function authorize(integration) {
    statusLine("Creating a one-time authorization link…");
    const { status, body } = await api(`/api/v1/connect/${integration}/connections`, { method: "POST" });
    if (status === 201 && body && body.authorize_url) {
      window.location.href = body.authorize_url;
      return;
    }
    banner("error", (body && body.error && body.error.message) || "Could not start the authorization.");
    await refresh(integration);
  }

  function renderAttach(integration, state) {
    const profileId = state.profile.id;
    let inner;
    if (state.cvms.length === 0) {
      inner = `<p>Credential connected. Launch a sandbox with your profile:</p>
               <p><code>umbra cvm launch --profile ${escapeHtml(profileId)}</code></p>`;
    } else {
      inner =
        "<p>Credential connected. Bind your profile to a sandbox:</p>" +
        state.cvms
          .map(
            (cvm) => `
        <div class="cvm-row">
          <span><code>${escapeHtml(cvm.fqdn)}</code> <span class="muted">(${escapeHtml(cvm.state)})</span></span>
          ${cvm.attached ? '<span class="badge on">attached</span>' : `<button class="secondary attach" data-cvm="${escapeHtml(cvm.id)}">Attach</button>`}
        </div>`
          )
          .join("");
    }
    renderPanel(stepsHtml(state) + `<div class="card"><h2>All set</h2>${inner}</div>`);
    document.querySelectorAll("button.attach").forEach((buttonNode) => {
      buttonNode.addEventListener("click", async () => {
        buttonNode.disabled = true;
        const { status, body } = await api(`/api/v1/connect/${integration}/attach`, {
          method: "POST",
          body: { cvm_id: buttonNode.dataset.cvm },
        });
        if (status === 200) {
          banner("ok", "Profile attached — the sandbox picks it up within seconds.");
        } else {
          banner("error", (body && body.error && body.error.message) || "Attach failed.");
        }
        await refresh(integration);
      });
    });
  }

  boot();
})();
