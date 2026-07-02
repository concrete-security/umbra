(function (A) {
  const TAB_DEFS = [
    { id: "overview", label: "Overview", icon: "overview", group: "Home", show: () => true },

    { id: "cvms", label: "CVMs", icon: "cvm", group: "Resources", show: () => true },
    {
      id: "profiles",
      label: "Profiles",
      icon: "profile",
      group: "Resources",
      show: () => A.has(A.P.USER_MANAGE) || (A.ctx?.me?.profiles || []).length > 0,
    },
    {
      id: "users",
      label: "Users",
      icon: "users",
      group: "Resources",
      show: () => A.has(A.P.USER_MANAGE) || A.has(A.P.PERM_MANAGE),
    },
    {
      id: "security",
      label: "Security CVM",
      icon: "shield",
      group: "Resources",
      show: () =>
        A.has(A.P.SC_CONFIG) ||
        A.has(A.P.TRAFFIC) ||
        A.has(A.P.USER_MANAGE) ||
        A.isPlatform(),
    },

    { id: "traffic", label: "Traffic", icon: "traffic", group: "Observability", show: () => A.has(A.P.TRAFFIC) },
    { id: "audit", label: "Audit", icon: "audit", group: "Observability", show: () => A.has(A.P.AUDIT) },

    { id: "entities", label: "Entities", icon: "entity", group: "Platform", show: () => A.isPlatform() },
    { id: "operations", label: "Operations", icon: "operations", group: "Platform", show: () => A.isPlatform() },
    { id: "system", label: "System", icon: "system", group: "Platform", show: () => A.isPlatform() },
    { id: "logs", label: "Logs", icon: "terminal", group: "Platform", show: () => A.isPlatform() },
  ];

  function buildTabs() {
    const nav = A.el("tab-nav");
    nav.innerHTML = "";
    const visible = TAB_DEFS.filter((t) => t.show());
    if (!visible.some((t) => t.id === A.activeTab)) A.activeTab = visible[0]?.id || "overview";
    let lastGroup = "";
    visible.forEach(({ id, label, group, icon }) => {
      if (group && group !== lastGroup) {
        const g = document.createElement("div");
        g.className = "nav-group-label hidden md:block";
        g.textContent = group;
        nav.appendChild(g);
        lastGroup = group;
      }
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "nav-item";
      btn.dataset.tab = id;
      btn.innerHTML = `<svg aria-hidden="true"><use href="/admin/assets/icons.svg#i-${icon || "info"}"/></svg><span>${A.UI.escapeHtml(label)}</span>`;
      if (id === A.activeTab) btn.classList.add("active");
      btn.addEventListener("click", () => selectTab(id));
      nav.appendChild(btn);
    });
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    const panel = A.el("panel-" + A.activeTab);
    if (panel) panel.classList.add("active");
    if (A.activeTab === "logs") A.Views.connectLogStream();
    else A.Views.disconnectLogStream();
    refreshActivePanel();
  }

  function selectTab(id) {
    A.activeTab = id;
    document.querySelectorAll("#tab-nav button").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === id);
    });
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    const panel = A.el("panel-" + id);
    if (panel) panel.classList.add("active");
    if (id === "logs") A.Views.connectLogStream();
    else A.Views.disconnectLogStream();
    refreshActivePanel();
  }

  function hasOpenExpansion() {
    // Something the user actively drilled into: a visible egress detail or an
    // open <details>. The periodic poll's wholesale re-render would collapse it.
    const containers = [A.el("panel-" + A.activeTab)];
    ["cvm-drawer", "sc-drawer"].forEach((id) => {
      const d = A.el(id);
      if (d && !d.classList.contains("hidden")) containers.push(d);
    });
    return containers.some((c) => {
      if (!c) return false;
      if (c.querySelector("details[open]")) return true;
      const eg = c.querySelector("#egress-detail");
      return !!eg && !eg.classList.contains("hidden");
    });
  }

  function captureNestedScroll(container) {
    const positions = {};
    container?.querySelectorAll("[data-scroll-key]").forEach((el) => {
      positions[el.dataset.scrollKey] = { top: el.scrollTop, left: el.scrollLeft };
    });
    return positions;
  }

  function restoreNestedScroll(container, positions) {
    if (!positions) return;
    container?.querySelectorAll("[data-scroll-key]").forEach((el) => {
      const pos = positions[el.dataset.scrollKey];
      if (!pos) return;
      el.scrollTop = pos.top;
      el.scrollLeft = pos.left;
    });
  }

  async function refreshActivePanel(opts = {}) {
    if (A.refreshInFlight || Date.now() < A.pollBackoffUntil) return;
    if (opts.poll && hasOpenExpansion()) {
      // Passive refresh while the user has something expanded — skip the
      // re-render so it doesn't collapse. The next poll resumes once they close it.
      A.setConn("live", "live");
      return;
    }
    // Passive polls re-render the active panel wholesale; preserve the scroll
    // position so a background refresh never yanks the page back to the top.
    const scrollEl = document.querySelector("main[data-active-panel]");
    const savedScroll = opts.poll && scrollEl ? scrollEl.scrollTop : null;
    const activePanel = A.el("panel-" + A.activeTab);
    const nestedScroll = opts.poll ? captureNestedScroll(activePanel) : null;
    A.refreshInFlight = true;
    try {
      A.pollSnapshot = {};
      if (A.has(A.P.TRAFFIC)) {
        A.pollSnapshot.recentTraffic = await A.fetchTrafficLogs({ limit: "15" });
      }
      await A.Ops.refreshPending();
      const V = A.Views;
      if (A.activeTab === "overview" && V.renderOverview) await V.renderOverview();
      else if (A.activeTab === "cvms" && V.renderCvms) await V.renderCvms();
      else if (A.activeTab === "profiles" && V.renderProfiles) await V.renderProfiles();
      else if (A.activeTab === "users" && V.renderUsers) await V.renderUsers();
      else if (A.activeTab === "security" && V.renderSecurity) await V.renderSecurity();
      else if (A.activeTab === "traffic" && V.renderTraffic) await V.renderTraffic();
      else if (A.activeTab === "audit" && V.renderAudit) await V.renderAudit();
      else if (A.activeTab === "operations" && V.renderOperations) await V.renderOperations();
      else if (A.activeTab === "entities" && V.renderEntities) await V.renderEntities();
      else if (A.activeTab === "system" && V.renderSystem) await V.renderSystem();
      else if (A.activeTab === "platform" && V.renderPlatform) await V.renderPlatform();
      if (
        A.drawerKind === "cvm" &&
        A.selectedCvm &&
        !A.el("cvm-drawer").classList.contains("hidden") &&
        A.drawerTab === "egress"
      ) {
        await A.Drawer.renderCvmBody();
      } else if (
        A.drawerKind === "sc" &&
        A.selectedSc &&
        !A.el("sc-drawer").classList.contains("hidden") &&
        A.drawerTab === "egress"
      ) {
        await A.Drawer.renderScBody();
      }
      if (Date.now() >= A.pollBackoffUntil) A.setConn("live", "live");
    } catch (_) {
      A.setConn("err", "error");
    } finally {
      A.refreshInFlight = false;
      if (savedScroll != null && scrollEl) scrollEl.scrollTop = savedScroll;
      restoreNestedScroll(activePanel, nestedScroll);
    }
  }

  async function bootApp() {
    try {
      await A.loadMe();
      await A.loadEntityPicker();
    } catch (err) {
      A.saveSession(null);
      const status = A.el("login-status");
      if (status) status.textContent = err.message || "Not authorized";
      showLogin();
      return;
    }
    A.el("login-panel").classList.add("hidden");
    A.el("app-shell").classList.remove("hidden");
    buildTabs();
    A.setConn("live", "live");
    startPolling();
    A.Drawer.bind();
    handleHash();
  }

  function handleHash() {
    const hash = location.hash.slice(1);
    if (!hash) return;
    if (hash.startsWith("cvm/")) {
      const id = hash.slice(4);
      // Opening the drawer sets location.hash itself, which fires hashchange and
      // re-enters here. If we're already on this CVM, do nothing so we don't
      // clobber the active tab (e.g. snap a freshly-opened Summary back to Egress).
      if (A.drawerKind === "cvm" && A.selectedCvm?.id === id) return;
      A.Drawer.openCvm(id, "summary");
      return;
    }
    if (hash.startsWith("sc/")) {
      const id = hash.slice(3);
      if (A.drawerKind === "sc" && A.selectedSc?.id === id) return;
      A.Drawer.openSc(id, A.has(A.P.TRAFFIC) ? "egress" : "summary");
      return;
    }
    const tabId = hash.split("/")[0];
    const known = TAB_DEFS.find((t) => t.id === tabId && t.show());
    if (known && A.activeTab !== tabId) {
      selectTab(tabId);
    }
  }

  function showLogin() {
    A.el("login-panel").classList.remove("hidden");
    A.el("app-shell").classList.add("hidden");
    A.setConn("", "signed out");
    stopPolling();
    A.Drawer.closeAll();
  }

  function schedulePoll() {
    if (A.pollTimer) clearTimeout(A.pollTimer);
    if (document.hidden) return;
    const delay = Math.max(A.POLL_MS, Math.max(0, A.pollBackoffUntil - Date.now()));
    A.pollTimer = setTimeout(async () => {
      await refreshActivePanel({ poll: true });
      schedulePoll();
    }, delay);
  }

  function startPolling() {
    stopPolling();
    document.addEventListener("visibilitychange", onVisibilityChange);
    refreshActivePanel();
    schedulePoll();
  }

  function onVisibilityChange() {
    if (document.hidden) {
      if (A.pollTimer) clearTimeout(A.pollTimer);
      A.pollTimer = null;
    } else {
      refreshActivePanel({ poll: true });
      schedulePoll();
    }
  }

  function stopPolling() {
    document.removeEventListener("visibilitychange", onVisibilityChange);
    if (A.pollTimer) clearTimeout(A.pollTimer);
    A.pollTimer = null;
    A.Views.disconnectLogStream && A.Views.disconnectLogStream();
  }

  A.randomUrlSafe = function randomUrlSafe(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  async function pkceChallenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    let binary = "";
    new Uint8Array(digest).forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function adminRedirectUri() {
    return A.apiBase() + "/admin/oauth/callback";
  }

  async function startBrowserLogin() {
    const status = A.el("login-status");
    if (status) status.textContent = "Redirecting to Google…";
    const verifier = A.randomUrlSafe(32);
    const challenge = await pkceChallenge(verifier);
    const state = A.randomUrlSafe(32);
    sessionStorage.setItem(A.PKCE_KEY, JSON.stringify({ verifier, state }));
    const params = new URLSearchParams({
      client_id: A.OAUTH_CLIENT_ID,
      redirect_uri: adminRedirectUri(),
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      scope: "openid email profile",
    });
    window.location.href = A.apiBase() + "/api/v1/auth/authorize?" + params.toString();
  }

  async function completeBrowserLogin() {
    const status = A.el("login-status");
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const stored = sessionStorage.getItem(A.PKCE_KEY);
    sessionStorage.removeItem(A.PKCE_KEY);
    if (!code || !stored) {
      if (status) status.textContent = "Sign-in failed: missing authorization code.";
      return;
    }
    let pkce;
    try {
      pkce = JSON.parse(stored);
    } catch {
      if (status) status.textContent = "Sign-in failed: session expired.";
      return;
    }
    if (state && pkce.state && state !== pkce.state) {
      if (status) status.textContent = "Sign-in failed: state mismatch.";
      return;
    }
    const response = await fetch(A.apiBase() + "/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: pkce.verifier,
        client_id: A.OAUTH_CLIENT_ID,
        redirect_uri: adminRedirectUri(),
      }),
    });
    if (!response.ok) {
      let message = "Token exchange failed.";
      try {
        const err = await response.json();
        message = err.error?.message || err.error || message;
      } catch (_) {}
      if (status) status.textContent = message;
      return;
    }
    const tokens = await response.json();
    A.saveSession({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
    });
    window.location.replace(A.apiBase() + "/admin");
  }

  A.buildTabs = buildTabs;
  A.selectTab = selectTab;
  A.refreshActivePanel = refreshActivePanel;
  A.bootApp = bootApp;
  A.showLogin = showLogin;
  A.startPolling = startPolling;
  A.stopPolling = stopPolling;
  A.disconnectLogStream = () => A.Views.disconnectLogStream && A.Views.disconnectLogStream();

  A.Shortcuts?.register({
    palette: () => {
      // Phase 4: command palette opens here
      A.UI.toast("Command palette (⌘K) — coming soon", "info");
    },
    closeAll: () => {
      A.Drawer.closeAll && A.Drawer.closeAll();
      document.querySelectorAll(".modal-overlay").forEach((m) => m.remove());
    },
  });

  if (window.location.pathname.endsWith("/admin/oauth/callback")) {
    completeBrowserLogin();
  } else {
    A.el("login-btn")?.addEventListener("click", startBrowserLogin);
    A.el("logout-btn")?.addEventListener("click", () => {
      A.saveSession(null);
      sessionStorage.removeItem(A.ENTITY_KEY);
      showLogin();
    });
    A.el("palette-trigger")?.addEventListener("click", () => {
      A.UI.toast("Command palette (⌘K) — coming soon", "info");
    });
    A.el("kbd-help-btn")?.addEventListener("click", () => A.Shortcuts?.toggleHelp());
    window.addEventListener("hashchange", handleHash);
    A.session = A.loadSession();
    if (A.session?.access_token) A.bootApp();
    else showLogin();
  }
})(window.Admin);
