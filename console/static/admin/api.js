(function (A) {
  function apiBase() {
    return window.location.origin;
  }

  function loadSession() {
    try {
      const raw = sessionStorage.getItem(A.STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function saveSession(value) {
    A.session = value;
    if (value) sessionStorage.setItem(A.STORAGE_KEY, JSON.stringify(value));
    else sessionStorage.removeItem(A.STORAGE_KEY);
  }

  function setConn(state, text) {
    const pill = A.el("conn-pill");
    if (!pill) return;
    const cls = state === "live" ? "pill pill-live" : state === "err" ? "pill pill-err" : "pill";
    pill.className = cls + " text-2xs inline-flex items-center gap-1.5 px-2.5 py-0.5";
    let dotCls = "dot";
    if (state === "live") dotCls = "dot dot-ok dot-pulse";
    else if (state === "err") dotCls = "dot dot-err";
    const dot = pill.querySelector(".dot");
    if (dot) dot.className = dotCls;
    else pill.insertAdjacentHTML("afterbegin", `<span class="${dotCls}"></span>`);
    const textEl = pill.querySelector("[data-conn-text]");
    if (textEl) textEl.textContent = text;
    else pill.appendChild(document.createTextNode(text));
  }

  function applyRateLimitBackoff(response) {
    if (response.status !== 429) return;
    let seconds = 15;
    try {
      const retryHeader = response.headers.get("Retry-After");
      if (retryHeader) seconds = Math.max(1, parseInt(retryHeader, 10) || seconds);
    } catch (_) {}
    A.pollBackoffUntil = Date.now() + seconds * 1000;
    A.setConn("err", "rate limited");
    A.UI.toast("Rate limit exceeded — pausing refresh for " + seconds + "s", "err");
  }

  async function api(path, options = {}) {
    if (Date.now() < A.pollBackoffUntil) {
      return new Response(JSON.stringify({ error: { code: "RATE_LIMITED" } }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (A.session?.access_token) headers.Authorization = "Bearer " + A.session.access_token;
    const response = await fetch(apiBase() + path, { ...options, headers });
    if (response.status === 429) applyRateLimitBackoff(response);
    if (response.status === 401 && A.session?.refresh_token) {
      const refreshed = await refreshTokens();
      if (refreshed) return api(path, options);
    }
    return response;
  }

  async function refreshTokens() {
    const response = await fetch(apiBase() + "/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refresh_token: A.session.refresh_token }),
    });
    if (!response.ok) return false;
    const body = await response.json();
    saveSession({
      access_token: body.access_token,
      refresh_token: body.refresh_token,
      expires_at: body.expires_at,
    });
    return true;
  }

  function newIdempotencyKey() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return A.randomUrlSafe(16);
  }

  async function loadMe() {
    const response = await api("/api/v1/me");
    if (!response.ok) throw new Error("session invalid");
    const me = await response.json();
    if (me.entity) {
      me.entity_id = me.entity.id;
      me.entity_name = me.entity.name;
    }
    const perms = me.permissions || [];
    if (!A.DASHBOARD_PERMS.some((p) => perms.includes(p))) {
      throw new Error("No console permissions on this account");
    }
    let viewEntityId = me.entity_id;
    const stored = sessionStorage.getItem(A.ENTITY_KEY);
    if (perms.includes(A.P.PLATFORM) && stored) viewEntityId = stored;
    A.ctx = {
      me,
      perms,
      viewEntityId,
      entityName: me.entity_name || me.entity_id,
    };
    const userPill = A.el("user-pill");
    const userText = userPill?.querySelector("[data-user-text]");
    if (userText) userText.textContent = me.email;
    else if (userPill) userPill.textContent = me.email;
    userPill?.classList.remove("hidden");
    A.el("logout-btn")?.classList.remove("hidden");
    updateScopePill();
    return me;
  }

  function updateScopePill() {
    const pill = A.el("scope-pill");
    if (!pill || !A.ctx) return;
    let label;
    if (A.isPlatform() && A.ctx.viewEntityId !== A.ctx.me.entity_id) {
      const ent = A.entitiesCache.find((e) => e.id === A.ctx.viewEntityId);
      label = ent ? ent.name : "Entity";
    } else {
      label = A.ctx.me.entity_name || "My entity";
    }
    pill.textContent = label;
    pill.className = "pill chip-accent text-2xs ml-1 inline-flex items-center gap-1 px-2.5 py-0.5";
    pill.classList.remove("hidden");
  }

  async function loadEntityPicker() {
    const wrap = A.el("entity-wrap");
    const select = A.el("entity-select");
    if (!A.isPlatform()) {
      wrap.classList.add("hidden");
      return;
    }
    const response = await api("/api/v1/entities?limit=200");
    if (!response.ok) {
      wrap.classList.add("hidden");
      return;
    }
    const body = await response.json();
    A.entitiesCache = body.items || [];
    select.innerHTML = A.entitiesCache
      .map(
        (e) =>
          '<option value="' +
          e.id +
          '"' +
          (e.id === A.ctx.viewEntityId ? " selected" : "") +
          ">" +
          A.UI.escapeHtml(e.name) +
          "</option>"
      )
      .join("");
    wrap.classList.remove("hidden");
    select.onchange = () => {
      A.ctx.viewEntityId = select.value;
      sessionStorage.setItem(A.ENTITY_KEY, A.ctx.viewEntityId);
      const ent = A.entitiesCache.find((e) => e.id === A.ctx.viewEntityId);
      if (ent) A.ctx.entityName = ent.name;
      A.entityScCache = null;
      updateScopePill();
      A.selectedProfileId = null;
      A.Drawer.closeAll();
      A.refreshActivePanel();
    };
    updateScopePill();
  }

  function adminQuery(path, params) {
    const q = new URLSearchParams(params || {});
    const eid = A.viewEntityId();
    if (eid && !q.has("entity_id")) q.set("entity_id", eid);
    const qs = q.toString();
    return "/api/v1/admin/" + path + (qs ? "?" + qs : "");
  }

  function trafficFromIso(windowKey) {
    if (!windowKey || windowKey === "all") return null;
    const mins = { "15m": 15, "1h": 60, "24h": 1440 }[windowKey];
    if (!mins) return null;
    return new Date(Date.now() - mins * 60 * 1000).toISOString();
  }

  async function fetchCvms() {
    if (A.isPlatform()) {
      const params = { limit: "200" };
      if (A.ctx.viewEntityId !== A.ctx.me.entity_id) params.entity_id = A.viewEntityId();
      const response = await api(adminQuery("cvms", params));
      if (response.ok) return (await response.json()).items || [];
    }
    const response = await api("/api/v1/cvms");
    if (!response.ok) return [];
    return (await response.json()).items || [];
  }

  async function fetchCvmDetail(cvmId) {
    if (A.isPlatform() && !A.isHomeEntity()) {
      const items = await fetchCvms();
      return items.find((c) => c.id === cvmId) || null;
    }
    const response = await api("/api/v1/cvms/" + cvmId);
    if (!response.ok) return null;
    const cvm = await response.json();
    const etag = response.headers.get("ETag");
    if (etag) cvm._etag = etag;
    return cvm;
  }

  async function fetchEntitySummary() {
    if (!A.isPlatform()) return null;
    const response = await api("/api/v1/admin/entities/" + A.viewEntityId() + "/summary");
    if (!response.ok) return null;
    return response.json();
  }

  async function fetchSecurityCvm() {
    if (A.isPlatform() && !A.isHomeEntity()) {
      const response = await api(adminQuery("security-cvms", { limit: "5" }));
      if (!response.ok) return null;
      const items = (await response.json()).items || [];
      return items.find((s) => s.entity_id === A.viewEntityId()) || items[0] || null;
    }
    if (!A.has(A.P.SC_CONFIG)) {
      const summary = await fetchEntitySummary();
      if (summary?.security_cvm) return summary.security_cvm;
      return null;
    }
    const response = await api("/api/v1/entities/" + A.viewEntityId() + "/security-cvm");
    if (!response.ok) return null;
    return response.json();
  }

  async function fetchEntitySc() {
    if (A.entityScCache) return A.entityScCache;
    A.entityScCache = await fetchSecurityCvm();
    return A.entityScCache;
  }

  async function fetchTrafficLogs(params) {
    const q = new URLSearchParams(params || {});
    const path = A.isPlatform()
      ? adminQuery("traffic-logs", Object.fromEntries(q))
      : "/api/v1/traffic-logs?" + q.toString();
    const response = await api(path);
    if (!response.ok) return { items: [], next_cursor: null };
    return response.json();
  }

  async function parseError(response) {
    try {
      const err = await response.json();
      return err.error?.message || err.error?.code || "Request failed";
    } catch {
      return "Request failed";
    }
  }

  A.apiBase = apiBase;
  A.loadSession = loadSession;
  A.saveSession = saveSession;
  A.setConn = setConn;
  A.api = api;
  A.newIdempotencyKey = newIdempotencyKey;
  A.loadMe = loadMe;
  A.updateScopePill = updateScopePill;
  A.loadEntityPicker = loadEntityPicker;
  A.adminQuery = adminQuery;
  A.trafficFromIso = trafficFromIso;
  A.fetchCvms = fetchCvms;
  A.fetchCvmDetail = fetchCvmDetail;
  A.fetchEntitySummary = fetchEntitySummary;
  A.fetchSecurityCvm = fetchSecurityCvm;
  A.fetchEntitySc = fetchEntitySc;
  A.fetchTrafficLogs = fetchTrafficLogs;
  A.parseError = parseError;
})(window.Admin);
