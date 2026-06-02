(function (A) {
  const MAX_CVM_NODES = 12;
  const MAX_DEST_NODES = 7;
  const WINDOW_MIN = 15;
  const TRAFFIC_LIMIT = 200;
  const BLOCK_CODE = 403;

  // The admin landing page is a live topology map: Dev CVMs → the entity's
  // Security CVM → the destinations they reach. Allowed traffic streams
  // through the gateway; policy-blocked traffic (403) is stopped at it.
  async function renderOverview() {
    const panel = A.el("panel-overview");
    if (!panel) return;

    const hasTraffic = A.has(A.P.TRAFFIC);
    const [cvms, sc, traffic, profiles] = await Promise.all([
      A.fetchCvms(),
      A.fetchSecurityCvm(),
      hasTraffic ? A.fetchTrafficLogs({ limit: String(TRAFFIC_LIMIT), from: windowFromIso() }) : Promise.resolve({ items: [] }),
      A.fetchProfiles ? A.fetchProfiles() : Promise.resolve([]),
    ]);

    const model = buildModel(cvms || [], sc, (traffic && traffic.items) || [], hasTraffic, profiles || []);
    A.Graph.render(panel, model);
  }

  function windowFromIso() {
    return new Date(Date.now() - WINDOW_MIN * 60 * 1000).toISOString();
  }

  function isBlocked(code) {
    return Number(code) === BLOCK_CODE;
  }

  function shortLabel(cvm) {
    const fqdn = cvm.fqdn || "";
    const head = fqdn ? fqdn.split(".")[0] : "";
    const label = head || String(cvm.id).slice(0, 8);
    return label.length > 16 ? label.slice(0, 15) + "…" : label;
  }

  function destKeyFor(host, topSet) {
    if (!host) return "__other";
    return topSet.has(host) ? host : "__other";
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function policyFor(profile) {
    return profile && profile.policy && typeof profile.policy === "object" ? profile.policy : {};
  }

  function injectionRules(profile) {
    return asArray(policyFor(profile).secret_injections).filter((injection) => injection && typeof injection === "object");
  }

  function hostMatches(pattern, host) {
    if (!pattern) return true;
    if (!host) return false;
    pattern = String(pattern).toLowerCase();
    host = String(host).toLowerCase();
    if (pattern === "*") return true;
    if (pattern === host) return true;
    if (!pattern.startsWith("*.")) return false;
    const suffix = pattern.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }

  function pathMatches(prefixes, path) {
    prefixes = asArray(prefixes);
    if (!prefixes.length || prefixes.includes("/")) return true;
    if (!path) return false;
    path = String(path);
    return prefixes.some((prefix) => path.startsWith(String(prefix)));
  }

  function methodMatches(methods, method) {
    methods = asArray(methods);
    if (!methods.length) return true;
    if (!method) return false;
    const upper = String(method).toUpperCase();
    return methods.some((m) => String(m).toUpperCase() === upper);
  }

  function portMatches(ports, port) {
    ports = asArray(ports);
    if (!ports.length || port == null) return true;
    const n = Number(port);
    return Number.isFinite(n) && ports.some((p) => Number(p) === n);
  }

  function schemeMatches(scheme, protocol) {
    if (!scheme || !protocol) return true;
    return String(scheme).toLowerCase() === String(protocol).toLowerCase();
  }

  function injectionMatchesTraffic(injection, traffic) {
    const match = injection.match && typeof injection.match === "object" ? injection.match : {};
    return (
      schemeMatches(match.scheme, traffic.protocol) &&
      hostMatches(match.host, traffic.destination_host || traffic.destination_ip) &&
      portMatches(match.ports, traffic.port) &&
      methodMatches(match.methods, traffic.method) &&
      pathMatches(match.path_prefixes, traffic.path)
    );
  }

  function secretSummaryFor(liveCvms, profileById, items, hasTrafficPerm) {
    const perCvm = new Map();
    const rulesByCvm = new Map();
    const uniqueRules = new Map();
    const profileIds = new Set();
    const hosts = new Set();

    liveCvms.forEach((cvm) => {
      const rules = [];
      asArray(cvm.profiles).forEach((binding) => {
        const profile = profileById.get(String(binding.id || ""));
        if (!profile) return;
        injectionRules(profile).forEach((injection, index) => {
          const id = injection.id || String(index);
          const key = `${profile.id}:${id}`;
          const match = injection.match && typeof injection.match === "object" ? injection.match : {};
          const rule = { key, profileId: profile.id, profileName: profile.name, injection };
          rules.push(rule);
          uniqueRules.set(key, rule);
          profileIds.add(profile.id);
          if (match.host) hosts.add(String(match.host));
        });
      });
      perCvm.set(cvm.id, rules.length);
      if (rules.length) rulesByCvm.set(cvm.id, rules);
    });

    const activeHosts = new Set();
    const activeCvms = new Set();
    let active = 0;
    if (hasTrafficPerm) {
      items.forEach((traffic) => {
        if (!traffic.cvm_id || isBlocked(traffic.response_code)) return;
        const rules = rulesByCvm.get(traffic.cvm_id);
        if (!rules || !rules.length) return;
        const matched = rules.find((rule) => injectionMatchesTraffic(rule.injection, traffic));
        if (!matched) return;
        active += 1;
        activeCvms.add(traffic.cvm_id);
        if (traffic.destination_host || traffic.destination_ip) activeHosts.add(traffic.destination_host || traffic.destination_ip);
      });
    }

    return {
      configured: uniqueRules.size,
      active,
      cvms: rulesByCvm.size,
      profiles: profileIds.size,
      hosts: hosts.size,
      activeCvms: activeCvms.size,
      activeHosts: activeHosts.size,
      perCvm,
    };
  }

  function buildModel(allCvms, sc, items, hasTrafficPerm, profiles) {
    const DEAD = new Set(["terminated", "decommissioned"]);
    const live = allCvms.filter((c) => !DEAD.has(String(c.state).toLowerCase()));
    const profileById = new Map(asArray(profiles).map((profile) => [String(profile.id), profile]));
    const secrets = secretSummaryFor(live, profileById, items, hasTrafficPerm);

    // Per-CVM traffic tallies.
    const tally = new Map(); // cvm_id → {total, allowed, blocked}
    items.forEach((t) => {
      if (!t.cvm_id) return;
      const e = tally.get(t.cvm_id) || { total: 0, allowed: 0, blocked: 0 };
      e.total += 1;
      if (isBlocked(t.response_code)) e.blocked += 1;
      else e.allowed += 1;
      tally.set(t.cvm_id, e);
    });

    const cvmNodes = live.map((c) => {
      const state = String(c.state).toLowerCase();
      const t = tally.get(c.id) || { total: 0, allowed: 0, blocked: 0 };
      return {
        id: c.id,
        label: shortLabel(c),
        fqdn: c.fqdn,
        state: c.state,
        ok: state === "running",
        error: state === "error" || state === "failed",
        profiles: c.profiles || [],
        total: t.total,
        allowed: t.allowed,
        blocked: t.blocked,
        secrets: secrets.perCvm.get(c.id) || 0,
      };
    });

    // Prioritise what to show when the fleet is large: errors, then busiest,
    // then running, then the rest.
    cvmNodes.sort((a, b) => {
      if (a.error !== b.error) return a.error ? -1 : 1;
      if (b.total !== a.total) return b.total - a.total;
      if (a.ok !== b.ok) return a.ok ? -1 : 1;
      return 0;
    });
    const shownCvms = cvmNodes.slice(0, MAX_CVM_NODES);
    const moreCvms = Math.max(0, cvmNodes.length - shownCvms.length);
    const shownIds = new Set(shownCvms.map((c) => c.id));

    // Destination aggregation.
    const hostAgg = new Map(); // host → {total, allowed, blocked}
    items.forEach((t) => {
      const host = t.destination_host || t.destination_ip || "unknown";
      const e = hostAgg.get(host) || { total: 0, allowed: 0, blocked: 0 };
      e.total += 1;
      if (isBlocked(t.response_code)) e.blocked += 1;
      else e.allowed += 1;
      hostAgg.set(host, e);
    });
    const hostsSorted = [...hostAgg.entries()].sort((a, b) => b[1].total - a[1].total);
    const topHosts = hostsSorted.slice(0, MAX_DEST_NODES);
    const topSet = new Set(topHosts.map(([h]) => h));
    const dests = topHosts.map(([host, v]) => ({ key: host, host, total: v.total, allowed: v.allowed, blocked: v.blocked, isOther: false }));
    const overflow = hostsSorted.slice(MAX_DEST_NODES);
    if (overflow.length) {
      const agg = overflow.reduce((acc, [, v]) => ({ total: acc.total + v.total, allowed: acc.allowed + v.allowed, blocked: acc.blocked + v.blocked }), { total: 0, allowed: 0, blocked: 0 });
      dests.push({ key: "__other", host: "other hosts", total: agg.total, allowed: agg.allowed, blocked: agg.blocked, isOther: true });
    }

    // Per-flow counts: (visible cvm, dest bucket, blocked) → count.
    const flowMap = new Map();
    items.forEach((t) => {
      if (!t.cvm_id || !shownIds.has(t.cvm_id)) return;
      const blocked = isBlocked(t.response_code);
      const destKey = destKeyFor(t.destination_host || t.destination_ip, topSet);
      const k = `${t.cvm_id}|${destKey}|${blocked ? 1 : 0}`;
      flowMap.set(k, (flowMap.get(k) || 0) + 1);
    });
    const flows = [...flowMap.entries()].map(([k, count]) => {
      const [cvmId, destKey, b] = k.split("|");
      return { cvmId, destKey, blocked: b === "1", count };
    });

    // Headline stats (from the full live fleet, not the capped view).
    const running = live.filter((c) => String(c.state).toLowerCase() === "running").length;
    const errored = cvmNodes.filter((c) => c.error).length;
    const total = items.length;
    const blocked = items.filter((t) => isBlocked(t.response_code)).length;
    const allowed = total - blocked;
    const scState = sc ? String(sc.state).toLowerCase() : null;

    return {
      scope: {
        entityName: A.ctx?.entityName || A.ctx?.me?.entity_name || "Topology",
        isPlatform: A.isPlatform(),
        canLaunch: A.canActOnCvms() && A.has(A.P.CVM_LAUNCH),
      },
      sc: sc ? { id: sc.id, fqdn: sc.fqdn, state: sc.state, ok: scState === "running", secrets } : null,
      hasTrafficPerm,
      cvms: shownCvms,
      moreCvms,
      dests,
      flows,
      secrets,
      stats: {
        cvmsRunning: running,
        cvmsTotal: live.length,
        errored,
        windowMin: WINDOW_MIN,
        total,
        allowed,
        blocked,
        allowedPct: total ? Math.round((allowed / total) * 100) : 0,
        blockedPct: total ? Math.round((blocked / total) * 100) : 0,
        reqPerMin: Math.round(total / WINDOW_MIN),
        secrets,
      },
    };
  }

  A.Views = A.Views || {};
  A.Views.renderOverview = renderOverview;
})(window.Admin);
