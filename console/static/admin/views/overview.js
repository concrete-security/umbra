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
    const [cvms, sc, traffic] = await Promise.all([
      A.fetchCvms(),
      A.fetchSecurityCvm(),
      hasTraffic ? A.fetchTrafficLogs({ limit: String(TRAFFIC_LIMIT), from: windowFromIso() }) : Promise.resolve({ items: [] }),
    ]);

    const model = buildModel(cvms || [], sc, (traffic && traffic.items) || [], hasTraffic);
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

  function buildModel(allCvms, sc, items, hasTrafficPerm) {
    const DEAD = new Set(["terminated", "decommissioned"]);
    const live = allCvms.filter((c) => !DEAD.has(String(c.state).toLowerCase()));

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
      sc: sc ? { id: sc.id, fqdn: sc.fqdn, state: sc.state, ok: scState === "running" } : null,
      hasTrafficPerm,
      cvms: shownCvms,
      moreCvms,
      dests,
      flows,
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
      },
    };
  }

  A.Views = A.Views || {};
  A.Views.renderOverview = renderOverview;
})(window.Admin);
