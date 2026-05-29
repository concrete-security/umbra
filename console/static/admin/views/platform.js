(function (A) {
  const UI = A.UI;

  async function renderOperations() {
    const response = await A.api(A.adminQuery("operations", { limit: "50" }));
    const body = response.ok ? await response.json() : { items: [] };
    const rows = (body.items || []).map((o) => [
      UI.fmtTs(o.updated_at),
      UI.escapeHtml(o.kind),
      UI.escapeHtml(o.status + (o.error?.code ? " (" + o.error.code + ")" : "")),
      UI.escapeHtml((o.progress?.step || "—") + " " + (o.progress?.percent ?? "")),
      UI.escapeHtml(o.actor_email || "—"),
      '<span class="mono">' + UI.escapeHtml(o.target?.id || "—") + "</span>",
    ]);
    A.el("panel-operations").innerHTML =
      UI.pageHeader("Operations", "Async platform operations.") +
      '<div class="card">' +
      UI.tableHtml(["Updated", "Kind", "Status", "Progress", "Actor", "Target"], rows) +
      "</div>";
  }

  async function renderPlatform() {
    const [entitiesRes, scRes] = await Promise.all([
      A.api("/api/v1/entities?limit=100"),
      A.api(A.adminQuery("security-cvms", { limit: "50" })),
    ]);
    const entities = entitiesRes.ok ? (await entitiesRes.json()).items || [] : [];
    const scItems = scRes.ok ? (await scRes.json()).items || [] : [];
    const entRows = entities.map((e) => [
      UI.escapeHtml(e.name),
      UI.escapeHtml(e.domain),
      '<span class="mono">' + e.id + "</span>",
    ]);
    const scRows = scItems.map((s, idx) => [
      UI.badge(s.state),
      UI.escapeHtml(s.entity_name || "—"),
      '<span class="mono">' + UI.escapeHtml(s.fqdn || "—") + "</span>",
    ]);
    const panel = A.el("panel-platform");
    panel.innerHTML =
      UI.pageHeader("Platform", "Cross-tenant inventory.") +
      '<div class="grid">' +
      '<div class="card"><h3>Entities</h3>' +
      UI.tableHtml(["Name", "Domain", "ID"], entRows) +
      "</div>" +
      '<div class="card"><h3>Security CVMs</h3>' +
      UI.tableHtml(["State", "Entity", "FQDN"], scRows, { clickable: true }) +
      "</div></div>";

    panel.querySelectorAll("tbody tr.clickable").forEach((tr, idx) => {
      tr.addEventListener("click", () => {
        const s = scItems[idx];
        if (s) {
          A.ctx.viewEntityId = s.entity_id || A.viewEntityId();
          sessionStorage.setItem(A.ENTITY_KEY, A.ctx.viewEntityId);
          A.entityScCache = null;
          A.Drawer.openSc(s, "egress");
        }
      });
    });
  }

  async function connectLogStream() {
    A.disconnectLogStream();
    if (!A.session?.access_token) return;
    A.el("panel-logs").innerHTML =
      UI.pageHeader("Logs", "Live structlog stream (platform operator).") +
      '<div class="card"><div id="log-stream"></div></div>';
    const target = A.el("log-stream");
    const controller = new AbortController();
    A.logAbort = controller;
    try {
      const response = await fetch(A.apiBase() + "/api/v1/admin/logs/stream", {
        headers: {
          Authorization: "Bearer " + A.session.access_token,
          Accept: "text/event-stream",
        },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        A.setConn("err", "logs");
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        parts.forEach((block) => {
          const line = block.split("\n").find((l) => l.startsWith("data: "));
          if (!line) return;
          try {
            const row = JSON.parse(line.slice(6));
            target.textContent +=
              "[" +
              UI.fmtTs(row.timestamp) +
              "] " +
              (row.level || "") +
              " " +
              (row.event || "") +
              (row.route ? " " + row.route : "") +
              (row.status ? " " + row.status : "") +
              "\n";
            target.scrollTop = target.scrollHeight;
          } catch (_) {}
        });
      }
    } catch (_) {
      if (!controller.signal.aborted) A.setConn("err", "logs");
    }
  }

  function disconnectLogStream() {
    if (A.logAbort) {
      A.logAbort.abort();
      A.logAbort = null;
    }
  }

  A.Views = A.Views || {};
  A.Views.renderOperations = renderOperations;
  A.Views.renderPlatform = renderPlatform;
  A.Views.connectLogStream = connectLogStream;
  A.Views.disconnectLogStream = disconnectLogStream;
})(window.Admin);
