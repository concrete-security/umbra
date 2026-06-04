(function (A) {
  const ICON_SPRITE = "/admin/assets/icons.svg";

  const UI = {
    escapeHtml(s) {
      return String(s ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    },

    _pad2(n) {
      return String(n).padStart(2, "0");
    },

    _parseTs(ts) {
      if (!ts) return null;
      const d = new Date(ts);
      return Number.isNaN(d.getTime()) ? null : d;
    },

    _fmtLocalTime(d) {
      return `${UI._pad2(d.getHours())}:${UI._pad2(d.getMinutes())}:${UI._pad2(d.getSeconds())}`;
    },

    _fmtLocalDate(d) {
      return `${d.getFullYear()}-${UI._pad2(d.getMonth() + 1)}-${UI._pad2(d.getDate())}`;
    },

    fmtTs(ts) {
      const d = UI._parseTs(ts);
      return d ? UI._fmtLocalTime(d) : ts || "—";
    },

    fmtTsFull(ts) {
      const d = UI._parseTs(ts);
      return d ? `${UI._fmtLocalDate(d)} ${UI._fmtLocalTime(d)}` : ts || "—";
    },

    fmtTsShort(ts) {
      const d = UI._parseTs(ts);
      return d
        ? `${UI._pad2(d.getMonth() + 1)}-${UI._pad2(d.getDate())} ${UI._fmtLocalTime(d)}`
        : ts || "—";
    },

    relTime(ts) {
      const d = UI._parseTs(ts);
      if (!d) return ts || "—";
      const diff = Math.max(0, Date.now() - d.getTime());
      const s = Math.floor(diff / 1000);
      if (s < 5) return "just now";
      if (s < 60) return `${s}s ago`;
      const m = Math.floor(s / 60);
      if (m < 60) return `${m}m ago`;
      const h = Math.floor(m / 60);
      if (h < 24) return `${h}h ago`;
      const days = Math.floor(h / 24);
      if (days < 7) return `${days}d ago`;
      return UI._fmtLocalDate(d);
    },

    fmtBytes(n) {
      if (n == null) return "—";
      n = Number(n);
      if (!Number.isFinite(n)) return "—";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i += 1;
      }
      return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
    },

    stateClass(state) {
      if (!state) return "";
      const s = String(state).toLowerCase();
      if (s === "running" || s === "succeeded" || s === "active" || s === "live") return "badge-running";
      if (s === "error" || s === "failed") return "badge-error";
      if (s === "pending") return "badge-warn";
      if (s === "stopped" || s === "terminated" || s === "decommissioned") return "badge-stopped";
      return "";
    },

    dotClass(state) {
      if (!state) return "dot";
      const s = String(state).toLowerCase();
      if (s === "running" || s === "succeeded" || s === "ok" || s === "live" || s === "active") return "dot dot-ok";
      if (s === "error" || s === "failed") return "dot dot-err";
      if (s === "pending" || s === "warn" || s === "warning") return "dot dot-warn";
      return "dot";
    },

    badge(state, label) {
      const text = label || state || "—";
      return `<span class="badge ${UI.stateClass(state)}">${UI.escapeHtml(text)}</span>`;
    },

    codeClass(code) {
      const n = Number(code);
      if (n >= 200 && n < 300) return "code-2xx";
      if (n >= 300 && n < 400) return "code-3xx";
      if (n >= 400) return "code-4xx";
      return "";
    },

    icon(name, classes = "") {
      const cls = classes ? ` class="${UI.escapeHtml(classes)}"` : "";
      return `<svg${cls} aria-hidden="true"><use href="${ICON_SPRITE}#i-${UI.escapeHtml(name)}"/></svg>`;
    },

    pageHeader(title, desc, opts) {
      opts = opts || {};
      const actions = opts.actions ? `<div class="flex items-center gap-2">${opts.actions}</div>` : "";
      const icon = opts.icon ? `<span class="flex h-9 w-9 items-center justify-center rounded-input bg-accent/10 text-accent">${UI.icon(opts.icon, "h-5 w-5")}</span>` : "";
      return `
        <header class="mb-6 flex items-start justify-between gap-4 flex-wrap">
          <div class="flex items-start gap-3 min-w-0">
            ${icon}
            <div class="min-w-0">
              <h2 class="text-xl font-semibold tracking-tight text-ink truncate">${UI.escapeHtml(title)}</h2>
              ${desc ? `<p class="mt-0.5 text-sm text-mute max-w-2xl">${UI.escapeHtml(desc)}</p>` : ""}
            </div>
          </div>
          ${actions}
        </header>`;
    },

    // Legacy card kept for old views during migration
    card(title, value) {
      return `<div class="card card-pad"><h3 class="section-title mb-2">${UI.escapeHtml(title)}</h3><div class="font-mono text-stat text-ink">${value ?? "—"}</div></div>`;
    },

    statTile({ icon, label, value, sub, tone, href, onClickAttr }) {
      const toneClass =
        tone === "ok" ? "text-ok"
        : tone === "warn" ? "text-warn"
        : tone === "err" ? "text-err"
        : "text-ink";
      const iconBg =
        tone === "ok" ? "bg-ok/10 text-ok"
        : tone === "warn" ? "bg-warn/10 text-warn"
        : tone === "err" ? "bg-err/10 text-err"
        : "bg-accent/10 text-accent";
      const click = onClickAttr || (href ? ` data-href="${UI.escapeHtml(href)}"` : "");
      const tag = href || onClickAttr ? "button" : "div";
      const interactive = href || onClickAttr ? ' type="button" class="stat-tile card-hover text-left w-full"' : ' class="stat-tile"';
      return `
        <${tag}${interactive}${click}>
          <div class="flex items-start justify-between relative">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="flex h-6 w-6 items-center justify-center rounded-md ${iconBg}">${UI.icon(icon, "h-3.5 w-3.5")}</span>
                <span class="section-title">${UI.escapeHtml(label)}</span>
              </div>
              <div class="stat-tile-value mt-3 ${toneClass}">${value ?? "—"}</div>
              ${sub ? `<div class="stat-tile-sub">${sub}</div>` : ""}
            </div>
          </div>
        </${tag}>`;
    },

    // Legacy tableHtml (kept for backwards compat)
    tableHtml(headers, rows, opts) {
      opts = opts || {};
      if (!rows.length) {
        return opts.empty || '<p class="px-4 py-6 text-center text-xs text-mute">No rows</p>';
      }
      const head = "<tr>" + headers.map((h) => `<th>${h}</th>`).join("") + "</tr>";
      const body = rows
        .map((r, idx) => {
          const cls = opts.clickable ? ' class="clickable"' : "";
          const data = opts.dataAttr ? ` data-idx="${idx}"` : "";
          return `<tr${cls}${data}>` + r.map((c) => `<td>${c}</td>`).join("") + "</tr>";
        })
        .join("");
      return `<div class="overflow-auto rounded-card border border-line${opts.tall ? " max-h-[520px]" : " max-h-[420px]"}"><table class="data-table${opts.clickable ? " clickable" : ""}"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
    },

    tableV2(cols, rows, opts) {
      opts = opts || {};
      if (opts.loading) {
        const n = typeof opts.loading === "number" ? opts.loading : 5;
        return UI.skeletonTable(cols.length, n);
      }
      if (!rows.length) {
        return opts.empty || UI.emptyV2({ title: "No results", body: "Adjust filters or try a different search." });
      }
      const sort = opts.sort || {};
      const head =
        "<tr>" +
        cols
          .map((c) => {
            const sortable = c.sortable !== false && opts.onSort;
            const isActive = sort.col === c.key;
            const dir = isActive ? (sort.dir === "asc" ? "▲" : "▼") : "";
            const sortAttr = sortable ? ` data-sort-col="${UI.escapeHtml(c.key)}" class="col-sortable"` : "";
            const align = c.align === "right" ? "text-right" : "";
            return `<th${sortAttr}><span class="inline-flex items-center gap-1 ${align}">${UI.escapeHtml(c.label)}${dir ? ` <span class="text-accent">${dir}</span>` : ""}</span></th>`;
          })
          .join("") +
        (opts.rowAction ? "<th></th>" : "") +
        "</tr>";
      const body = rows
        .map((r, idx) => {
          const cells = cols
            .map((c) => {
              const value = c.render ? c.render(r) : r[c.key];
              const align = c.align === "right" ? "text-right" : "";
              const cellCls = c.cellClass || "";
              return `<td class="${align} ${cellCls}">${value ?? "—"}</td>`;
            })
            .join("");
          const actionCell = opts.rowAction ? `<td class="text-right">${opts.rowAction(r, idx)}</td>` : "";
          const rowAttr = opts.rowAttr ? opts.rowAttr(r, idx) : "";
          const cls = opts.onRowClick ? " class=\"cursor-pointer\"" : "";
          return `<tr${cls} data-row-idx="${idx}"${rowAttr ? " " + rowAttr : ""}>${cells}${actionCell}</tr>`;
        })
        .join("");
      const cls = `data-table${opts.onRowClick ? " clickable" : ""}`;
      const tallCls = opts.tall ? "max-h-[640px]" : "max-h-[520px]";
      return `<div class="overflow-auto rounded-card border border-line ${tallCls}"><table class="${cls}"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
    },

    skeletonTable(cols, rows) {
      let html = `<div class="overflow-hidden rounded-card border border-line"><table class="data-table"><tbody>`;
      for (let r = 0; r < rows; r++) {
        html += "<tr>";
        for (let c = 0; c < cols; c++) {
          html += `<td class="px-3 py-2.5"><div class="skeleton h-3 ${c === 0 ? "w-20" : "w-32"}"></div></td>`;
        }
        html += "</tr>";
      }
      html += "</tbody></table></div>";
      return html;
    },

    skeleton(width, height) {
      return `<div class="skeleton ${width || "w-24"} ${height || "h-4"}"></div>`;
    },

    filterChips(items, active, attr) {
      return (
        '<div class="flex flex-wrap items-center gap-1.5">' +
        items
          .map(
            ([id, label]) =>
              `<button type="button" class="filter-chip${active === id ? " active" : ""}" data-${attr}="${UI.escapeHtml(id)}">${UI.escapeHtml(label)}</button>`
          )
          .join("") +
        "</div>"
      );
    },

    emptyState(msg, ctaHtml) {
      return `<div class="empty-pane">${UI.icon("info", "h-10 w-10 text-mute-soft mb-3")}<p class="text-sm text-mute mb-4">${UI.escapeHtml(msg)}</p>${ctaHtml || ""}</div>`;
    },

    emptyV2({ icon, title, body, ctaLabel, onCta, ctaId }) {
      const cta = ctaLabel ? `<button type="button" class="btn btn-primary" ${ctaId ? `id="${UI.escapeHtml(ctaId)}"` : ""} ${onCta ? `data-cta="${UI.escapeHtml(onCta)}"` : ""}>${UI.escapeHtml(ctaLabel)}</button>` : "";
      return `
        <div class="empty-pane">
          ${UI.icon(icon || "info", "h-10 w-10 text-mute-soft mb-3")}
          <h3>${UI.escapeHtml(title)}</h3>
          ${body ? `<p>${UI.escapeHtml(body)}</p>` : ""}
          ${cta}
        </div>`;
    },

    copyButton(value, label) {
      const display = label || value;
      return `<button type="button" class="copy-pill" data-copy="${UI.escapeHtml(value)}" title="Copy ${UI.escapeHtml(value)}">${UI.escapeHtml(display)}${UI.icon("copy", "h-3 w-3 ml-1 opacity-60")}</button>`;
    },

    shortDigest(value, head = 18, tail = 10) {
      const s = String(value || "");
      if (!s) return "—";
      if (s.length <= head + tail + 3) return s;
      return `${s.slice(0, head)}...${s.slice(-tail)}`;
    },

    digestCopy(value, label) {
      if (!value) return '<span class="text-mute">—</span>';
      return UI.copyButton(value, label || UI.shortDigest(value));
    },

    helpHint(content) {
      return `<button type="button" class="help-hint" data-hint="${UI.escapeHtml(content)}" aria-label="${UI.escapeHtml(content)}">?</button>`;
    },

    kebabMenu(items) {
      const id = "kebab-" + Math.random().toString(36).slice(2, 9);
      return `
        <div class="relative inline-block text-left" data-kebab="${id}">
          <button type="button" class="btn btn-ghost btn-xs" data-kebab-toggle="${id}" aria-label="More actions">${UI.icon("more", "h-4 w-4")}</button>
          <div class="kebab-menu hidden" data-kebab-panel="${id}">
            ${items.map((it) => `<button type="button" class="kebab-item${it.danger ? " kebab-item-danger" : ""}" data-kebab-action="${UI.escapeHtml(it.id)}">${it.icon ? UI.icon(it.icon, "h-3.5 w-3.5 mr-1.5") : ""}${UI.escapeHtml(it.label)}</button>`).join("")}
          </div>
        </div>`;
    },

    toast(message, kind = "info") {
      let root = document.getElementById("toast-root");
      if (!root) {
        root = document.createElement("div");
        root.id = "toast-root";
        root.className = "fixed top-16 right-4 z-[100] flex flex-col gap-2 max-w-sm";
        document.body.appendChild(root);
      }
      const cls = kind === "ok" ? "toast-ok" : kind === "err" ? "toast-err" : "";
      const iconName = kind === "ok" ? "check" : kind === "err" ? "alert" : "info";
      const node = document.createElement("div");
      node.className = "toast " + cls;
      node.innerHTML = `${UI.icon(iconName, "h-4 w-4 mt-0.5 shrink-0 " + (kind === "ok" ? "text-ok" : kind === "err" ? "text-err" : "text-mute"))}<span class="text-ink">${UI.escapeHtml(message)}</span>`;
      root.appendChild(node);
      setTimeout(() => {
        node.style.opacity = "0";
        node.style.transition = "opacity 200ms";
      }, 3600);
      setTimeout(() => node.remove(), 4000);
    },

    confirm(opts) {
      return new Promise((resolve) => {
        UI.dialog({
          title: opts.title || "Confirm",
          body: opts.message || "",
          primary: { label: opts.okLabel || "OK", danger: !!opts.danger },
          onClose: (ok) => resolve(!!ok),
        });
      });
    },

    openModal(html, onBind) {
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      overlay.innerHTML = `<div class="modal-panel modal-wide">${html}</div>`;
      overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.remove();
      });
      document.body.appendChild(overlay);
      if (onBind) onBind(overlay);
      return overlay;
    },

    closeModal(overlay) {
      overlay?.remove();
    },

    /**
     * Generalized dialog with form validation.
     * opts = { title, body (HTML), wide, primary: {label, danger, run: async (overlay) => boolean|undefined}, secondary: {label}, onClose: (resultBool) => void }
     */
    dialog(opts) {
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      const sizeClass = opts.size === "xl" ? "modal-xl" : opts.wide ? "modal-wide" : "";
      overlay.innerHTML = `
        <div class="modal-panel ${sizeClass}">
          <div class="flex items-start justify-between mb-3">
            <h3 class="text-lg font-semibold text-ink">${UI.escapeHtml(opts.title || "")}</h3>
            <button type="button" class="btn btn-ghost btn-xs" data-dlg-close aria-label="Close">${UI.icon("x", "h-4 w-4")}</button>
          </div>
          ${opts.subtitle ? `<p class="text-sm text-mute mb-4 -mt-2">${UI.escapeHtml(opts.subtitle)}</p>` : ""}
          <div data-dlg-body class="text-sm text-ink">${opts.body || ""}</div>
          <div class="mt-5 flex items-center justify-end gap-2">
            <button type="button" class="btn btn-ghost" data-dlg-cancel>${UI.escapeHtml(opts.secondary?.label || "Cancel")}</button>
            ${opts.primary ? `<button type="button" class="btn ${opts.primary.danger ? "btn-danger" : "btn-primary"}" data-dlg-ok>${UI.escapeHtml(opts.primary.label || "OK")}</button>` : ""}
          </div>
        </div>`;
      const close = (result) => {
        overlay.remove();
        document.removeEventListener("keydown", esc);
        opts.onClose && opts.onClose(result);
      };
      const esc = (e) => {
        if (e.key === "Escape") close(false);
      };
      overlay.addEventListener("click", (e) => {
        if (e.target === overlay) close(false);
      });
      overlay.querySelector("[data-dlg-close]").onclick = () => close(false);
      overlay.querySelector("[data-dlg-cancel]").onclick = () => close(false);
      const okBtn = overlay.querySelector("[data-dlg-ok]");
      if (okBtn) {
        okBtn.onclick = async () => {
          if (opts.primary?.run) {
            okBtn.disabled = true;
            try {
              const result = await opts.primary.run(overlay);
              if (result === false) {
                okBtn.disabled = false;
                return;
              }
              close(true);
            } catch (err) {
              UI.toast(err?.message || "Failed", "err");
              okBtn.disabled = false;
            }
          } else {
            close(true);
          }
        };
      }
      document.addEventListener("keydown", esc);
      document.body.appendChild(overlay);
      if (opts.onBind) opts.onBind(overlay);
      return overlay;
    },

    strongConfirm({ title, body, confirmWord, primary, danger }) {
      return new Promise((resolve) => {
        const word = (confirmWord || "CONFIRM").toUpperCase();
        UI.dialog({
          title: title || "Confirm",
          body: `
            <p class="mb-3 text-sm text-mute">${UI.escapeHtml(body || "")}</p>
            <label class="field-label">Type <span class="font-mono text-ink">${UI.escapeHtml(word)}</span> to confirm</label>
            <input type="text" class="input font-mono" data-strong autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false">
          `,
          primary: {
            label: primary || word,
            danger: !!danger,
            async run(overlay) {
              const input = overlay.querySelector("[data-strong]");
              if ((input.value || "").trim().toUpperCase() !== word) {
                input.classList.add("border-err");
                UI.toast(`Type ${word} to confirm`, "err");
                return false;
              }
            },
          },
          onClose: resolve,
          onBind(overlay) {
            const input = overlay.querySelector("[data-strong]");
            input?.focus();
          },
        });
      });
    },

    permissionGrid({ available, granted, scope, onChange }) {
      const grants = new Set(granted || []);
      const items = (available || A.ENTITY_PERMS || []).filter((p) => !scope || p !== "PLATFORM_OPERATOR" || scope === "platform");
      const descriptions = {
        CVM_LAUNCH: "Provision new Dev CVMs",
        CVM_MANAGE: "Start, stop, update and terminate CVMs",
        SECURITY_CVM_CONFIGURE: "Provision, update and decommission the Security CVM",
        TRAFFIC_LOGS_VIEW: "View egress traffic logs",
        AUDIT_VIEW: "View the audit log",
        AUDIT_EXPORT: "Export audit records",
        USER_MANAGE: "Invite, deactivate and erase users",
        PERMISSION_MANAGE: "Grant and revoke permissions",
        QUOTA_MANAGE: "Set and clear resource quotas",
        PLATFORM_OPERATOR: "Full platform access across all entities",
      };
      const id = "pg-" + Math.random().toString(36).slice(2, 7);
      const html = items
        .map((p) => {
          const checked = grants.has(p) ? "checked" : "";
          const desc = descriptions[p] || "";
          return `
            <label class="flex items-start gap-2 rounded-input border border-line-soft p-2.5 hover:border-line cursor-pointer">
              <input type="checkbox" data-perm="${UI.escapeHtml(p)}" class="mt-0.5 accent-accent" ${checked}>
              <span class="min-w-0">
                <span class="block text-sm font-medium text-ink">${UI.escapeHtml(p.replace(/_/g, " ").toLowerCase().replace(/^./, c => c.toUpperCase()))}</span>
                ${desc ? `<span class="block text-2xs text-mute mt-0.5">${UI.escapeHtml(desc)}</span>` : ""}
              </span>
            </label>`;
        })
        .join("");
      const wrapper = `<div class="grid grid-cols-1 sm:grid-cols-2 gap-2" data-permission-grid="${id}">${html}</div>`;
      if (onChange) {
        queueMicrotask(() => {
          document.querySelectorAll(`[data-permission-grid="${id}"] input[type=checkbox]`).forEach((cb) => {
            cb.addEventListener("change", () => {
              const list = Array.from(document.querySelectorAll(`[data-permission-grid="${id}"] input:checked`)).map((c) => c.dataset.perm);
              onChange(list);
            });
          });
        });
      }
      return wrapper;
    },

    dateRange({ id, from, to, presets, onChange }) {
      const presetButtons = (presets || [
        ["1h", "Last hour"],
        ["24h", "24 hours"],
        ["7d", "7 days"],
        ["custom", "Custom"],
      ])
        .map(([key, label]) => `<button type="button" class="filter-chip" data-dr-preset="${UI.escapeHtml(key)}">${UI.escapeHtml(label)}</button>`)
        .join("");
      return `
        <div class="flex flex-wrap items-center gap-2" data-date-range="${UI.escapeHtml(id)}">
          ${presetButtons}
          <input type="datetime-local" class="input input-sm w-44" data-dr-from value="${UI.escapeHtml(from || "")}">
          <span class="text-mute text-2xs">to</span>
          <input type="datetime-local" class="input input-sm w-44" data-dr-to value="${UI.escapeHtml(to || "")}">
        </div>`;
    },

    diffView(before, after) {
      const fmt = (v) => UI.escapeHtml(v == null ? "null" : JSON.stringify(v, null, 2));
      const beforeStr = fmt(before);
      const afterStr = fmt(after);
      return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="card overflow-hidden">
            <div class="px-3 py-2 border-b border-line text-2xs uppercase tracking-wider text-mute bg-elev/40">Before</div>
            <pre class="font-mono text-2xs p-3 overflow-auto max-h-96 text-ink-dim whitespace-pre-wrap">${beforeStr}</pre>
          </div>
          <div class="card overflow-hidden">
            <div class="px-3 py-2 border-b border-line text-2xs uppercase tracking-wider text-mute bg-elev/40">After</div>
            <pre class="font-mono text-2xs p-3 overflow-auto max-h-96 text-ink-dim whitespace-pre-wrap">${afterStr}</pre>
          </div>
        </div>`;
    },

    sortableHeader(label, key, sort) {
      const active = sort?.col === key;
      const arrow = active ? (sort.dir === "asc" ? "▲" : "▼") : "";
      return `<button type="button" class="inline-flex items-center gap-1 text-2xs uppercase tracking-wider text-mute hover:text-ink" data-sort-col="${UI.escapeHtml(key)}">${UI.escapeHtml(label)}${arrow ? ` <span class="text-accent">${arrow}</span>` : ""}</button>`;
    },

    bar(value, max, opts) {
      opts = opts || {};
      const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
      const tone = opts.tone || "accent";
      const toneCls = tone === "ok" ? "bg-ok" : tone === "warn" ? "bg-warn" : tone === "err" ? "bg-err" : "bg-accent";
      return `<div class="h-1.5 w-full rounded-full bg-elev overflow-hidden"><div class="h-full ${toneCls}" style="width:${pct}%"></div></div>`;
    },

    // Global delegated handlers — attach once
    bindGlobalHandlers() {
      if (UI._handlersBound) return;
      UI._handlersBound = true;
      document.addEventListener("click", (e) => {
        const copyBtn = e.target.closest("[data-copy]");
        if (copyBtn) {
          const val = copyBtn.dataset.copy;
          if (val) {
            navigator.clipboard?.writeText(val).then(() => UI.toast("Copied", "ok"));
          }
        }
        const kebabToggle = e.target.closest("[data-kebab-toggle]");
        document.querySelectorAll("[data-kebab-panel]").forEach((p) => {
          if (!kebabToggle || p.dataset.kebabPanel !== kebabToggle.dataset.kebabToggle) {
            p.classList.add("hidden");
          }
        });
        if (kebabToggle) {
          const panel = document.querySelector(`[data-kebab-panel="${kebabToggle.dataset.kebabToggle}"]`);
          panel?.classList.toggle("hidden");
        }
        const presetBtn = e.target.closest("[data-dr-preset]");
        if (presetBtn) {
          const wrapper = presetBtn.closest("[data-date-range]");
          if (wrapper) {
            const preset = presetBtn.dataset.drPreset;
            const fromEl = wrapper.querySelector("[data-dr-from]");
            const toEl = wrapper.querySelector("[data-dr-to]");
            if (preset !== "custom") {
              const now = new Date();
              const fromDate = new Date(now);
              if (preset === "1h") fromDate.setHours(now.getHours() - 1);
              else if (preset === "24h") fromDate.setDate(now.getDate() - 1);
              else if (preset === "7d") fromDate.setDate(now.getDate() - 7);
              const toLocal = (d) => {
                const tz = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
                return tz.toISOString().slice(0, 16);
              };
              fromEl.value = toLocal(fromDate);
              toEl.value = toLocal(now);
            }
            wrapper.querySelectorAll("[data-dr-preset]").forEach((b) => b.classList.toggle("active", b === presetBtn));
            wrapper.dispatchEvent(new CustomEvent("range-change", { detail: { from: fromEl.value, to: toEl.value }, bubbles: true }));
          }
        }
        const hint = e.target.closest("[data-hint]");
        if (hint) {
          UI.toast(hint.dataset.hint, "info");
        }
      });
      document.addEventListener("change", (e) => {
        const inp = e.target.closest("[data-dr-from], [data-dr-to]");
        if (inp) {
          const wrapper = inp.closest("[data-date-range]");
          const fromEl = wrapper.querySelector("[data-dr-from]");
          const toEl = wrapper.querySelector("[data-dr-to]");
          wrapper.querySelectorAll("[data-dr-preset]").forEach((b) => b.classList.toggle("active", b.dataset.drPreset === "custom"));
          wrapper.dispatchEvent(new CustomEvent("range-change", { detail: { from: fromEl.value, to: toEl.value }, bubbles: true }));
        }
      });
      document.addEventListener("click", (e) => {
        const trigger = e.target.closest("[data-href]");
        if (trigger && trigger.dataset.href.startsWith("#")) {
          location.hash = trigger.dataset.href;
        }
      });
    },
  };

  A.UI = UI;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => UI.bindGlobalHandlers());
  } else {
    UI.bindGlobalHandlers();
  }
})(window.Admin);
