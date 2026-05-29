(function (A) {
  const handlers = {
    palette: null,
    help: null,
    closeAll: null,
  };

  const NAV_KEYS = {
    h: "overview",
    c: "cvms",
    p: "profiles",
    u: "users",
    s: "security",
    t: "traffic",
    a: "audit",
    o: "operations",
    e: "platform/entities",
    y: "platform/system",
    l: "logs",
  };

  let lastG = 0;
  let helpVisible = false;

  function handleKey(e) {
    if (e.defaultPrevented) return;
    const inField = e.target instanceof HTMLElement && /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;
    const meta = e.metaKey || e.ctrlKey;

    if (meta && e.key.toLowerCase() === "k") {
      e.preventDefault();
      handlers.palette?.();
      return;
    }

    if (e.key === "Escape") {
      handlers.closeAll?.();
      return;
    }

    if (inField) return;

    if (e.key === "/") {
      e.preventDefault();
      const search = document.querySelector('[data-active-panel] [data-search], [data-active-panel] input[type="search"]');
      if (search instanceof HTMLElement) search.focus();
      return;
    }

    if (e.key === "?") {
      e.preventDefault();
      toggleHelp();
      return;
    }

    if (e.key.toLowerCase() === "g" && !meta) {
      lastG = Date.now();
      return;
    }

    if (Date.now() - lastG < 1200 && !meta) {
      const target = NAV_KEYS[e.key.toLowerCase()];
      if (target) {
        e.preventDefault();
        location.hash = target;
        lastG = 0;
      }
    }
  }

  function toggleHelp() {
    if (helpVisible) {
      document.getElementById("kb-help")?.remove();
      helpVisible = false;
      return;
    }
    helpVisible = true;
    const node = document.createElement("div");
    node.id = "kb-help";
    node.className = "modal-overlay";
    node.innerHTML = `
      <div class="modal-panel">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-lg font-semibold text-ink">Keyboard shortcuts</h3>
          <button type="button" class="btn btn-ghost btn-xs" data-kb-close>${A.UI.icon("x", "h-4 w-4")}</button>
        </div>
        <div class="space-y-3 text-sm">
          <div class="flex items-center justify-between"><span class="text-mute">Search & navigate</span><kbd>⌘K</kbd></div>
          <div class="flex items-center justify-between"><span class="text-mute">Focus search</span><kbd>/</kbd></div>
          <div class="flex items-center justify-between"><span class="text-mute">Show this menu</span><kbd>?</kbd></div>
          <div class="flex items-center justify-between"><span class="text-mute">Dismiss</span><kbd>Esc</kbd></div>
          <div class="section-divider"></div>
          <p class="text-2xs uppercase tracking-wider text-mute">Go to…</p>
          <div class="grid grid-cols-2 gap-2 text-2xs">
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>h</kbd><span class="text-mute">Overview</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>c</kbd><span class="text-mute">CVMs</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>p</kbd><span class="text-mute">Profiles</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>u</kbd><span class="text-mute">Users</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>s</kbd><span class="text-mute">Security CVM</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>t</kbd><span class="text-mute">Traffic</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>a</kbd><span class="text-mute">Audit</span></div>
            <div class="flex items-center gap-2"><kbd>g</kbd><kbd>o</kbd><span class="text-mute">Operations</span></div>
          </div>
        </div>
      </div>`;
    node.addEventListener("click", (e) => {
      if (e.target === node || e.target.closest("[data-kb-close]")) {
        node.remove();
        helpVisible = false;
      }
    });
    document.body.appendChild(node);
  }

  function register({ palette, closeAll }) {
    if (palette) handlers.palette = palette;
    if (closeAll) handlers.closeAll = closeAll;
  }

  A.Shortcuts = { register, toggleHelp };

  document.addEventListener("keydown", handleKey);
})(window.Admin);
