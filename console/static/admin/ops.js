(function (A) {
  const Ops = {
    load() {
      try {
        const raw = sessionStorage.getItem(A.OPS_KEY);
        return raw ? JSON.parse(raw) : [];
      } catch {
        return [];
      }
    },

    save(list) {
      const trimmed = list.slice(-30);
      sessionStorage.setItem(A.OPS_KEY, JSON.stringify(trimmed));
      return trimmed;
    },

    track(op) {
      const list = Ops.load();
      const entry = {
        id: op.id,
        kind: op.kind,
        status: op.status,
        targetId: op.target?.id || op.target_id,
        cvmId: op.target?.type === "cvm" ? op.target?.id : op.cvm_id,
        updatedAt: Date.now(),
      };
      const idx = list.findIndex((x) => x.id === entry.id);
      if (idx >= 0) list[idx] = { ...list[idx], ...entry };
      else list.push(entry);
      return Ops.save(list);
    },

    pendingForCvm(cvmId) {
      return Ops.load().filter(
        (o) =>
          o.cvmId === cvmId &&
          o.status !== "succeeded" &&
          o.status !== "failed" &&
          o.status !== "cancelled"
      );
    },

    anyPending() {
      return Ops.load().some(
        (o) => o.status !== "succeeded" && o.status !== "failed" && o.status !== "cancelled"
      );
    },

    async poll(operationId, onUpdate) {
      for (let i = 0; i < 120; i++) {
        const response = await A.api("/api/v1/operations/" + operationId);
        if (!response.ok) throw new Error(await A.parseError(response));
        const op = await response.json();
        Ops.track(op);
        if (onUpdate) onUpdate(op);
        if (op.status === "succeeded") return op;
        if (["failed", "cancelled"].includes(op.status)) {
          throw new Error(op.error?.message || op.error?.code || `Operation ${op.status}`);
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
      throw new Error("Operation timed out");
    },

    async refreshPending() {
      const list = Ops.load();
      const pending = list.filter(
        (o) => o.status !== "succeeded" && o.status !== "failed" && o.status !== "cancelled"
      );
      if (!pending.length) return list;
      let changed = false;
      for (const entry of pending) {
        if (["succeeded", "failed", "cancelled"].includes(entry.status)) continue;
        const response = await A.api("/api/v1/operations/" + entry.id);
        if (!response.ok) continue;
        const op = await response.json();
        entry.status = op.status;
        entry.kind = op.kind;
        if (op.target?.id) entry.cvmId = op.target.type === "cvm" ? op.target.id : entry.cvmId;
        changed = true;
      }
      if (changed) Ops.save(list);
      return list;
    },
  };

  A.Ops = Ops;
})(window.Admin);
