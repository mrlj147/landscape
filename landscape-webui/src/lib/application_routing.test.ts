import { describe, expect, it } from "vitest";
import {
  ApplicationRoutingDraft,
  applyBlockReason,
  canStopPolicy,
  modeAllowsEditing,
  needsQuiescentConfirmation,
  routingCurrentRevision,
  routingStateLabel,
  saveBlockReason,
} from "./application_routing";
import type {
  ApplicationRoutingStatus,
  ApplicationRule,
} from "./application_routing";

const rule = (line = "telecom"): ApplicationRule => ({
  appid: 2550017,
  line_id: line,
  learn_endpoint: true,
  allow_udp_endpoint_hints: false,
});
function status(
  revision = 0,
  overrides: Partial<ApplicationRoutingStatus> = {},
): ApplicationRoutingStatus {
  return {
    mode: "lab",
    state: "stopped",
    message: "",
    saved_revision: revision,
    active_revision: null,
    catalog_total: 3306,
    clients: ["192.0.2.10"],
    lines: [
      {
        id: "telecom",
        name: "电信（测试出口）",
        flow_id: 1,
        wan_ifname: "test1",
        ready: true,
      },
      {
        id: "unicom",
        name: "联通（测试出口）",
        flow_id: 2,
        wan_ifname: "test2",
        ready: true,
      },
    ],
    policy: { revision, rules: [rule()] },
    runtime: { armed: false },
    ...overrides,
  };
}
function model(value = status()): ApplicationRoutingDraft {
  const draft = new ApplicationRoutingDraft();
  draft.acceptMutation(value);
  return draft;
}

describe("application routing draft consistency", () => {
  it("hides stale live status after a refresh failure and restores confirmation without losing edits", async () => {
    const live = status(2, {
      state: "running",
      active_revision: 2,
      runtime: { armed: true, admission_live: true },
    });
    const draft = model(live);
    draft.update(2550017, { line_id: "unicom" });
    await expect(
      draft.refreshStatus(() => Promise.reject(new Error("服务暂不可用"))),
    ).rejects.toThrow("服务暂不可用");
    expect(routingStateLabel(draft.status, draft.runtimeUnconfirmed)).toBe(
      "运行状态待确认",
    );
    expect(routingCurrentRevision(draft.status, draft.runtimeUnconfirmed)).toBe(
      "未确认",
    );
    expect(saveBlockReason(draft)).toContain("尚未确认");
    expect(applyBlockReason(draft, true)).toContain("尚未确认");
    expect(draft.rules[0].line_id).toBe("unicom");
    expect(draft.dirty).toBe(true);
    expect(draft.expectedRevision).toBe(2);

    await expect(
      draft.refreshStatus(() => Promise.resolve(live)),
    ).resolves.toBe(true);
    expect(routingStateLabel(draft.status, draft.runtimeUnconfirmed)).toBe(
      "测试分流运行中",
    );
    expect(routingCurrentRevision(draft.status, draft.runtimeUnconfirmed)).toBe(
      2,
    );
    expect(draft.runtimeUnconfirmed).toBe(false);
    expect(saveBlockReason(draft)).toBeNull();
    expect(draft.rules[0].line_id).toBe("unicom");
    expect(draft.dirty).toBe(true);
  });

  it("ignores a stale refresh failure after a newer status has been confirmed", async () => {
    const draft = model();
    let rejectOld!: (reason: Error) => void;
    const oldRead = draft.refreshStatus(
      () =>
        new Promise((_, reject) => {
          rejectOld = reject;
        }),
    );
    await draft.refreshStatus(() => Promise.resolve(status(3)));
    rejectOld(new Error("old request failed"));
    await expect(oldRead).rejects.toThrow("old request failed");
    expect(draft.runtimeUnconfirmed).toBe(false);
    expect(draft.expectedRevision).toBe(3);
  });

  it("does not erase line edits made while a status request is pending", () => {
    const draft = model();
    const read = draft.beginRead();
    draft.update(2550017, { line_id: "unicom" });
    draft.acceptRead(read, status(1));
    expect(draft.rules[0].line_id).toBe("unicom");
    expect(draft.dirty).toBe(true);
    expect(draft.expectedRevision).toBe(0);
    expect(draft.conflict).toBe(true);
    expect(applyBlockReason(draft, true)).toContain("重新载入");
  });

  it("ignores an older status response after a newer request completes", () => {
    const draft = model();
    const old = draft.beginRead();
    const latest = draft.beginRead();
    expect(draft.acceptRead(latest, status(2))).toBe(true);
    expect(draft.acceptRead(old, status(1))).toBe(false);
    expect(draft.expectedRevision).toBe(2);
  });

  it("does not let an in-flight read undo a completed save", () => {
    const draft = model();
    const old = draft.beginRead();
    draft.update(2550017, { line_id: "unicom" });
    draft.acceptMutation(
      status(1, { policy: { revision: 1, rules: [rule("unicom")] } }),
    );
    expect(draft.acceptRead(old, status(0))).toBe(false);
    expect(draft.rules[0].line_id).toBe("unicom");
    expect(draft.dirty).toBe(false);
    expect(draft.expectedRevision).toBe(1);
  });

  it("can stop the controller without discarding unsaved line changes", () => {
    const draft = model(status(2, { state: "running", active_revision: 2 }));
    draft.update(2550017, { line_id: "unicom" });
    draft.acceptMutation(status(2, { state: "stopped" }), true);
    expect(draft.status?.state).toBe("stopped");
    expect(draft.rules[0].line_id).toBe("unicom");
    expect(draft.dirty).toBe(true);
    expect(draft.expectedRevision).toBe(2);
  });

  it("explicit reload resolves a conflict and updates the save revision", () => {
    const draft = model();
    draft.update(2550017, { line_id: "unicom" });
    draft.acceptRead(draft.beginRead(), status(3));
    draft.reloadSaved();
    expect(draft.conflict).toBe(false);
    expect(draft.dirty).toBe(false);
    expect(draft.expectedRevision).toBe(3);
    expect(draft.rules[0].line_id).toBe("telecom");
  });

  it("requires explicit endpoint learning and clears dependent UDP consent", () => {
    const draft = model();
    expect(draft.add(1540009, "unicom")).toBe(true);
    expect(draft.rules[1].learn_endpoint).toBe(true);
    expect(draft.rules[1].allow_udp_endpoint_hints).toBe(false);
    expect(draft.add(1540009, "telecom")).toBe(false);
    draft.update(1540009, {
      learn_endpoint: true,
      allow_udp_endpoint_hints: true,
    });
    draft.update(1540009, { learn_endpoint: false });
    expect(draft.rules[1].allow_udp_endpoint_hints).toBe(false);
  });
});

describe("application routing application gates", () => {
  it("keeps stop recovery available while server runtime is unverified, and blocks save/apply", () => {
    const draft = model(
      status(3, {
        state: "error",
        active_revision: null,
        runtime_unverified: true,
      }),
    );
    expect(canStopPolicy(draft.status)).toBe(true);
    expect(saveBlockReason(draft)).toContain("重试停止");
    expect(applyBlockReason(draft, true)).toContain("重试停止");
    expect(routingStateLabel(draft.status)).toBe("运行状态待确认");
    draft.acceptMutation(
      status(3, { state: "stopped", runtime_unverified: false }),
    );
    expect(saveBlockReason(draft)).toBeNull();
    expect(canStopPolicy(draft.status)).toBe(false);
  });

  it("allows a local unconfirmed stop retry without enabling production actions", () => {
    const draft = model(status(2, { state: "error" }));
    draft.markRuntimeUnconfirmed();
    expect(canStopPolicy(draft.status, draft.runtimeUnconfirmed)).toBe(true);
    expect(saveBlockReason(draft)).toContain("尚未确认");
    expect(
      canStopPolicy(
        status(2, { mode: "production", runtime_unverified: true }),
        true,
      ),
    ).toBe(false);
  });
  it("requires quiescence on a first lab activation but allows a resumed armed controller", () => {
    const draft = model();
    expect(needsQuiescentConfirmation(draft.status)).toBe(true);
    expect(applyBlockReason(draft, false)).toContain("没有活动连接");
    expect(applyBlockReason(draft, true)).toBeNull();
    draft.acceptMutation(status(0, { runtime: { armed: true } }));
    expect(applyBlockReason(draft, false)).toBeNull();
  });

  it("blocks production and unknown backend modes even when their exit is ready", () => {
    for (const mode of ["production", "unexpected"]) {
      const draft = model(status(0, { mode }));
      expect(modeAllowsEditing(draft.status)).toBe(false);
      expect(applyBlockReason(draft, true)).toContain("禁止修改");
    }
  });

  it("blocks unavailable lines and unsaved changes", () => {
    const draft = model();
    draft.update(2550017, { line_id: "unicom" });
    expect(applyBlockReason(draft, true)).toContain("先保存");
    const unavailable = status();
    unavailable.lines[0].ready = false;
    draft.acceptMutation(unavailable);
    expect(applyBlockReason(draft, true)).toContain("尚未就绪");
  });

  it("allows a saved empty policy to remove application overrides", () => {
    const draft = model(status(1, { policy: { revision: 1, rules: [] } }));
    expect(applyBlockReason(draft, true)).toBeNull();
  });

  it("allows preview simulation without falsely requiring real WAN readiness", () => {
    const value = status(0, { mode: "preview", runtime: null });
    value.lines.forEach((line) => {
      line.ready = false;
    });
    const draft = model(value);
    expect(applyBlockReason(draft, true)).toBeNull();
    draft.acceptMutation({
      ...value,
      policy: { revision: 0, rules: [{ ...rule(), line_id: "missing" }] },
    });
    expect(applyBlockReason(draft, true)).toContain("已不存在");
  });

  it("invalidates a prior live state after a mutation error until a fresh read confirms it", () => {
    const draft = model(
      status(2, {
        state: "running",
        active_revision: 2,
        runtime: { armed: true, admission_live: true },
      }),
    );
    const stale = draft.beginRead();
    draft.markRuntimeUnconfirmed();
    expect(draft.runtimeUnconfirmed).toBe(true);
    expect(applyBlockReason(draft, true)).toContain("尚未确认");
    expect(
      draft.acceptRead(
        stale,
        status(2, { state: "running", active_revision: 2 }),
      ),
    ).toBe(false);
    draft.acceptRead(
      draft.beginRead(),
      status(2, { state: "error", active_revision: null }),
    );
    expect(draft.runtimeUnconfirmed).toBe(false);
    expect(routingStateLabel(draft.status)).toBe("运行异常");
  });

  it("never labels a preview response as live routing even if it contains an active revision", () => {
    const preview = status(4, {
      mode: "preview",
      state: "running",
      active_revision: 4,
      runtime: { armed: true, admission_live: true },
    });
    expect(routingStateLabel(preview)).toBe("模拟运行中");
    expect(needsQuiescentConfirmation(preview)).toBe(true);
    preview.simulated_revision = 4;
    expect(needsQuiescentConfirmation(preview)).toBe(false);
  });

  it("requires kernel admission confirmation before describing lab routing as running", () => {
    expect(
      routingStateLabel(
        status(2, {
          state: "running",
          active_revision: 2,
          runtime: { admission_live: false },
        }),
      ),
    ).toBe("等待出口确认");
    expect(
      routingStateLabel(
        status(2, {
          state: "running",
          active_revision: 2,
          runtime: { admission_live: true },
        }),
      ),
    ).toBe("测试分流运行中");
  });
  it("allows configured live mode only with actual WAN readiness and a quiescent first arm", () => {
    const draft = new ApplicationRoutingDraft();
    const value = status(1, { mode: "live", runtime: { armed: false } });
    draft.acceptMutation(value);
    expect(modeAllowsEditing(value)).toBe(true);
    expect(needsQuiescentConfirmation(value)).toBe(true);
    expect(applyBlockReason(draft, false)).toContain("首次");
    expect(applyBlockReason(draft, true)).toBeNull();
    value.lines[0].ready = false;
    expect(applyBlockReason(draft, true)).toContain("尚未就绪");
    value.lines[0].ready = true;
    value.runtime = { armed: true, admission_live: true };
    value.state = "running";
    value.active_revision = 1;
    expect(routingStateLabel(value)).toBe("应用分流运行中");
  });
});
