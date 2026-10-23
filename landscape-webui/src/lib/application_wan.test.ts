import { describe, expect, it } from "vitest";
import { ApplicationRoutingDraft, applyBlockReason, saveBlockReason } from "./application_routing";
import type { ApplicationRoutingStatus } from "./application_routing";

function status(count: number): ApplicationRoutingStatus {
  return {
    mode: "preview", state: "stopped", message: "", saved_revision: 0,
    active_revision: null, simulated_revision: null, catalog_total: 3326,
    clients: ["192.0.2.69"], wan_source: "landscape", wan_source_error: null,
    lines: Array.from({ length: count }, (_, i) => ({
      id: `wan-uuid-${i}`, name: ["家庭光纤", "企业出口", "5G 备用"][i]!,
      flow_id: i + 1, wan_ifname: `wan${i}`, ready: false,
    })),
    policy: { revision: 0, rules: [] }, runtime: null,
  };
}

describe("native WAN selection", () => {
  it("does not create a rule or simulate an invented exit when no WAN exists", () => {
    const draft = new ApplicationRoutingDraft();
    draft.acceptMutation(status(0));
    expect(draft.add(2550017, "")).toBe(false);
    expect(draft.rules).toEqual([]);
    expect(applyBlockReason(draft, true)).toContain("尚未配置 WAN");
  });

  it("preserves a third WAN selection across renames and marks deletion as invalid", () => {
    const draft = new ApplicationRoutingDraft();
    const initial = status(3);
    draft.acceptMutation(initial);
    expect(draft.add(2550017, initial.lines[2]!.id)).toBe(true);
    expect(saveBlockReason(draft)).toBeNull();
    const saved = { ...initial, saved_revision: 1,
      policy: { revision: 1, rules: draft.rules.map(rule => ({ ...rule })) } };
    draft.acceptMutation(saved);
    const renamed = structuredClone(saved);
    renamed.lines[2]!.name = "备用出口新名称";
    draft.acceptRead(draft.beginRead(), renamed);
    expect(draft.rules[0]!.line_id).toBe("wan-uuid-2");
    expect(applyBlockReason(draft, true)).toBeNull();
    renamed.lines = renamed.lines.slice(0, 2);
    draft.acceptRead(draft.beginRead(), renamed);
    expect(saveBlockReason(draft)).toContain("已不存在");
    expect(applyBlockReason(draft, true)).toContain("已不存在");
    draft.update(2550017, { line_id: renamed.lines[0]!.id });
    expect(saveBlockReason(draft)).toBeNull();
  });

  it("blocks saving when the native WAN source cannot be read", () => {
    const draft = new ApplicationRoutingDraft();
    const failed = status(0);
    failed.wan_source_error = "无法读取当前 WAN 配置";
    draft.acceptMutation(failed);
    expect(saveBlockReason(draft)).toBe(failed.wan_source_error);
  });
});
