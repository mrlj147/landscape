export interface ApplicationRule {
  appid: number;
  line_id: string;
  learn_endpoint: boolean;
  allow_udp_endpoint_hints: boolean;
}

export interface ApplicationLine {
  id: string;
  name: string;
  flow_id: number | null;
  wan_ifname: string;
  ready: boolean;
  reason?: string;
  enabled?: boolean;
  configured_ready?: boolean;
}

export interface ApplicationEntry {
  appid: number;
  name: string;
  translations: string[];
  category_path?: string[];
  domains?: string[];
  domain_patterns?: string[];
  ips?: string[];
  cidrs?: string[];
  endpoint_counts?: Record<string, number>;
  rule_count?: number;
}

export interface ApplicationRoutingStatus {
  mode: string;
  state: "stopped" | "running" | "error" | "unavailable";
  message: string;
  saved_revision: number;
  active_revision: number | null;
  simulated_revision?: number | null;
  last_applied_revision?: number | null;
  runtime_unverified?: boolean;
  catalog_total: number;
  clients: string[];
  lines: ApplicationLine[];
  wan_source?: "landscape" | "fixture";
  wan_source_error?: string | null;
  policy: { revision: number; rules: ApplicationRule[] };
  runtime: {
    armed?: boolean;
    admission_live?: boolean;
    pinned_connections?: unknown[];
    pinned_connection_count?: number;
    [key: string]: unknown;
  } | null;
}

export interface ApplicationCatalog {
  items: ApplicationEntry[];
  total: number;
  offset: number;
  limit: number;
}

function cloneRules(rules: ApplicationRule[]): ApplicationRule[] {
  return rules.map((rule) => ({ ...rule }));
}

function signature(rules: ApplicationRule[]): string {
  return JSON.stringify(
    cloneRules(rules)
      .sort((a, b) => a.appid - b.appid)
      .map((rule) => [
        rule.appid,
        rule.line_id,
        rule.learn_endpoint,
        rule.allow_udp_endpoint_hints,
      ]),
  );
}

/** An in-flight status read must never erase a newer local edit or save. */
export class ApplicationRoutingDraft {
  status: ApplicationRoutingStatus | null = null;
  runtimeUnconfirmed = false;
  rules: ApplicationRule[] = [];
  expectedRevision = 0;
  private savedSignature = signature([]);
  private editEpoch = 0;
  private readSequence = 0;

  get dirty(): boolean {
    return signature(this.rules) !== this.savedSignature;
  }

  get conflict(): boolean {
    return (
      this.status !== null &&
      this.status.saved_revision !== this.expectedRevision
    );
  }

  beginRead() {
    return { sequence: ++this.readSequence, editEpoch: this.editEpoch };
  }

  async refreshStatus(
    read: () => Promise<ApplicationRoutingStatus>,
    isCurrent = () => true,
  ): Promise<boolean> {
    const ticket = this.beginRead();
    try {
      const status = await read();
      return isCurrent() && this.acceptRead(ticket, status);
    } catch (error) {
      if (isCurrent() && ticket.sequence === this.readSequence)
        this.markRuntimeUnconfirmed();
      throw error;
    }
  }

  acceptRead(
    ticket: { sequence: number; editEpoch: number },
    status: ApplicationRoutingStatus,
  ): boolean {
    if (ticket.sequence !== this.readSequence) return false;
    const canReload = !this.dirty && ticket.editEpoch === this.editEpoch;
    this.status = status;
    this.runtimeUnconfirmed = false;
    if (canReload) this.loadRules(status);
    return true;
  }

  acceptMutation(
    status: ApplicationRoutingStatus,
    preserveLocalEdits = false,
  ): void {
    const keepEdits = preserveLocalEdits && this.dirty;
    ++this.readSequence;
    this.status = status;
    this.runtimeUnconfirmed = false;
    if (!keepEdits) this.loadRules(status);
  }

  markRuntimeUnconfirmed(): void {
    ++this.readSequence;
    this.runtimeUnconfirmed = true;
  }

  reloadSaved(): void {
    if (this.status) {
      ++this.readSequence;
      ++this.editEpoch;
      this.loadRules(this.status);
    }
  }

  private loadRules(status: ApplicationRoutingStatus): void {
    this.rules = cloneRules(status.policy.rules);
    this.expectedRevision = status.policy.revision;
    this.savedSignature = signature(this.rules);
  }

  add(appid: number, lineId: string): boolean {
    if (!lineId) return false;
    if (this.rules.some((rule) => rule.appid === appid)) return false;
    this.rules.push({
      appid,
      line_id: lineId,
      learn_endpoint: true,
      allow_udp_endpoint_hints: false,
    });
    ++this.editEpoch;
    return true;
  }

  update(appid: number, change: Partial<Omit<ApplicationRule, "appid">>): void {
    const rule = this.rules.find((item) => item.appid === appid);
    if (!rule) return;
    Object.assign(rule, change);
    if (!rule.learn_endpoint) rule.allow_udp_endpoint_hints = false;
    ++this.editEpoch;
  }

  remove(appid: number): void {
    this.rules = this.rules.filter((rule) => rule.appid !== appid);
    ++this.editEpoch;
  }
}

export function modeAllowsEditing(
  status: ApplicationRoutingStatus | null,
): boolean {
  return ["preview", "lab", "live"].includes(status?.mode ?? "");
}

export function needsQuiescentConfirmation(
  status: ApplicationRoutingStatus | null,
): boolean {
  if (!status) return false;
  if (status.mode === "preview") return status.simulated_revision == null;
  return ["lab", "live"].includes(status.mode) && status.runtime?.armed !== true;
}

export function saveBlockReason(draft: ApplicationRoutingDraft): string | null {
  if (!draft.status) return "正在读取配置";
  if (!modeAllowsEditing(draft.status)) return "生产环境尚未验收，已禁止修改";
  if (draft.runtimeUnconfirmed || draft.status.runtime_unverified) {
    return "运行状态尚未确认，请先重试停止并核对状态";
  }
  if (draft.conflict) return "服务器草稿已更新，请重新载入后编辑";
  if (draft.status.wan_source_error) return draft.status.wan_source_error;
  if (draft.rules.some((rule) => !draft.status!.lines.some((line) => line.id === rule.line_id)))
    return "所选 WAN 已不存在，请重新选择出口或移除对应规则";
  return null;
}

export function canStopPolicy(
  status: ApplicationRoutingStatus | null,
  locallyUnconfirmed = false,
): boolean {
  return (
    modeAllowsEditing(status) &&
    !!status &&
    (status.state === "running" ||
      status.runtime_unverified === true ||
      locallyUnconfirmed)
  );
}

export function applyBlockReason(
  draft: ApplicationRoutingDraft,
  confirmedQuiescent: boolean,
): string | null {
  const status = draft.status;
  if (!status) return "正在读取配置";
  const saveReason = saveBlockReason(draft);
  if (saveReason) return saveReason;
  if (status.state === "unavailable") return status.message || "控制服务不可用";
  if (draft.conflict) return "服务器草稿已更新，请重新载入后编辑";
  if (draft.dirty) return "请先保存草稿，再应用已保存的版本";
  if (!status.lines.length) return "尚未配置 WAN，请先添加实际的 WAN 线路";
  for (const rule of draft.rules) {
    const line = status.lines.find((item) => item.id === rule.line_id);
    if (!line) return "所选线路已不存在，请重新选择出口";
    if (status.mode !== "preview" && !line.ready)
      return `${line?.name || rule.line_id || "所选线路"}尚未就绪`;
    if (rule.allow_udp_endpoint_hints && !rule.learn_endpoint)
      return "UDP 学习需要先开启目标地址学习";
  }
  if (needsQuiescentConfirmation(status) && !confirmedQuiescent) {
    return status.mode === "preview"
      ? "请确认使用没有活动连接的模拟客户端"
      : "首次应用前，请确认指定客户端没有活动连接";
  }
  return null;
}

/** Preview responses can never be described as an applied physical route. */
export function routingStateLabel(
  status: ApplicationRoutingStatus | null,
  locallyUnconfirmed = false,
): string {
  if (locallyUnconfirmed) return "运行状态待确认";
  if (!status) return "读取中";
  if (status.mode === "preview") {
    if (status.state === "error") return "模拟出错";
    if (status.state === "running") return "模拟运行中";
    return "模拟已停止";
  }
  if (!["lab", "live"].includes(status.mode)) return "未支持的运行模式";
  if (status.runtime_unverified) return "运行状态待确认";
  if (
    status.state === "running" &&
    status.active_revision !== null &&
    status.runtime?.admission_live === true
  )
    return status.mode === "live" ? "应用分流运行中" : "测试分流运行中";
  if (status.state === "running") return "等待出口确认";
  if (status.state === "error") return "运行异常";
  if (status.state === "unavailable") return "分流服务不可用";
  return "分流已停止";
}

export function routingCurrentRevision(
  status: ApplicationRoutingStatus | null,
  locallyUnconfirmed = false,
): number | null | undefined | "未确认" {
  if (locallyUnconfirmed || status?.runtime_unverified) return "未确认";
  return status?.mode === "preview"
    ? status.simulated_revision
    : status?.active_revision;
}

export function apiErrorMessage(error: unknown): string {
  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof error.message === "string"
  )
    return error.message;
  return "请求失败，请检查控制服务后重试。当前编辑已保留。";
}
