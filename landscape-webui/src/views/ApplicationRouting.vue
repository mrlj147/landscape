<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useDialog, useMessage } from "naive-ui";
import {
  applyApplicationPolicy,
  getApplicationCatalog,
  getApplicationRoutingStatus,
  saveApplicationPolicy,
  stopApplicationPolicy,
} from "@/api/application-routing";
import {
  ApplicationRoutingDraft,
  apiErrorMessage,
  applyBlockReason,
  canStopPolicy,
  modeAllowsEditing,
  needsQuiescentConfirmation,
  routingCurrentRevision,
  routingStateLabel,
  saveBlockReason,
} from "@/lib/application_routing";
import type {
  ApplicationEntry,
  ApplicationRoutingStatus,
} from "@/lib/application_routing";

const draft = reactive(new ApplicationRoutingDraft());
const message = useMessage();
const dialog = useDialog();
const error = ref("");
const catalogError = ref("");
const busy = ref<"" | "save" | "apply" | "stop">("");
const loading = ref(false);
const search = ref("");
const page = ref(1);
const pageSize = 20;
const policyPage = ref(1);
const policyPageSize = 20;
const visibleRules = computed(() => draft.rules.slice((policyPage.value - 1) * policyPageSize, policyPage.value * policyPageSize));
const total = ref(0);
const catalogLoading = ref(false);
const entries = ref<ApplicationEntry[]>([]);
const names = reactive<Record<number, ApplicationEntry>>({});
const quiescent = ref(false);
let searchSequence = 0;
let statusSequence = 0;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;
let disposed = false;

const status = computed(() => draft.status);
const preview = computed(() => status.value?.mode === "preview");
const editable = computed(() => modeAllowsEditing(status.value));
const controlsDisabled = computed(() => !editable.value || !!busy.value);
const runtimeUnconfirmed = computed(
  () => draft.runtimeUnconfirmed || status.value?.runtime_unverified === true,
);
const saveReason = computed(() =>
  saveBlockReason(draft as ApplicationRoutingDraft),
);
const applyReason = computed(() =>
  applyBlockReason(draft as ApplicationRoutingDraft, quiescent.value),
);
const lineOptions = computed(() =>
  (status.value?.lines ?? []).map((line) => ({
    label: line.name,
    value: line.id,
  })),
);
const selectedIds = computed(
  () => new Set(draft.rules.map((rule) => rule.appid)),
);
const currentRevision = computed(() =>
  routingCurrentRevision(status.value, draft.runtimeUnconfirmed),
);
const stateLabel = computed(() =>
  routingStateLabel(status.value, runtimeUnconfirmed.value),
);
const needQuiescent = computed(() => needsQuiescentConfirmation(status.value));

function remember(items: ApplicationEntry[]) {
  for (const item of items) names[item.appid] = item;
}

async function resolveSelectedNames() {
  const missing = visibleRules.value.filter((rule) => !names[rule.appid]);
  // Bounded requests also allow a large saved policy to remain responsive.
  for (let start = 0; start < missing.length && !disposed; start += 4) {
    await Promise.all(
      missing.slice(start, start + 4).map(async (rule) => {
        try {
          const result = await getApplicationCatalog(
            String(rule.appid),
            0,
            100,
          );
          if (!disposed) remember(result.items);
        } catch {
          /* Numeric AppID remains usable when a name lookup fails. */
        }
      }),
    );
  }
}

async function refreshStatus() {
  const sequence = ++statusSequence;
  loading.value = true;
  error.value = "";
  try {
    if (
      await draft.refreshStatus(
        getApplicationRoutingStatus,
        () => !disposed && sequence === statusSequence,
      )
    )
      void resolveSelectedNames();
  } catch (cause) {
    if (!disposed && sequence === statusSequence)
      error.value = apiErrorMessage(cause);
  } finally {
    if (!disposed && sequence === statusSequence) loading.value = false;
  }
}

async function refreshCatalog() {
  const sequence = ++searchSequence;
  catalogLoading.value = true;
  catalogError.value = "";
  try {
    const result = await getApplicationCatalog(
      search.value.trim(),
      (page.value - 1) * pageSize,
      pageSize,
    );
    if (disposed || sequence !== searchSequence) return;
    entries.value = result.items;
    total.value = result.total;
    remember(result.items);
  } catch (cause) {
    if (!disposed && sequence === searchSequence)
      catalogError.value = apiErrorMessage(cause);
  } finally {
    if (!disposed && sequence === searchSequence) catalogLoading.value = false;
  }
}

watch(search, () => {
  ++searchSequence;
  if (debounceTimer) clearTimeout(debounceTimer);
  page.value = 1;
  debounceTimer = setTimeout(() => void refreshCatalog(), 250);
});

watch(policyPage, () => void resolveSelectedNames());
watch(() => draft.rules.length, (count) => { policyPage.value = Math.min(policyPage.value, Math.max(1, Math.ceil(count / policyPageSize))); });

function changePage(value: number) {
  page.value = value;
  void refreshCatalog();
}
function addApplication(entry: ApplicationEntry) {
  if (controlsDisabled.value) return;
  remember([entry]);
  if (draft.add(entry.appid, status.value?.lines[0]?.id ?? "")) policyPage.value = Math.ceil(draft.rules.length / policyPageSize);
}

function reloadSaved() {
  const reload = () => {
    draft.reloadSaved();
    quiescent.value = false;
    void resolveSelectedNames();
  };
  if (!draft.dirty) {
    reload();
    return;
  }
  dialog.warning({
    title: "重新载入已保存草稿",
    content: "这会放弃当前页面尚未保存的编辑。",
    positiveText: "重新载入",
    negativeText: "保留编辑",
    onPositiveClick: reload,
  });
}

async function mutate(
  kind: "save" | "apply" | "stop",
  action: () => Promise<ApplicationRoutingStatus>,
) {
  if (busy.value || !editable.value) return;
  ++statusSequence;
  loading.value = false;
  busy.value = kind;
  error.value = "";
  try {
    const result = await action();
    if (disposed) return;
    draft.acceptMutation(result, kind === "stop");
    quiescent.value = false;
    if (kind === "save")
      message.success("草稿已保存。需要点击应用才会进入对应运行状态。");
    else if (result.mode === "preview")
      message.info(
        kind === "apply"
          ? "模拟应用完成，未接触任何真实网络。"
          : "模拟已停止，未改动真实网络。",
      );
    else if (kind === "stop")
      message.info("已停止接纳新的应用分流，已有连接保留原出口。");
    else if (
      result.state === "running" &&
      result.active_revision === result.saved_revision &&
      result.runtime?.admission_live
    )
      message.success("内核已确认应用此版本。");
    else
      message.warning(result.message || "请求已返回，尚未确认测试分流生效。");
  } catch (cause) {
    if (!disposed) {
      error.value = apiErrorMessage(cause);
      if (kind !== "save") {
        draft.markRuntimeUnconfirmed();
        const ticket = draft.beginRead();
        try {
          const current = await getApplicationRoutingStatus();
          if (!disposed) draft.acceptRead(ticket, current);
        } catch {
          if (!disposed)
            error.value += " 运行状态也未能确认，请刷新状态后再操作。";
        }
      }
    }
  } finally {
    if (!disposed) busy.value = "";
  }
}

function save() {
  if (saveReason.value) {
    error.value = saveReason.value;
    return;
  }
  const rules = draft.rules.map((rule) => ({ ...rule }));
  void mutate("save", () =>
    saveApplicationPolicy(draft.expectedRevision, rules),
  );
}

function apply() {
  if (applyReason.value) {
    error.value = applyReason.value;
    return;
  }
  void mutate("apply", () =>
    applyApplicationPolicy(draft.expectedRevision, quiescent.value),
  );
}

function stop() {
  if (!canStopPolicy(status.value, draft.runtimeUnconfirmed)) return;
  void mutate("stop", stopApplicationPolicy);
}

onMounted(() => {
  void refreshStatus();
  void refreshCatalog();
});
onUnmounted(() => {
  disposed = true;
  ++searchSequence;
  if (debounceTimer) clearTimeout(debounceTimer);
});
</script>

<template>
  <n-layout :native-scrollbar="false" content-style="padding: 18px;">
    <n-space vertical :size="16" class="application-routing">
      <div class="page-heading">
        <div>
          <h2>应用分流</h2>
          <n-text depth="3">选择应用，为后续新连接指定电信或联通出口。</n-text>
        </div>
        <n-button :loading="loading" :disabled="!!busy" @click="refreshStatus"
          >刷新状态</n-button
        >
      </div>

      <n-alert
        v-if="preview"
        type="info"
        title="Mac 离线预览 · 不接触真实网络"
        :bordered="false"
      >
        保存和模拟应用仅更新本地预览数据。这里的线路、运行状态与连接数均不代表家庭网络已分流。
      </n-alert>
      <n-alert
        v-else-if="status?.mode === 'lab'"
        type="warning"
        title="测试机验证环境"
        :bordered="false"
      >
        电信 /
        联通标签当前对应测试出口；真实运营商线路尚未验收。本页不代表家庭网络已迁移。
      </n-alert>
      <n-alert
        v-else-if="status?.mode === 'live'"
        type="info"
        title="已配置的 Linux 应用分流"
        :bordered="false"
      >
        仅作用于下方指定客户端。首次识别连接沿用原出口；启用端点学习后，后续新连接可使用指定线路。已有连接保持原出口；共享 CDN 的端点学习可能误判。
      </n-alert>

      <n-alert
        v-if="error"
        type="error"
        title="操作未完成"
        closable
        @close="error = ''"
        >{{ error }}</n-alert
      >
      <n-alert v-if="draft.conflict" type="warning" title="草稿版本已变化"
        >服务器保存了更新的版本，当前编辑仍保留。请重新载入草稿后继续。</n-alert
      >

      <n-card size="small">
        <n-space justify="space-between" :size="20" align="center">
          <n-space vertical :size="4"
            ><n-text depth="3">{{ preview ? "模拟状态" : "运行状态" }}</n-text
            ><n-text strong>{{ stateLabel }}</n-text></n-space
          >
          <n-space vertical :size="4"
            ><n-text depth="3">已保存版本</n-text
            ><n-text strong
              >{{ status?.saved_revision ?? "—"
              }}{{ draft.dirty ? " · 有未保存编辑" : "" }}</n-text
            ></n-space
          >
          <n-space vertical :size="4"
            ><n-text depth="3">{{
              preview ? "已模拟版本" : "已确认运行版本"
            }}</n-text
            ><n-text strong>{{
              currentRevision ?? "尚未应用"
            }}</n-text></n-space
          >
          <n-space vertical :size="4"
            ><n-text depth="3">{{
              preview ? "模拟客户端" : "适用客户端"
            }}</n-text
            ><n-text>{{ status?.clients.join("、") || "—" }}</n-text></n-space
          >
        </n-space>
        <n-text v-if="status?.message" depth="3" class="status-message">{{
          preview && status.state !== "error" && status.state !== "unavailable"
            ? "仅进行本机离线模拟，不发送真实数据包，不改动网卡、分流状态或系统服务。"
            : status.message
        }}</n-text>
      </n-card>

      <div class="editor-columns">
        <n-card title="添加应用" size="small">
          <template #header-extra
            ><n-tag size="small"
              >应用库 {{ status?.catalog_total ?? "—" }} 项</n-tag
            ></template
          >
          <n-space vertical :size="12">
            <n-input
              v-model:value="search"
              clearable
              placeholder="搜索应用、分类、域名、IP 或 AppID"
              aria-label="搜索应用"
            />
            <n-alert v-if="catalogError" type="error">{{
              catalogError
            }}</n-alert>
            <n-spin :show="catalogLoading">
              <n-empty
                v-if="!entries.length && !catalogLoading"
                description="没有找到匹配的应用"
              />
              <div
                v-for="entry in entries"
                :key="entry.appid"
                class="catalog-row"
              >
                <div class="application-name">
                  <n-text strong>{{ entry.name }}</n-text
                  ><n-text depth="3" class="small-text"
                    >{{ entry.appid
                    }}<template v-if="entry.translations.length">
                      · {{ entry.translations.join(" / ") }}</template
                    ></n-text
                  >
                  <n-text v-if="entry.category_path?.length" depth="3" class="small-text">{{ entry.category_path.join(" / ") }}</n-text>
                  <n-collapse v-if="entry.rule_count !== undefined" class="endpoint-details">
                    <n-collapse-item :title="`规则 ${entry.rule_count} · 域名 ${entry.endpoint_counts?.domains ?? 0} · IP ${entry.endpoint_counts?.ips ?? 0}`" :name="entry.appid">
                      <div v-for="field in (['domains', 'domain_patterns', 'ips', 'cidrs'] as const)" :key="field" class="small-text">
                        <strong>{{ {domains:'域名',domain_patterns:'域名表达式',ips:'IP',cidrs:'网段'}[field] }} ({{ entry.endpoint_counts?.[field] ?? 0 }}): </strong>{{ entry[field]?.join('、') || '未提取到显式条目' }}
                      </div>
                      <n-text depth="3" class="small-text">每类最多显示 16 项；为规则中的显式引用，并非该应用的全部服务器。具体协议匹配由完整规则引擎执行。</n-text>
                    </n-collapse-item>
                  </n-collapse>
                </div>
                <n-button
                  size="small"
                  :disabled="controlsDisabled || selectedIds.has(entry.appid)"
                  @click="addApplication(entry)"
                  >{{
                    selectedIds.has(entry.appid) ? "已添加" : "添加"
                  }}</n-button
                >
              </div>
            </n-spin>
            <n-space justify="space-between" align="center"
              ><n-text depth="3">共 {{ total }} 项</n-text
              ><n-pagination
                :page="page"
                :page-size="pageSize"
                :item-count="total"
                :page-slot="5"
                size="small"
                :disabled="catalogLoading"
                @update:page="changePage"
            /></n-space>
          </n-space>
        </n-card>

        <n-space vertical :size="14">
          <n-card title="应用与出口" size="small">
            <template #header-extra
              ><n-tag size="small"
                >{{ draft.rules.length }} 条草稿规则</n-tag
              ></template
            >
            <n-empty
              v-if="!draft.rules.length"
              description="从应用库添加需要指定出口的应用。空规则沿用默认分流。"
            />
            <div
              v-for="rule in visibleRules"
              :key="rule.appid"
              class="policy-row"
            >
              <div class="policy-title">
                <div class="application-name">
                  <n-text strong>{{
                    names[rule.appid]?.name ?? `应用 #${rule.appid}`
                  }}</n-text
                  ><n-text depth="3" class="small-text"
                    >AppID {{ rule.appid }}</n-text
                  >
                </div>
                <n-button
                  quaternary
                  size="small"
                  :disabled="controlsDisabled"
                  @click="draft.remove(rule.appid)"
                  >移除</n-button
                >
              </div>
              <n-select
                :value="rule.line_id"
                :options="lineOptions"
                :disabled="controlsDisabled"
                :aria-label="`应用 ${rule.appid} 的出口`"
                placeholder="选择出口"
                @update:value="
                  (value: string) =>
                    draft.update(rule.appid, { line_id: value })
                "
              />
              <n-space vertical :size="6" class="rule-options">
                <n-checkbox
                  :checked="rule.learn_endpoint"
                  :disabled="controlsDisabled"
                  @update:checked="
                    (value: boolean) =>
                      draft.update(rule.appid, { learn_endpoint: value })
                  "
                  >允许学习已识别连接的目标地址</n-checkbox
                >
                <n-checkbox
                  :checked="rule.allow_udp_endpoint_hints"
                  :disabled="controlsDisabled || !rule.learn_endpoint"
                  @update:checked="
                    (value: boolean) =>
                      draft.update(rule.appid, {
                        allow_udp_endpoint_hints: value,
                      })
                  "
                  >同时允许 UDP 目标地址学习</n-checkbox
                >
                <n-text v-if="!rule.learn_endpoint" depth="3" class="small-text"
                  >未开启学习时，这条规则不会根据新识别结果为后续连接选线。</n-text
                >
              </n-space>
            </div>
            <n-pagination v-if="draft.rules.length > policyPageSize" v-model:page="policyPage" :page-size="policyPageSize" :item-count="draft.rules.length" :page-slot="5" size="small" />
          </n-card>

          <n-card title="保存与应用" size="small">
            <n-space vertical :size="12">
              <n-text depth="3"
                >仅处理新的 IPv4
                连接；已有连接保持原出口。首次连接通常沿用默认策略，学习到应用后才影响同一客户端到同一目标的新连接。共享
                CDN 目标可能承载多种应用，请按需开启学习。</n-text
              >
              <n-checkbox
                v-if="needQuiescent"
                v-model:checked="quiescent"
                :disabled="controlsDisabled"
                >{{
                  preview
                    ? "确认使用没有活动连接的模拟客户端（不检查真实设备）"
                    : "确认指定客户端当前没有活动连接，允许首次初始化"
                }}</n-checkbox
              >
              <n-space>
                <n-button
                  type="primary"
                  :loading="busy === 'save'"
                  :disabled="controlsDisabled || !!saveReason"
                  @click="save"
                  >保存草稿</n-button
                >
                <n-button
                  type="info"
                  :loading="busy === 'apply'"
                  :disabled="controlsDisabled || !!applyReason"
                  @click="apply"
                  >{{ preview ? "模拟应用" : "应用已保存策略" }}</n-button
                >
                <n-button
                  :loading="busy === 'stop'"
                  :disabled="
                    controlsDisabled ||
                    !canStopPolicy(status, draft.runtimeUnconfirmed)
                  "
                  @click="stop"
                  >{{
                    runtimeUnconfirmed
                      ? "重试停止并核对"
                      : preview
                        ? "停止模拟"
                        : "停止新分流"
                  }}</n-button
                >
                <n-button :disabled="!!busy || !status" @click="reloadSaved"
                  >重新载入草稿</n-button
                >
              </n-space>
              <n-text v-if="applyReason" depth="3">{{ applyReason }}</n-text>
              <n-text v-if="busy" depth="3">{{
                busy === "save"
                  ? "正在保存，请勿重复提交…"
                  : preview
                    ? "正在更新本地模拟状态…"
                    : "正在等待测试控制器确认；请勿重复提交。"
              }}</n-text>
            </n-space>
          </n-card>

          <n-card :title="preview ? '模拟出口' : '测试出口状态'" size="small">
            <n-space vertical :size="10"
              ><div
                v-for="line in status?.lines ?? []"
                :key="line.id"
                class="line-status"
              >
                <n-text>{{ line.name }}</n-text
                ><n-tag
                  size="small"
                  :type="preview || line.ready ? 'info' : 'warning'"
                  >{{
                    preview
                      ? "可模拟 · 未验证真实线路"
                      : line.ready
                        ? "测试出口就绪"
                        : "尚未就绪"
                  }}</n-tag
                ><n-text v-if="line.reason" depth="3">{{
                  preview &&
                  line.reason === "Preview has no real WAN readiness check"
                    ? "此出口可用于模拟选线，尚未连接或验证真实电信、联通线路。"
                    : line.reason
                }}</n-text>
              </div></n-space
            >
            <n-text
              v-if="
                !preview &&
                status?.runtime?.pinned_connection_count !== undefined
              "
              depth="3"
              class="status-message"
              >已有固定出口连接：{{
                status.runtime.pinned_connection_count
              }}</n-text
            >
          </n-card>
        </n-space>
      </div>
    </n-space>
  </n-layout>
</template>

<style scoped>
.application-routing {
  max-width: 1480px;
  margin: 0 auto;
}
.page-heading,
.policy-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
h2 {
  margin: 0 0 6px;
  font-size: 22px;
}
.editor-columns {
  display: grid;
  grid-template-columns: minmax(300px, 0.9fr) minmax(380px, 1.3fr);
  gap: 16px;
  align-items: start;
}
.catalog-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 0;
  border-bottom: 1px solid var(--n-border-color);
}
.application-name {
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow-wrap: anywhere;
}
.small-text {
  font-size: 12px;
}
.policy-row + .policy-row {
  border-top: 1px solid var(--n-border-color);
  padding-top: 16px;
}
.policy-row {
  padding-bottom: 16px;
}
.policy-title {
  margin-bottom: 10px;
}
.rule-options {
  margin-top: 10px;
}
.status-message {
  display: block;
  margin-top: 12px;
}
.line-status {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
@media (max-width: 950px) {
  .editor-columns {
    grid-template-columns: 1fr;
  }
}
</style>
