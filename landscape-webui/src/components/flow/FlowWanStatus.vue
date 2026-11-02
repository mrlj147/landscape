<script setup lang="ts">
import { computed, onMounted, onUnmounted } from "vue";
import { useI18n } from "vue-i18n";
import { useFailoverStore } from "@/stores/failover";
const props = defineProps<{ flowId: number }>();
const { t } = useI18n();
const store = useFailoverStore();
onMounted(store.subscribe);
onUnmounted(store.unsubscribe);
const rows = computed(() =>
  store.statuses.filter((row) => row.flow_id === props.flowId),
);
function name(id: string | null | undefined, row: (typeof rows.value)[number]) {
  if (!id) return t("flow.failover.no_exit");
  return row.candidates.find((c) => c.link_id === id)?.iface_name || id;
}
</script>
<template>
  <n-flex vertical size="small" style="width: 100%">
    <n-text v-if="store.unavailable" type="warning">{{
      t("flow.failover.status_unavailable")
    }}</n-text>
    <n-flex v-for="row in rows" :key="String(row.ipv6)" vertical size="small">
      <n-space align="center">
        <n-tag size="small">{{ row.ipv6 ? "IPv6" : "IPv4" }}</n-tag>
        <n-text strong
          >{{ t("flow.failover.active") }}:
          {{ row.active_iface_name || t("flow.failover.no_exit") }}</n-text
        >
        <n-text depth="3">{{ t(`flow.failover.reason.${row.reason}`) }}</n-text>
        <n-text v-if="row.retry_after_secs != null" depth="3">{{
          t("flow.failover.remaining", { seconds: row.retry_after_secs })
        }}</n-text>
      </n-space>
      <n-collapse v-if="row.history.length">
        <n-collapse-item
          :title="t('flow.failover.history')"
          :name="String(row.ipv6)"
        >
          <n-flex
            v-for="(event, index) in [...row.history].reverse()"
            :key="index"
            size="small"
          >
            <n-text depth="3">{{
              new Date(event.at_ms).toLocaleString()
            }}</n-text>
            <n-text
              >{{ name(event.previous, row) }} →
              {{ name(event.active, row) }}</n-text
            >
            <n-text depth="3">{{
              t(`flow.failover.reason.${event.reason}`)
            }}</n-text>
          </n-flex>
        </n-collapse-item>
      </n-collapse>
    </n-flex>
  </n-flex>
</template>
