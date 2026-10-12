<template>
  <div class="page">
    <h1>{{ $t("status.title") }}</h1>
    <cv-button :disabled="loading" @click="refresh">{{
      $t("c.refresh")
    }}</cv-button>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
    />
    <template v-if="status">
      <p v-if="!status.role">{{ $t("c.notConfigured") }}</p>
      <dl v-else>
        <dt>{{ $t("c.role") }}</dt>
        <dd>{{ status.role === "hub" ? $t("c.hub") : $t("c.member") }}</dd>
        <dt>{{ $t("c.hubUrl") }}</dt>
        <dd>
          <code>{{ status.hub_url }}</code>
        </dd>
        <dt>{{ $t("c.apiConnection") }}</dt>
        <dd>{{ status.lapi === "ok" ? $t("c.ready") : status.lapi }}</dd>
        <template v-if="status.role === 'hub'">
          <dt>{{ $t("c.activeBans") }}</dt>
          <dd>{{ status.active_bans }}</dd>
          <dt>{{ $t("c.membersCount") }}</dt>
          <dd>{{ status.members }}</dd>
        </template>
        <dt>{{ $t("c.sources") }}</dt>
        <dd>
          <ul>
            <li>SSH</li>
            <li v-for="(modules, kind) in status.sources" :key="kind">
              {{ $t("c.kind." + kind) }}: {{ modules.join(", ") }}
            </li>
          </ul>
        </dd>
        <dt>{{ $t("c.services") }}</dt>
        <dd>
          <ul>
            <li v-for="(state, name) in status.services" :key="name">
              {{ name }}: {{ state }}
            </li>
          </ul>
        </dd>
      </dl>
    </template>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "Status",
  mixins: [task],
  data: () => ({ loading: false, error: "", status: null }),
  created() {
    this.refresh();
  },
  methods: {
    async refresh() {
      this.loading = true;
      this.error = "";
      try {
        this.status = await this.task("get-status");
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
<style scoped>
.page {
  max-width: 1050px;
}
h1 {
  margin-bottom: 1rem;
}
dl {
  margin: 2rem 0;
  display: grid;
  grid-template-columns: 14rem 1fr;
  gap: 0.6rem;
}
</style>
