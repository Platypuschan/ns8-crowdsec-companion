<template>
  <div class="page">
    <h1>{{ $t("bans.title") }}</h1>
    <p>{{ $t("c.bansHelp") }}</p>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
      @close="error = ''"
    />
    <cv-inline-notification
      v-if="notHub"
      kind="info"
      :title="$t('c.hubOnly')"
    />
    <template v-else>
      <div class="toolbar">
        <cv-button
          kind="danger"
          size="small"
          :disabled="busy || !selected.length"
          @click="unban"
          >{{ $t("c.unban") }} ({{ selected.length }})</cv-button
        >
        <cv-button kind="ghost" size="small" :disabled="busy" @click="load">{{
          $t("c.refresh")
        }}</cv-button>
        <cv-text-input v-model="search" :label="$t('c.search')" />
      </div>
      <div class="table-scroll">
        <table class="bx--data-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  :aria-label="$t('c.selectAll')"
                  :checked="allSelected"
                  @change="selectAll($event.target.checked)"
                />
              </th>
              <th>IP</th>
              <th>{{ $t("c.reason") }}</th>
              <th>{{ $t("c.detectedBy") }}</th>
              <th>{{ $t("c.country") }}</th>
              <th>{{ $t("c.remaining") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in visible" :key="d.id">
              <td>
                <input
                  type="checkbox"
                  :aria-label="d.ip"
                  :checked="selected.includes(d.ip)"
                  @change="toggle(d.ip, $event.target.checked)"
                />
              </td>
              <td>
                <code>{{ d.ip }}</code>
              </td>
              <td>{{ d.scenario }}</td>
              <td>{{ d.machine || d.origin }}</td>
              <td>{{ d.country || "—" }}</td>
              <td>{{ d.duration || d.until }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="!decisions.length && !busy">{{ $t("c.noBans") }}</p>
    </template>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "Bans",
  mixins: [task],
  data: () => ({
    busy: false,
    error: "",
    notHub: false,
    decisions: [],
    selected: [],
    search: "",
  }),
  computed: {
    visible() {
      const q = this.search.trim().toLowerCase();
      return q
        ? this.decisions.filter((d) =>
            (d.ip + " " + d.scenario + " " + d.machine)
              .toLowerCase()
              .includes(q)
          )
        : this.decisions;
    },
    allSelected() {
      return (
        this.visible.length > 0 &&
        this.visible.every((d) => this.selected.includes(d.ip))
      );
    },
  },
  created() {
    this.load();
  },
  methods: {
    toggle(ip, on) {
      this.selected = on
        ? [...new Set([...this.selected, ip])]
        : this.selected.filter((x) => x !== ip);
    },
    selectAll(on) {
      this.selected = on ? [...new Set(this.visible.map((d) => d.ip))] : [];
    },
    async load() {
      this.busy = true;
      try {
        const config = await this.task("get-configuration");
        this.notHub = config.role !== "hub";
        if (!this.notHub) {
          this.decisions = (await this.task("list-decisions")).decisions;
          const present = new Set(this.decisions.map((d) => d.ip));
          this.selected = this.selected.filter((ip) => present.has(ip));
        }
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
    async unban() {
      this.busy = true;
      try {
        await this.task("unban", { addresses: this.selected });
        this.selected = [];
        await this.load();
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
  },
};
</script>
<style scoped>
.page {
  max-width: 1050px;
}
h1,
p {
  margin-bottom: 1rem;
}
.toolbar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  margin-bottom: 1rem;
}
.table-scroll {
  overflow-x: auto;
}
</style>
