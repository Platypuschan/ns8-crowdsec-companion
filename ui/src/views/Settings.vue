<template>
  <div class="page">
    <h1>{{ $t("settings.title") }}</h1>
    <p class="intro">{{ $t("c.intro") }}</p>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
      @close="error = ''"
    />
    <cv-inline-notification
      v-if="success"
      kind="success"
      :title="success"
      @close="success = ''"
    />
    <cv-loading v-if="loading" :active="true" />
    <template v-if="loaded">
      <section>
        <h2>{{ $t("c.role") }}</h2>
        <p>{{ $t("c.roleHelp") }}</p>
        <cv-radio-group vertical>
          <cv-radio-button
            v-model="form.role"
            name="role"
            value="hub"
            :label="$t('c.hub')"
            :disabled="configured || busy"
          />
          <cv-radio-button
            v-model="form.role"
            name="role"
            value="member"
            :label="$t('c.member')"
            :disabled="configured || busy"
          />
        </cv-radio-group>
        <p v-if="configured" class="hint">{{ $t("c.roleFixed") }}</p>
      </section>
      <section v-if="form.role === 'hub'">
        <h2>{{ $t("c.hubSettings") }}</h2>
        <cv-text-input
          v-model="form.hub_host"
          :label="$t('c.hubHost')"
          placeholder="crowdsec.example.org"
          :helper-text="$t('c.hubHostHelp')"
          :invalid-message="fieldError('hub_host')"
        />
        <cv-toggle v-model="form.lets_encrypt" :label="$t('c.letsEncrypt')">
          <template slot="text-left">{{ $t("c.disabled") }}</template>
          <template slot="text-right">{{ $t("c.enabled") }}</template>
        </cv-toggle>
      </section>
      <section v-if="form.role === 'member'">
        <h2>{{ $t("c.memberSettings") }}</h2>
        <p v-if="config.hub_url">
          {{ $t("c.connectedTo") }} <code>{{ config.hub_url }}</code>
          <span v-if="config.member_name">
            ({{ $t("c.as") }} <code>{{ config.member_name }}</code
            >)</span
          >
        </p>
        <cv-text-area
          v-model="form.token"
          :label="$t('c.token')"
          :helper-text="configured ? $t('c.tokenKeep') : $t('c.tokenHelp')"
          :invalid-message="fieldError('token')"
          :rows="3"
        />
        <cv-checkbox
          v-model="form.insecure_skip_verify"
          value="insecure"
          :label="$t('c.insecure')"
        />
      </section>
      <section v-if="form.role">
        <h2>{{ $t("c.protection") }}</h2>
        <cv-text-input
          v-model="form.ban_duration"
          :label="$t('c.banDuration')"
          :helper-text="$t('c.banDurationHelp')"
          :invalid-message="fieldError('ban_duration')"
        />
        <cv-text-area
          v-model="allowlist"
          :label="$t('c.allowlist')"
          :helper-text="
            form.role === 'hub'
              ? $t('c.allowlistHelp')
              : $t('c.allowlistMember')
          "
          :invalid-message="fieldError('allowlist')"
          :disabled="form.role !== 'hub'"
          :rows="4"
          placeholder="192.0.2.0/24&#10;2001:db8::/48"
        />
        <cv-toggle v-model="form.samba_audit" :label="$t('c.sambaAudit')">
          <template slot="text-left">{{ $t("c.disabled") }}</template>
          <template slot="text-right">{{ $t("c.enabled") }}</template>
        </cv-toggle>
        <p class="hint">{{ $t("c.sambaAuditHelp") }}</p>
      </section>
      <cv-button :disabled="busy || !form.role" @click="save">{{
        $t("c.save")
      }}</cv-button>
    </template>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "Settings",
  mixins: [task],
  data: () => ({
    loading: true,
    loaded: false,
    busy: false,
    error: "",
    success: "",
    errors: {},
    config: {},
    allowlist: "",
    form: {
      role: "",
      hub_host: "",
      lets_encrypt: true,
      token: "",
      insecure_skip_verify: false,
      ban_duration: "4h",
      samba_audit: true,
    },
  }),
  computed: {
    configured() {
      return !!this.config.role;
    },
  },
  created() {
    this.load();
  },
  methods: {
    fieldError(field) {
      return this.errors[field] ? this.$t("c.err." + this.errors[field]) : "";
    },
    async load() {
      this.loading = true;
      try {
        this.config = await this.task("get-configuration");
        Object.keys(this.form).forEach((key) => {
          if (key in this.config) this.form[key] = this.config[key];
        });
        this.form.token = "";
        this.allowlist = (this.config.allowlist || []).join("\n");
        this.loaded = true;
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
    async save() {
      this.busy = true;
      this.error = "";
      this.success = "";
      this.errors = {};
      const data = {
        role: this.form.role,
        ban_duration: this.form.ban_duration.trim(),
        samba_audit: this.form.samba_audit,
        allowlist: this.allowlist
          .split(/[\s,]+/)
          .map((v) => v.trim())
          .filter((v) => v),
      };
      if (this.form.role === "hub") {
        data.hub_host = this.form.hub_host.trim();
        data.lets_encrypt = this.form.lets_encrypt;
      } else {
        data.insecure_skip_verify = !!this.form.insecure_skip_verify;
        if (this.form.token.trim()) data.token = this.form.token.trim();
      }
      try {
        await this.task("configure-module", data);
        this.success = this.$t("c.saved");
        await this.load();
      } catch (e) {
        this.parseValidation(e);
      } finally {
        this.busy = false;
      }
    },
    parseValidation(e) {
      if (e.validation && e.validation.length) {
        e.validation.forEach((v) =>
          this.$set(this.errors, v.field || v.parameter, v.error)
        );
        return;
      }
      this.error = e.message;
    },
  },
};
</script>
<style scoped>
.page {
  max-width: 900px;
}
h1,
h2,
.intro {
  margin-bottom: 1rem;
}
section {
  margin: 2rem 0;
}
section > * {
  margin-bottom: 1rem;
}
.hint {
  color: #6f6f6f;
}
</style>
