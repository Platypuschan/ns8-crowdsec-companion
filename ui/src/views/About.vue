<template>
  <div>
    <h1>CrowdSec Companion</h1>
    <p>{{ $t("c.intro") }}</p>
    <p>{{ $t("c.aboutSources") }}</p>
    <p>{{ $t("c.aboutCloud") }}</p>
    <p>
      <a
        href="https://github.com/Platypuschan/ns8-crowdsec-companion"
        target="_blank"
        rel="noopener noreferrer"
        >{{ $t("c.documentation") }}</a
      >
    </p>
    <img :src="defaultLogo" width="96" height="96" alt="CrowdSec Companion" />
  </div>
</template>
<script>
import defaultLogo from "../assets/module_default_logo.png";

export default {
  name: "About",
  data() {
    return { defaultLogo };
  },
};
</script>
<style scoped>
p,
h1 {
  margin-bottom: 1rem;
}
</style>
