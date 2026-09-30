<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const a = computed(() => store.result?.assessment)
const hasContent = computed(() =>
  !!a.value && (a.value.reasons_malicious.length > 0 || a.value.reasons_legitimate.length > 0 || !!a.value.method),
)
</script>

<template>
  <div v-if="a && hasContent" class="card">
    <div class="cols">
      <div v-if="a.reasons_malicious.length" class="col bad">
        <h4>Arguments pour une menace réelle</h4>
        <ul><li v-for="(x, i) in a.reasons_malicious" :key="i">{{ x }}</li></ul>
      </div>
      <div v-if="a.reasons_legitimate.length" class="col good">
        <h4>Arguments pour un faux positif / fichier légitime</h4>
        <ul><li v-for="(x, i) in a.reasons_legitimate" :key="i">{{ x }}</li></ul>
      </div>
    </div>
    <details v-if="a.method" class="method">
      <summary>Comment les pourcentages sont calculés</summary>
      <p>{{ a.method }}</p>
      <p>Ce sont des estimations calibrées et justifiées, pas une certitude : chaque détection détaille son calcul.</p>
    </details>
  </div>
</template>

<style scoped>
.card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 16px; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.col { border-radius: 10px; padding: 10px 14px; border: 1px solid var(--border); }
.col.bad { border-left: 4px solid var(--malicious); }
.col.good { border-left: 4px solid var(--safe); }
.col h4 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }
.col ul { padding-left: 18px; font-size: 12.5px; color: var(--text-secondary); }
.col li { margin: 4px 0; }
.method { margin-top: 12px; font-size: 12px; color: var(--text-muted); }
.method summary { cursor: pointer; }
.method p { margin-top: 6px; }
@media (max-width: 640px) { .cols { grid-template-columns: 1fr; } }
</style>
