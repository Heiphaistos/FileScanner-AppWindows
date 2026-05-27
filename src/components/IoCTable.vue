<script setup lang="ts">
import { computed, ref } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const iocs = computed(() => store.result?.ioc_list ?? [])
const yara = computed(() => store.result?.yara_matches ?? [])
const copied = ref(false)

function severityClass(s: string) {
  return `badge badge-${s.toLowerCase()}`
}

async function copyAll() {
  const lines: string[] = []
  if (yara.value.length) {
    lines.push('=== Règles YARA déclenchées ===')
    yara.value.forEach(m => {
      lines.push(`[${m.severity}] ${m.rule_name} — ${m.description}`)
      if (m.matched_strings.length) lines.push(`  Strings: ${m.matched_strings.join(', ')}`)
    })
    lines.push('')
  }
  if (iocs.value.length) {
    lines.push('=== Indicateurs de Compromission ===')
    iocs.value.forEach(i => lines.push(`[${i.severity}] ${i.ioc_type}: ${i.value} — ${i.description}`))
  }
  await navigator.clipboard.writeText(lines.join('\n'))
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}
</script>

<template>
  <div v-if="iocs.length > 0 || yara.length > 0" class="ioc-wrapper">
    <div class="toolbar">
      <button class="btn-copy" @click="copyAll">{{ copied ? '✓ Copié !' : '⎘ Copier tout' }}</button>
    </div>

    <div v-if="yara.length > 0" class="section-card">
      <div class="section-title">Règles déclenchées ({{ yara.length }})</div>
      <table>
        <thead>
          <tr>
            <th>Sévérité</th>
            <th>Règle</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in yara" :key="m.rule_name">
            <td><span :class="severityClass(m.severity)">{{ m.severity }}</span></td>
            <td class="mono">{{ m.rule_name }}</td>
            <td>{{ m.description }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="iocs.length > 0" class="section-card">
      <div class="section-title">Indicateurs de compromission ({{ iocs.length }})</div>
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Valeur</th>
            <th>Sévérité</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ioc in iocs" :key="`${ioc.ioc_type}-${ioc.value}`">
            <td>{{ ioc.ioc_type }}</td>
            <td class="mono">{{ ioc.value }}</td>
            <td><span :class="severityClass(ioc.severity)">{{ ioc.severity }}</span></td>
            <td>{{ ioc.description }}</td>
          </tr>
        </tbody>
      </table>
    </div>

  </div>
</template>

<style scoped>
.ioc-wrapper { display: flex; flex-direction: column; gap: 1rem; }
.toolbar { display: flex; justify-content: flex-end; }
</style>
