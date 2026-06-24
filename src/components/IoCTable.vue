<script setup lang="ts">
import { computed, ref } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const iocs = computed(() => store.result?.ioc_list ?? [])
const yara = computed(() => store.result?.yara_matches ?? [])
const copied = ref(false)

// B1 — Virtual scrolling : activé si IoCs > 100 entrées
const VIRTUAL_THRESHOLD = 100
const ROW_HEIGHT = 44  // px par ligne
const VISIBLE_ROWS = 12 // fenêtre visible

const scrollTop = ref(0)
const containerRef = ref<HTMLElement | null>(null)

const useVirtual = computed(() => iocs.value.length > VIRTUAL_THRESHOLD)

const virtualStart = computed(() =>
  Math.max(0, Math.floor(scrollTop.value / ROW_HEIGHT) - 2)
)
const virtualEnd = computed(() =>
  Math.min(iocs.value.length, virtualStart.value + VISIBLE_ROWS + 4)
)
const visibleIocs = computed(() =>
  useVirtual.value ? iocs.value.slice(virtualStart.value, virtualEnd.value) : iocs.value
)
const paddingTop = computed(() =>
  useVirtual.value ? virtualStart.value * ROW_HEIGHT : 0
)
const paddingBottom = computed(() =>
  useVirtual.value
    ? (iocs.value.length - virtualEnd.value) * ROW_HEIGHT
    : 0
)

function onScroll(e: Event) {
  scrollTop.value = (e.target as HTMLElement).scrollTop
}

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
      <span v-if="iocs.length > 0" class="ioc-count">
        {{ iocs.length }} IoC{{ iocs.length > 1 ? 's' : '' }}
        <span v-if="useVirtual" class="virtual-badge">scroll virtuel</span>
      </span>
      <button class="btn-copy" @click="copyAll">{{ copied ? '✓ Copié !' : '⎘ Copier tout' }}</button>
    </div>

    <!-- Table YARA (toujours complète, généralement < 20 règles) -->
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

    <!-- Table IoC avec virtual scrolling si > VIRTUAL_THRESHOLD entrées -->
    <div v-if="iocs.length > 0" class="section-card">
      <div class="section-title">Indicateurs de compromission ({{ iocs.length }})</div>
      <div
        ref="containerRef"
        class="ioc-scroll-container"
        :style="useVirtual ? { maxHeight: `${VISIBLE_ROWS * ROW_HEIGHT}px`, overflowY: 'auto' } : {}"
        @scroll="useVirtual ? onScroll($event) : undefined"
      >
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
            <!-- Spacer top (virtual scroll) -->
            <tr v-if="useVirtual && paddingTop > 0" :style="{ height: `${paddingTop}px` }">
              <td colspan="4" style="padding:0;border:none;" />
            </tr>
            <tr
              v-for="ioc in visibleIocs"
              :key="`${ioc.ioc_type}-${ioc.value}`"
              :style="useVirtual ? { height: `${ROW_HEIGHT}px` } : {}"
            >
              <td>{{ ioc.ioc_type }}</td>
              <td class="mono">{{ ioc.value }}</td>
              <td><span :class="severityClass(ioc.severity)">{{ ioc.severity }}</span></td>
              <td>{{ ioc.description }}</td>
            </tr>
            <!-- Spacer bottom (virtual scroll) -->
            <tr v-if="useVirtual && paddingBottom > 0" :style="{ height: `${paddingBottom}px` }">
              <td colspan="4" style="padding:0;border:none;" />
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ioc-wrapper { display: flex; flex-direction: column; gap: 1rem; }
.toolbar { display: flex; justify-content: flex-end; align-items: center; gap: 0.75rem; }
.ioc-count { font-size: 0.75rem; color: var(--text-muted); }
.virtual-badge {
  display: inline-block;
  margin-left: 0.4rem;
  padding: 0.1rem 0.4rem;
  background: rgba(96, 165, 250, 0.15);
  border: 1px solid rgba(96, 165, 250, 0.3);
  border-radius: 4px;
  font-size: 0.65rem;
  color: var(--accent);
}
.ioc-scroll-container {
  overflow-y: auto;
  border-radius: var(--radius);
}
/* Scrollbar discrète */
.ioc-scroll-container::-webkit-scrollbar { width: 6px; }
.ioc-scroll-container::-webkit-scrollbar-track { background: transparent; }
.ioc-scroll-container::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
</style>
