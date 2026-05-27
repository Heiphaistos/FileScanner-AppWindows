<script setup lang="ts">
import { ref } from 'vue'
import { useScanStore } from '../stores/scan'
import type { ExportFormat } from '../types/scan'

const store = useScanStore()
const exporting = ref<ExportFormat | null>(null)

const formats: { id: ExportFormat; label: string; icon: string }[] = [
  { id: 'json', label: 'JSON', icon: '{ }' },
  { id: 'html', label: 'HTML', icon: '</>' },
  { id: 'txt',  label: 'Texte', icon: 'TXT' },
  { id: 'md',   label: 'Markdown', icon: '#' },
  { id: 'pdf',  label: 'PDF', icon: '⬇' },
]

async function doExport(fmt: ExportFormat) {
  if (exporting.value) return
  exporting.value = fmt
  try {
    await store.exportReport(fmt)
  } finally {
    exporting.value = null
  }
}
</script>

<template>
  <div v-if="store.hasResult" class="export-menu">
    <div class="section-title">Exporter le rapport</div>
    <div class="export-grid">
      <button
        v-for="fmt in formats"
        :key="fmt.id"
        class="export-btn"
        :class="{ loading: exporting === fmt.id }"
        :disabled="!!exporting"
        @click="doExport(fmt.id)"
      >
        <span class="fmt-icon">{{ fmt.icon }}</span>
        <span>{{ fmt.label }}</span>
      </button>
    </div>
  </div>
</template>

<style scoped>
.export-menu { display: flex; flex-direction: column; gap: 0.75rem; }
.export-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
.export-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.25rem;
  padding: 0.6rem 0.4rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 0.78rem;
  transition: all 0.15s;
}
.export-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--text-primary); }
.export-btn:disabled { opacity: 0.5; cursor: default; }
.export-btn.loading { border-color: var(--accent); }
.fmt-icon { font-family: monospace; font-size: 0.85rem; color: var(--text-muted); }
</style>
