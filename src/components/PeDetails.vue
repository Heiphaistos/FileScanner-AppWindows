<script setup lang="ts">
import { computed, ref } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const pe = computed(() => store.result?.pe_info ?? null)
const script = computed(() => store.result?.script_info ?? null)
const showImports = ref(false)
const copied = ref(false)

function entropyClass(e: number) {
  if (e > 7.2) return 'entropy-high'
  if (e > 6.0) return 'entropy-mid'
  return 'entropy-low'
}

async function copyAll() {
  const lines: string[] = []
  if (pe.value) {
    lines.push('=== Analyse PE ===')
    lines.push(`Architecture: ${pe.value.is_64bit ? '64-bit' : '32-bit'}`)
    lines.push(`Signé: ${pe.value.is_signed ? 'Oui' : 'Non'}`)
    lines.push(`Packer: ${pe.value.is_packed ? 'Oui' : 'Non'}`)
    lines.push(`Entropie max: ${pe.value.entropy_max.toFixed(3)}`)
    lines.push('')
    lines.push('--- Sections ---')
    pe.value.sections.forEach(s =>
      lines.push(`${s.name || '(vide)'}: virt=${s.virtual_size}, raw=${s.raw_size}, entropie=${s.entropy.toFixed(3)}`)
    )
    if (pe.value.suspicious_imports.length) {
      lines.push('')
      lines.push('--- Imports suspects ---')
      lines.push(pe.value.suspicious_imports.join(', '))
    }
    if (pe.value.imports.length) {
      lines.push('')
      lines.push('--- Tous les imports ---')
      lines.push(pe.value.imports.join(', '))
    }
  }
  if (script.value) {
    lines.push('')
    lines.push(`=== Analyse script (${script.value.script_type}) ===`)
    lines.push(`Obfuscation: ${script.value.obfuscation_detected ? 'Oui' : 'Non'}`)
    lines.push(`Blobs Base64: ${script.value.base64_blobs_count}`)
    if (script.value.dangerous_calls.length)
      lines.push(`Appels dangereux: ${script.value.dangerous_calls.join(', ')}`)
  }
  await navigator.clipboard.writeText(lines.join('\n'))
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}
</script>

<template>
  <div v-if="pe || script" class="pe-wrapper">
    <div class="toolbar">
      <button class="btn-copy" @click="copyAll">{{ copied ? '✓ Copié !' : '⎘ Copier tout' }}</button>
    </div>

    <div v-if="pe" class="section-card">
      <div class="section-title">Analyse PE</div>
      <div class="info-row">
        <span class="info-label">Architecture</span>
        <span>{{ pe.is_64bit ? '64-bit' : '32-bit' }}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Signature</span>
        <span :class="pe.is_signed ? 'text-safe' : 'text-warn'">
          {{ pe.is_signed ? '✓ Signé' : '✗ Non signé' }}
        </span>
      </div>
      <div class="info-row">
        <span class="info-label">Packer détecté</span>
        <span :class="pe.is_packed ? 'text-warn' : 'text-muted'">
          {{ pe.is_packed ? '⚠ Oui' : 'Non' }}
        </span>
      </div>
      <div class="info-row">
        <span class="info-label">Entropie max</span>
        <span :class="entropyClass(pe.entropy_max)">{{ pe.entropy_max.toFixed(3) }}</span>
      </div>

      <div class="section-title" style="margin-top: 1rem;">Sections PE</div>
      <table>
        <thead>
          <tr>
            <th>Nom</th>
            <th>Taille virt.</th>
            <th>Taille raw</th>
            <th>Entropie</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in pe.sections" :key="s.name">
            <td class="mono">{{ s.name || '(vide)' }}</td>
            <td>{{ s.virtual_size }}</td>
            <td>{{ s.raw_size }}</td>
            <td :class="entropyClass(s.entropy)">{{ s.entropy.toFixed(3) }}</td>
          </tr>
        </tbody>
      </table>

      <div v-if="pe.suspicious_imports.length > 0" class="suspicious-imports">
        <div class="section-title" style="margin-top: 1rem;">Imports suspects</div>
        <div class="import-list">
          <span v-for="imp in pe.suspicious_imports" :key="imp" class="import-chip">{{ imp }}</span>
        </div>
      </div>

      <button v-if="pe.imports.length > 0" class="btn btn-ghost" style="margin-top: 0.75rem; width: 100%;" @click="showImports = !showImports">
        {{ showImports ? 'Masquer' : 'Voir' }} tous les imports ({{ pe.imports.length }})
      </button>
      <div v-if="showImports" class="imports-full">
        <span v-for="imp in pe.imports" :key="imp" class="mono import-entry">{{ imp }}</span>
      </div>
    </div>

    <div v-if="script" class="section-card">
      <div class="section-title">Analyse script ({{ script.script_type }})</div>
      <div class="info-row">
        <span class="info-label">Obfuscation</span>
        <span :class="script.obfuscation_detected ? 'text-warn' : 'text-muted'">
          {{ script.obfuscation_detected ? '⚠ Détectée' : 'Aucune' }}
        </span>
      </div>
      <div class="info-row">
        <span class="info-label">Blobs Base64</span>
        <span :class="script.base64_blobs_count > 0 ? 'text-warn' : 'text-muted'">
          {{ script.base64_blobs_count }}
        </span>
      </div>
      <div v-if="script.dangerous_calls.length > 0">
        <div class="section-title" style="margin-top: 0.75rem;">Appels dangereux</div>
        <div class="import-list">
          <span v-for="call in script.dangerous_calls" :key="call" class="import-chip danger">{{ call }}</span>
        </div>
      </div>
    </div>

  </div>
</template>

<style scoped>
.pe-wrapper { display: flex; flex-direction: column; gap: 1rem; }
.toolbar { display: flex; justify-content: flex-end; }
.info-row { display: flex; justify-content: space-between; padding: 0.35rem 0; border-bottom: 1px solid rgba(51,65,85,0.5); font-size: 0.82rem; }
.info-label { color: var(--text-muted); }
.text-safe { color: var(--safe); }
.text-warn { color: var(--suspicious); }
.text-muted { color: var(--text-muted); }
.entropy-high { color: var(--malicious); font-weight: 700; }
.entropy-mid { color: var(--suspicious); }
.entropy-low { color: var(--text-secondary); }
.suspicious-imports { }
.import-list { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.4rem; }
.import-chip {
  background: rgba(249, 115, 22, 0.15);
  color: var(--suspicious);
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-family: monospace;
}
.import-chip.danger {
  background: rgba(239, 68, 68, 0.15);
  color: var(--malicious);
}
.imports-full {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
  margin-top: 0.5rem;
  max-height: 150px;
  overflow-y: auto;
}
.import-entry {
  font-size: 0.72rem;
  color: var(--text-muted);
  background: var(--bg-base);
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
}
</style>
