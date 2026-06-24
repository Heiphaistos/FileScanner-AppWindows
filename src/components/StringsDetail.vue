<script setup lang="ts">
import { computed, ref } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const result = computed(() => store.result)
const copied = ref(false)

function severityClass(s: string) {
  return `badge badge-${s.toLowerCase()}`
}

async function copyAll() {
  const r = result.value
  if (!r) return
  const lines: string[] = []
  if (r.yara_matches.length) {
    lines.push('=== Patterns YARA ===')
    r.yara_matches.forEach(m => {
      lines.push(`[${m.severity}] ${m.rule_name} — ${m.description}`)
      if (m.matched_strings.length) lines.push(`  Strings: ${m.matched_strings.join(', ')}`)
    })
    lines.push('')
  }
  if (r.script_info?.matched_lines.length) {
    lines.push(`=== Appels dangereux (${r.script_info.script_type}) ===`)
    r.script_info.matched_lines.forEach(ml =>
      lines.push(`L${ml.line_number} | ${ml.pattern} | ${ml.line_content}`)
    )
    lines.push('')
  }
  if (r.script_info?.base64_samples.length) {
    lines.push('=== Blobs Base64 ===')
    r.script_info.base64_samples.forEach((b, i) => lines.push(`#${i + 1}: ${b}`))
    lines.push('')
  }
  if (r.pe_info?.suspicious_imports.length) {
    lines.push('=== Imports PE suspects ===')
    lines.push(r.pe_info.suspicious_imports.join(', '))
    lines.push('')
  }
  if (r.virustotal?.detection_names.length) {
    lines.push('=== Détections VirusTotal ===')
    lines.push(r.virustotal.detection_names.join('\n'))
  }
  await navigator.clipboard.writeText(lines.join('\n'))
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

const hasContent = computed(() => {
  const r = result.value
  if (!r) return false
  return (
    r.yara_matches.length > 0 ||
    (r.script_info?.matched_lines.length ?? 0) > 0 ||
    (r.script_info?.base64_samples.length ?? 0) > 0 ||
    (r.pe_info?.suspicious_imports.length ?? 0) > 0 ||
    (r.virustotal?.detection_names.length ?? 0) > 0
  )
})
</script>

<template>
  <div v-if="result" class="strings-wrapper">
    <div class="toolbar">
      <button class="btn-copy" @click="copyAll">{{ copied ? '✓ Copié !' : '⎘ Copier tout' }}</button>
    </div>

    <!-- YARA patterns -->
    <div v-if="result.yara_matches.length" class="section-card">
      <div class="section-title">Patterns YARA déclenchés</div>
      <div v-for="m in result.yara_matches" :key="m.rule_name" class="yara-card">
        <div class="yara-header">
          <span class="mono rule-name">{{ m.rule_name }}</span>
          <span :class="severityClass(m.severity)">{{ m.severity }}</span>
        </div>
        <div class="yara-desc">{{ m.description }}</div>
        <div v-if="m.matched_strings.length" class="chips-row">
          <span class="chips-label">Strings détectés :</span>
          <code v-for="(s, i) in m.matched_strings" :key="i" class="string-chip">{{ s }}</code>
        </div>
      </div>
    </div>

    <!-- Script — lignes correspondantes -->
    <div v-if="result.script_info?.matched_lines.length" class="section-card">
      <div class="section-title">
        Appels dangereux — {{ result.script_info.script_type }}
        <span class="count-badge">{{ result.script_info.matched_lines.length }} occurrence(s)</span>
      </div>
      <div class="table-scroll">
        <table class="match-table">
          <thead>
            <tr>
              <th class="col-line">Ligne</th>
              <th class="col-pattern">Pattern</th>
              <th class="col-content">Contenu</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(ml, i) in result.script_info.matched_lines" :key="i">
              <td class="col-line mono">{{ ml.line_number }}</td>
              <td class="col-pattern"><span class="pattern-tag">{{ ml.pattern }}</span></td>
              <td class="col-content mono small">{{ ml.line_content }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Base64 blobs -->
    <div v-if="result.script_info?.base64_samples.length" class="section-card">
      <div class="section-title">
        Blobs Base64 détectés
        <span class="count-badge">{{ result.script_info.base64_blobs_count }} total</span>
      </div>
      <div class="b64-list">
        <div v-for="(b, i) in result.script_info.base64_samples" :key="i" class="b64-item">
          <span class="b64-index">#{{ i + 1 }}</span>
          <code class="b64-content">{{ b }}</code>
        </div>
      </div>
    </div>

    <!-- PE imports suspects -->
    <div v-if="result.pe_info?.suspicious_imports.length" class="section-card">
      <div class="section-title">
        Imports PE suspects
        <span class="count-badge">{{ result.pe_info.suspicious_imports.length }}</span>
      </div>
      <div class="chips-row">
        <code v-for="imp in result.pe_info.suspicious_imports" :key="imp" class="import-chip">{{ imp }}</code>
      </div>
    </div>

    <!-- VirusTotal détections -->
    <div v-if="result.virustotal?.detection_names.length" class="section-card">
      <div class="section-title">
        Noms de détection VirusTotal
        <span class="count-badge">{{ result.virustotal.positives }} / {{ result.virustotal.total }} moteurs</span>
      </div>
      <div class="vt-grid">
        <span v-for="name in result.virustotal.detection_names" :key="name" class="vt-name">{{ name }}</span>
      </div>
    </div>

    <div v-if="!hasContent" class="empty-state">
      Aucune détection de string — fichier propre ou type non analysable en profondeur.
    </div>

  </div>
</template>

<style scoped>
.strings-wrapper { display: flex; flex-direction: column; gap: 1rem; }

.yara-card {
  background: var(--bg-elevated);
  border-radius: var(--radius);
  padding: 0.75rem 1rem;
  margin-top: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.yara-header { display: flex; align-items: center; gap: 0.75rem; }
.rule-name { font-size: 0.82rem; font-weight: 700; color: var(--text-primary); }
.yara-desc { font-size: 0.78rem; color: var(--text-secondary); }

.chips-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; margin-top: 0.25rem; }
.chips-label { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.string-chip {
  background: rgba(239, 68, 68, 0.12);
  color: var(--malicious);
  border: 1px solid rgba(239, 68, 68, 0.25);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
}
.import-chip {
  background: rgba(249, 115, 22, 0.12);
  color: var(--suspicious);
  border: 1px solid rgba(249, 115, 22, 0.25);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
}

.count-badge {
  font-size: 0.68rem;
  font-weight: 600;
  color: var(--text-muted);
  margin-left: 0.5rem;
}

.table-scroll { overflow-x: auto; }
.match-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.78rem;
}
.match-table th {
  text-align: left;
  padding: 0.4rem 0.6rem;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.match-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }
.col-line { width: 4rem; color: var(--accent); font-weight: 700; }
.col-pattern { width: 12rem; }
.col-content { color: var(--text-secondary); word-break: break-all; }
.small { font-size: 0.72rem; }

.pattern-tag {
  background: rgba(99, 102, 241, 0.15);
  color: var(--accent);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 600;
}

.b64-list { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.25rem; }
.b64-item { display: flex; align-items: flex-start; gap: 0.6rem; }
.b64-index { font-size: 0.68rem; color: var(--text-muted); padding-top: 0.15rem; min-width: 1.5rem; }
.b64-content {
  font-size: 0.7rem;
  color: var(--suspicious);
  word-break: break-all;
  background: rgba(249, 115, 22, 0.06);
  padding: 0.3rem 0.5rem;
  border-radius: 4px;
  flex: 1;
}

.vt-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.25rem; }
.vt-name {
  background: rgba(239, 68, 68, 0.1);
  color: var(--malicious);
  border: 1px solid rgba(239, 68, 68, 0.2);
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.72rem;
}

.empty-state {
  text-align: center;
  color: var(--text-muted);
  font-size: 0.82rem;
  padding: 2rem;
}
</style>
