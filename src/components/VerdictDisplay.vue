<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'
import { threatColor } from '../types/scan'
import QuarantineButton from './QuarantineButton.vue'

const store = useScanStore()
const result = computed(() => store.result)
const a = computed(() => result.value?.assessment)
// Probabilité de menace réelle : l'évaluation calibrée si présente, sinon le score brut.
const threat = computed(() => a.value?.malicious_probability ?? result.value?.verdict_score ?? 0)
const hasDetections = computed(() => (result.value?.detections?.length ?? 0) > 0)

const scoreDash = computed(() => {
  const circ = 2 * Math.PI * 44
  return `${(threat.value / 100) * circ} ${circ}`
})

const scoreClass = computed(() => {
  const s = result.value?.verdict_score ?? 0
  if (s <= 20) return 'score-safe'
  if (s <= 59) return 'score-suspicious'
  return 'score-malicious'
})
</script>

<template>
  <div v-if="result" class="verdict-wrapper">
    <div class="verdict-badge" :style="{ borderColor: store.verdictColor, color: store.verdictColor }">
      <span class="verdict-text">
        {{ store.verdictLabel }}
        <span v-if="a?.label" class="verdict-sublabel">— {{ a.label }}</span>
      </span>
      <span class="verdict-score" :class="scoreClass">{{ result.verdict_score }}/100</span>
    </div>

    <div class="synthesis">
      <div class="gauge" title="Probabilité que le fichier soit réellement malveillant">
        <svg viewBox="0 0 100 100" width="104" height="104">
          <circle cx="50" cy="50" r="44" fill="none" stroke="var(--border)" stroke-width="8" />
          <circle
            cx="50" cy="50" r="44" fill="none"
            :stroke="threatColor(threat)" stroke-width="8" stroke-linecap="round"
            :stroke-dasharray="scoreDash" transform="rotate(-90 50 50)"
          />
          <text x="50" y="50" text-anchor="middle" fill="var(--text-primary)" font-size="22" font-weight="700">{{ threat }} %</text>
          <text x="50" y="66" text-anchor="middle" fill="var(--text-muted)" font-size="8.5">menace réelle</text>
        </svg>
      </div>
      <div class="bars">
        <div class="bar-row">
          <span>Probabilité de menace réelle</span>
          <b :style="{ color: threatColor(threat) }">{{ threat }} %</b>
        </div>
        <div class="track"><div class="fill" :style="{ width: threat + '%', background: threatColor(threat) }"></div></div>
        <template v-if="hasDetections && a">
          <div class="bar-row">
            <span>Probabilité que les alertes soient des faux positifs</span>
            <b style="color: var(--safe)">{{ a.false_positive_probability }} %</b>
          </div>
          <div class="track"><div class="fill" :style="{ width: a.false_positive_probability + '%', background: 'var(--safe)' }"></div></div>
        </template>
        <p v-if="a?.summary" class="synth-summary">{{ a.summary }}</p>
      </div>
    </div>

    <p v-if="result.explanation" class="explanation">{{ result.explanation }}</p>

    <div class="meta-grid">
      <div class="meta-item">
        <span class="meta-label">Catégorie</span>
        <span class="meta-value">{{ result.category || '—' }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Fichier</span>
        <span class="meta-value mono">{{ result.file_name }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Taille</span>
        <span class="meta-value">{{ (result.file_size / 1024).toFixed(1) }} Ko</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">MIME réel</span>
        <span class="meta-value mono">{{ result.mime_type }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">MD5</span>
        <span class="meta-value mono small">{{ result.hashes.md5 }}</span>
      </div>
      <div class="meta-item full">
        <span class="meta-label">SHA256</span>
        <span class="meta-value mono small">{{ result.hashes.sha256 }}</span>
      </div>
    </div>

    <div v-if="result.virustotal" class="vt-row">
      <span class="meta-label">VirusTotal</span>
      <span
        class="vt-score"
        :class="result.virustotal.positives > 0 ? 'danger' : 'clean'"
      >
        {{ result.virustotal.positives }} / {{ result.virustotal.total }} moteurs
      </span>
      <a :href="result.virustotal.permalink" target="_blank" class="vt-link">↗ Voir rapport</a>
    </div>

    <div v-if="result.clamav" class="clamav-hit">
      <span class="section-title">ClamAV</span>
      <div class="clamav-inner">
        <span class="badge badge-malicious">DÉTECTÉ</span>
        <span class="clamav-name">{{ result.clamav.malware_name }}</span>
        <span class="clamav-db">{{ result.clamav.database }}</span>
      </div>
    </div>

    <div v-if="result.ai_verdict" class="ai-block">
      <span class="section-title">Analyse IA locale</span>
      <p>{{ result.ai_verdict }}</p>
    </div>

    <!-- Feature B — Bouton quarantaine visible uniquement si verdict Malicious -->
    <QuarantineButton v-if="result.verdict === 'Malicious'" />
  </div>
</template>

<style scoped>
.verdict-wrapper { display: flex; flex-direction: column; gap: 1rem; }

.verdict-badge {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border: 2px solid;
  border-radius: var(--radius-lg);
  padding: 1rem 1.5rem;
}
.verdict-text { font-size: 1.5rem; font-weight: 800; letter-spacing: 0.05em; }
.verdict-sublabel { font-size: 0.9rem; font-weight: 600; letter-spacing: 0; color: var(--text-muted); }
.verdict-score { font-size: 1.25rem; font-weight: 700; }

.synthesis {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1rem 1.25rem;
}
.gauge { flex-shrink: 0; }
.bars { flex: 1; min-width: 0; }
.bar-row { display: flex; justify-content: space-between; gap: 12px; font-size: 0.8rem; font-weight: 600; margin: 0.5rem 0 0.25rem; color: var(--text-secondary); }
.bar-row:first-child { margin-top: 0; }
.track { height: 8px; background: var(--border); border-radius: 99px; overflow: hidden; }
.fill { height: 100%; border-radius: 99px; transition: width 0.4s; }
.synth-summary { color: var(--text-muted); font-size: 0.78rem; margin-top: 0.625rem; }
.explanation { white-space: pre-line; font-size: 0.82rem; line-height: 1.6; color: var(--text-secondary); }
@media (max-width: 560px) { .synthesis { flex-direction: column; align-items: stretch; } }

.meta-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}
.meta-item { display: flex; flex-direction: column; gap: 0.2rem; }
.meta-item.full { grid-column: 1 / -1; }
.meta-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); }
.meta-value { font-size: 0.8rem; color: var(--text-secondary); }
.meta-value.small { font-size: 0.7rem; }

.vt-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  background: var(--bg-elevated);
  padding: 0.75rem 1rem;
  border-radius: var(--radius);
}
.vt-score { font-weight: 700; }
.vt-score.danger { color: var(--malicious); }
.vt-score.clean { color: var(--safe); }
.vt-link { margin-left: auto; font-size: 0.8rem; color: var(--accent); text-decoration: none; }

.ai-block {
  background: var(--bg-elevated);
  border-left: 3px solid var(--accent);
  padding: 0.75rem 1rem;
  border-radius: 0 var(--radius) var(--radius) 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  font-size: 0.82rem;
  color: var(--text-secondary);
}
.clamav-hit {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: var(--radius);
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}
.clamav-inner { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
.clamav-name { font-weight: 700; color: var(--malicious); font-size: 0.85rem; }
.clamav-db { font-size: 0.72rem; color: var(--text-muted); }

.score-safe { color: var(--safe); }
.score-suspicious { color: var(--suspicious); }
.score-malicious { color: var(--malicious); }
</style>
