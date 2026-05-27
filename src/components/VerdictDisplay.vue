<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const result = computed(() => store.result)

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
      <span class="verdict-text">{{ store.verdictLabel }}</span>
      <span class="verdict-score" :class="scoreClass">{{ result.verdict_score }}/100</span>
    </div>

    <div class="meta-grid">
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
.verdict-score { font-size: 1.25rem; font-weight: 700; }

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
