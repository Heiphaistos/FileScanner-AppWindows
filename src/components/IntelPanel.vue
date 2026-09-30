<script setup lang="ts">
import { computed } from 'vue'
import { useScanStore } from '../stores/scan'
import { INTEL_LABELS } from '../types/scan'

const store = useScanStore()
const r = computed(() => store.result!)
const intel = computed(() => r.value.intel ?? [])
const queried = computed(() => intel.value.filter((s) => s.status !== 'NotConfigured'))
const unconfigured = computed(() => intel.value.filter((s) => s.status === 'NotConfigured'))
const flagged = computed(() => queried.value.filter((s) => s.status === 'Malicious' || s.status === 'Suspicious').length)
const vt = computed(() => r.value.virustotal)
</script>

<template>
  <details v-if="intel.length" class="card" open>
    <summary class="head">
      🌍 Réputation en ligne — {{ queried.length }} base(s) consultée(s){{ flagged ? `, ${flagged} alerte(s)` : '' }}
      <span class="badge-count">{{ intel.length }}</span>
    </summary>

    <div class="body">
      <p class="note">
        Seule l'empreinte du fichier (SHA-256 / MD5) est envoyée, jamais le fichier.
        « Inconnu » est normal pour un fichier personnel, récent ou peu diffusé.
      </p>
      <div v-for="s in queried" :key="s.source" class="src">
        <div class="src-head">
          <div>
            <b>{{ s.source }}</b>
            <small>{{ s.kind }}</small>
          </div>
          <span class="status" :style="{ color: INTEL_LABELS[s.status].color, borderColor: INTEL_LABELS[s.status].color + '66' }">
            {{ INTEL_LABELS[s.status].label }}
          </span>
        </div>
        <p class="sum">{{ s.summary }}</p>
        <div v-if="s.threat_names.length" class="names">
          <span v-for="n in s.threat_names" :key="n" class="chip danger">{{ n }}</span>
        </div>
        <ul v-if="s.details.length" class="details">
          <li v-for="(d, i) in s.details" :key="i">{{ d }}</li>
        </ul>
        <a v-if="s.link" :href="s.link" target="_blank" rel="noopener noreferrer" class="link">Voir le rapport ↗</a>
      </div>
      <p v-if="unconfigured.length" class="note unconf">
        Non interrogées (clé API absente) :
        {{ unconfigured.map((s) => s.source).join(', ') }}.
      </p>

      <details v-if="vt && vt.engines && vt.engines.length" class="engines">
        <summary>Détail VirusTotal : {{ vt.engines.length }} moteur(s) ayant signalé le fichier</summary>
        <table>
          <thead><tr><th>Antivirus</th><th>Classement</th><th>Nom de détection</th></tr></thead>
          <tbody>
            <tr v-for="e in vt.engines" :key="e.engine">
              <td>{{ e.engine }}</td>
              <td :style="{ color: e.category === 'malicious' ? 'var(--malicious)' : 'var(--suspicious)' }">
                {{ e.category === 'malicious' ? 'Malveillant' : 'Suspect' }}
              </td>
              <td class="mono">{{ e.result }}</td>
            </tr>
          </tbody>
        </table>
      </details>
    </div>
  </details>
</template>

<style scoped>
.card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; }
.head { font-weight: 600; font-size: 13px; padding: 12px 18px; cursor: pointer; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
.badge-count { background: var(--border); border-radius: 99px; font-size: 11px; padding: 1px 8px; color: var(--text-secondary); }
.body { padding: 0 18px 16px; }
.note { font-size: 12px; color: var(--text-muted); margin: 4px 0 6px; }
.note.unconf { margin-top: 12px; }
.src { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; margin-top: 8px; }
.src-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; }
.src-head b { color: var(--text-primary); }
.src-head small { display: block; color: var(--text-muted); font-size: 11.5px; }
.status { border: 1px solid; border-radius: 99px; padding: 1px 9px; font-size: 10.5px; font-weight: 700; white-space: nowrap; }
.sum { font-size: 13px; margin-top: 6px; color: var(--text-secondary); }
.names { margin-top: 4px; display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font-size: 11px; padding: 1px 8px; border-radius: 99px; }
.chip.danger { background: color-mix(in srgb, var(--malicious) 15%, transparent); color: var(--malicious); }
.details { font-size: 12px; color: var(--text-secondary); padding-left: 18px; margin-top: 4px; }
.link { font-size: 12px; color: var(--accent); display: inline-block; margin-top: 6px; text-decoration: none; }
.engines { margin-top: 12px; font-size: 12.5px; }
.engines summary { cursor: pointer; color: var(--text-secondary); margin-bottom: 6px; }
.engines table { width: 100%; border-collapse: collapse; }
.engines th, .engines td { text-align: left; padding: 3px 8px; border-bottom: 1px solid var(--border); }
.engines th { color: var(--text-muted); font-size: 11px; text-transform: uppercase; }
.mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 11.5px; }
</style>
