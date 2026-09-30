<script setup lang="ts">
import { computed, ref } from 'vue'
import { useScanStore } from '../stores/scan'
import { SEVERITY_LABELS, threatColor } from '../types/scan'

const store = useScanStore()
const detections = computed(() => store.result?.detections ?? [])
const hideLikelyFp = ref(false)
const open = ref<Set<string>>(new Set())

const shown = computed(() =>
  hideLikelyFp.value ? detections.value.filter((d) => d.confidence >= 30) : detections.value,
)
const likelyFp = computed(() => detections.value.filter((d) => d.confidence < 30).length)

function toggle(id: string) {
  const s = new Set(open.value)
  if (s.has(id)) s.delete(id)
  else s.add(id)
  open.value = s
}
</script>

<template>
  <div v-if="detections.length" class="card">
    <div class="head">
      <span class="title">🔎 Détections expliquées <span class="badge-count">{{ detections.length }}</span></span>
      <label v-if="likelyFp" class="filter">
        <input type="checkbox" v-model="hideLikelyFp" />
        Masquer les faux positifs probables ({{ likelyFp }})
      </label>
    </div>
    <p class="legend">
      <b>Menace</b> = probabilité que l'élément soit réellement malveillant ·
      <b>Faux positif</b> = probabilité que ce soit une fausse alerte ·
      <b>Gravité</b> = impact <i>si</i> c'est réel. Cliquez pour le détail.
    </p>

    <div v-for="d in shown" :key="d.id" class="det" :style="{ borderLeftColor: threatColor(d.confidence) }">
      <div class="det-head" @click="toggle(d.id)">
        <div class="det-title">
          <span>{{ d.title }}</span>
          <small>{{ d.source }} · {{ d.verdict }}</small>
        </div>
        <div class="pcts">
          <span class="pct" :style="{ color: threatColor(d.confidence) }">{{ d.confidence }} %<small>menace</small></span>
          <span class="pct fp">{{ d.false_positive }} %<small>faux positif</small></span>
        </div>
      </div>
      <div class="mini-track"><div :style="{ width: d.confidence + '%', background: threatColor(d.confidence) }"></div></div>

      <div v-if="open.has(d.id)" class="det-body">
        <div class="tags">
          <span class="sev" :class="`sev-${d.severity}`">GRAVITÉ SI RÉEL : {{ SEVERITY_LABELS[d.severity] }}</span>
          <code v-if="d.value">{{ d.value }}</code>
        </div>
        <h5>Ce que ça fait</h5>
        <p>{{ d.what_it_does }}</p>
        <div class="two">
          <div class="why bad">
            <h5>Pourquoi ça peut être malveillant</h5>
            <p>{{ d.why_malicious }}</p>
          </div>
          <div class="why good">
            <h5>Pourquoi ça peut être légitime (faux positif)</h5>
            <p>{{ d.why_legitimate }}</p>
          </div>
        </div>
        <h5>Calcul du pourcentage</h5>
        <ul class="calc">
          <li>Probabilité de départ pour ce type de signal : <b>{{ d.base_confidence }} %</b></li>
          <li v-for="(f, i) in d.factors" :key="i">
            <b :class="f.delta < 0 ? 'minus' : 'plus'">{{ f.delta > 0 ? '+' : '' }}{{ f.delta }}</b> : {{ f.label }}
          </li>
          <li>Résultat : <b>{{ d.confidence }} %</b> de menace réelle → <b>{{ d.false_positive }} %</b> de faux positif</li>
        </ul>
        <template v-if="d.evidence.length">
          <h5>Preuves trouvées dans le fichier</h5>
          <pre class="evidence">{{ d.evidence.join('\n') }}</pre>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
.card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; }
.head { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; padding: 12px 18px 4px; }
.title { font-weight: 600; font-size: 13px; display: flex; gap: 8px; align-items: center; color: var(--text-primary); }
.badge-count { background: var(--border); border-radius: 99px; font-size: 11px; padding: 1px 8px; color: var(--text-secondary); }
.filter { font-size: 12px; color: var(--text-secondary); display: flex; gap: 6px; align-items: center; cursor: pointer; }
.legend { font-size: 11.5px; color: var(--text-muted); padding: 0 18px 10px; }
.det { border-top: 1px solid var(--border); border-left: 4px solid; }
.det-head { display: flex; justify-content: space-between; gap: 12px; padding: 10px 14px 6px; cursor: pointer; }
.det-head:hover { background: var(--bg-elevated); }
.det-title { display: flex; flex-direction: column; min-width: 0; font-size: 13px; font-weight: 600; word-break: break-word; color: var(--text-primary); }
.det-title small { font-weight: 400; color: var(--text-muted); font-size: 11.5px; margin-top: 2px; }
.pcts { display: flex; gap: 14px; flex-shrink: 0; }
.pct { display: flex; flex-direction: column; align-items: flex-end; font-weight: 800; font-size: 16px; line-height: 1.1; }
.pct small { font-size: 10px; font-weight: 500; color: var(--text-muted); }
.pct.fp { color: var(--safe); }
.mini-track { height: 3px; background: var(--border); margin: 0 14px 8px; border-radius: 99px; overflow: hidden; }
.mini-track div { height: 100%; }
.det-body { padding: 4px 16px 14px; font-size: 13px; color: var(--text-secondary); }
.tags { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.tags code { background: var(--bg-base); padding: 1px 6px; border-radius: 4px; }
.sev { font-size: 10.5px; font-weight: 700; border-radius: 99px; padding: 1px 9px; border: 1px solid; }
.sev-Low { color: #64748b; border-color: #64748b66; }
.sev-Medium { color: #eab308; border-color: #eab30866; }
.sev-High { color: var(--suspicious); border-color: color-mix(in srgb, var(--suspicious) 40%, transparent); }
.sev-Critical { color: var(--malicious); border-color: color-mix(in srgb, var(--malicious) 40%, transparent); }
h5 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin: 12px 0 4px; }
.two { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.why { border-radius: 8px; padding: 2px 12px 10px; background: var(--bg-base); }
.why.bad { border-left: 3px solid var(--malicious); }
.why.good { border-left: 3px solid var(--safe); }
.calc { padding-left: 18px; color: var(--text-secondary); }
.calc li { margin: 3px 0; }
.plus { color: var(--malicious); }
.minus { color: var(--safe); }
.evidence { background: var(--bg-base); border-radius: 8px; padding: 8px 10px; font-size: 11.5px; white-space: pre-wrap; word-break: break-all; font-family: "Cascadia Code", Consolas, monospace; max-height: 220px; overflow: auto; }
@media (max-width: 640px) { .two { grid-template-columns: 1fr; } .det-head { flex-direction: column; } .pcts { align-self: flex-start; } .pct { align-items: flex-start; } }
</style>
