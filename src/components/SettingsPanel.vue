<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { useScanStore } from '../stores/scan'
import type { AppSettings } from '../types/scan'

const store = useScanStore()
const vtTestMsg = ref('')
const vtTesting = ref(false)

// Clés secondaires : champ + lien d'inscription. Vide = source « non configurée ».
type KeyField = { key: keyof AppSettings; label: string; url: string }
const keyFields: KeyField[] = [
  { key: 'metadefender_api_key', label: 'MetaDefender (OPSWAT, ~20 antivirus)', url: 'https://metadefender.opswat.com/' },
  { key: 'hybrid_analysis_api_key', label: 'Hybrid Analysis (sandbox CrowdStrike)', url: 'https://www.hybrid-analysis.com/signup' },
  { key: 'opentip_api_key', label: 'Kaspersky OpenTIP', url: 'https://opentip.kaspersky.com/' },
  { key: 'otx_api_key', label: 'AlienVault OTX', url: 'https://otx.alienvault.com/' },
  { key: 'abusech_api_key', label: 'abuse.ch (MalwareBazaar + ThreatFox + YARAify)', url: 'https://auth.abuse.ch/' },
]

onMounted(async () => {
  if (!store.settingsLoaded) {
    await store.loadSettings()
  }
})

async function save() {
  await store.saveSettings()
}

function onKeyInput(key: keyof AppSettings, e: Event) {
  ;(store.settings as Record<string, string | boolean>)[key] = (e.target as HTMLInputElement).value
}

async function testVtKey() {
  vtTesting.value = true
  vtTestMsg.value = ''
  try {
    vtTestMsg.value = await invoke<string>('test_vt_key', { apiKey: store.settings.vt_api_key })
  } catch (e) {
    vtTestMsg.value = String(e)
  } finally {
    vtTesting.value = false
  }
}
</script>

<template>
  <div class="settings-panel">
    <div class="section-title">Paramètres</div>

    <p class="intro">Toutes les clés sont gratuites et facultatives. Une clé vide = source non interrogée. Seule l'empreinte du fichier est envoyée.</p>

    <div class="field">
      <label class="field-label">Clé API VirusTotal (~70 antivirus)</label>
      <div class="input-row">
        <input
          v-model="store.settings.vt_api_key"
          type="password"
          class="input"
          placeholder="Entrez votre clé VT…"
          @blur="save"
        />
        <button
          class="btn-test"
          :disabled="vtTesting || !store.settings.vt_api_key"
          @click="testVtKey"
        >
          {{ vtTesting ? '…' : 'Tester' }}
        </button>
      </div>
      <span v-if="vtTestMsg" class="vt-msg" :class="vtTestMsg.includes('valide') ? 'ok' : 'err'">
        {{ vtTestMsg }}
      </span>
      <a class="field-link" href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer">S'inscrire ↗</a>
    </div>

    <div v-for="f in keyFields" :key="f.key" class="field">
      <label class="field-label">{{ f.label }}</label>
      <input
        :value="store.settings[f.key]"
        type="password"
        class="input"
        placeholder="Clé API (facultatif)…"
        @input="onKeyInput(f.key, $event)"
        @blur="save"
      />
      <a class="field-link" :href="f.url" target="_blank" rel="noopener noreferrer">S'inscrire ↗</a>
    </div>

    <div class="field">
      <div class="field-row">
        <label class="field-label">Sources gratuites (Team Cymru MHR + CIRCL)</label>
        <label class="toggle">
          <input v-model="store.settings.intel_free_lookups" type="checkbox" @change="save" />
          <span class="toggle-slider" />
        </label>
      </div>
      <span class="field-hint">Sans clé, actives par défaut. Décocher pour les couper.</span>
    </div>

    <div class="field">
      <label class="field-label">Dossier base ClamAV (optionnel)</label>
      <input
        v-model="store.settings.clamav_db_path"
        type="text"
        class="input"
        placeholder="Automatique (ClamAV local ou AppData)"
        @blur="save"
      />
      <span class="field-hint">Laisser vide pour détection automatique</span>
    </div>

    <div class="field">
      <div class="field-row">
        <label class="field-label">Analyse IA locale</label>
        <label class="toggle">
          <input v-model="store.settings.ai_enabled" type="checkbox" @change="save" />
          <span class="toggle-slider" />
        </label>
      </div>
      <span class="field-hint">Heuristique basée sur score agrégé (stub ONNX v1.0)</span>
    </div>
  </div>
</template>

<style scoped>
.settings-panel { display: flex; flex-direction: column; gap: 1.25rem; }
.intro { font-size: 0.68rem; color: var(--text-muted); line-height: 1.5; }
.field { display: flex; flex-direction: column; gap: 0.4rem; }
.field-label { font-size: 0.78rem; font-weight: 600; color: var(--text-secondary); }
.field-hint { font-size: 0.68rem; color: var(--text-muted); }
.field-link { font-size: 0.68rem; color: var(--accent); text-decoration: none; }
.field-link:hover { text-decoration: underline; }
.field-row { display: flex; align-items: center; justify-content: space-between; }
.input-row { display: flex; gap: 0.4rem; }
.input-row .input { flex: 1; }
.btn-test {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius);
  padding: 0 0.75rem;
  font-size: 0.75rem;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s;
}
.btn-test:hover:not(:disabled) { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-test:disabled { opacity: 0.4; cursor: default; }
.vt-msg { font-size: 0.7rem; padding: 0.25rem 0.5rem; border-radius: 4px; }
.vt-msg.ok { background: rgba(34,197,94,0.1); color: var(--safe); }
.vt-msg.err { background: rgba(239,68,68,0.1); color: var(--malicious); }
</style>
