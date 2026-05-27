<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const vtTestMsg = ref('')
const vtTesting = ref(false)

onMounted(async () => {
  if (!store.settingsLoaded) {
    await store.loadSettings()
  }
})

async function save() {
  await store.saveSettings()
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

    <div class="field">
      <label class="field-label">Clé API VirusTotal</label>
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
      <span class="field-hint">Stockée dans le gestionnaire d'identifiants Windows</span>
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
.field { display: flex; flex-direction: column; gap: 0.4rem; }
.field-label { font-size: 0.78rem; font-weight: 600; color: var(--text-secondary); }
.field-hint { font-size: 0.68rem; color: var(--text-muted); }
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
