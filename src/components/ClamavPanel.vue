<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import type { ClamavStatus } from '../types/scan'

const status = ref<ClamavStatus | null>(null)
const loading = ref(false)
const updating = ref(false)
const updateMsg = ref('')

async function loadStatus() {
  loading.value = true
  try {
    status.value = await invoke<ClamavStatus>('get_clamav_status')
  } catch {
    status.value = null
  } finally {
    loading.value = false
  }
}

async function updateDb() {
  updating.value = true
  updateMsg.value = 'Téléchargement en cours… (peut prendre plusieurs minutes)'
  try {
    const files = await invoke<string[]>('update_clamav_db')
    updateMsg.value = `Mis à jour : ${files.join(', ')}`
    await loadStatus()
  } catch (e) {
    updateMsg.value = `Erreur : ${String(e)}`
  } finally {
    updating.value = false
  }
}

onMounted(loadStatus)
</script>

<template>
  <div class="clamav-panel">
    <div class="section-title">Base ClamAV</div>

    <div v-if="loading" class="status-row muted">Chargement…</div>

    <template v-else-if="status">
      <div class="status-row">
        <span class="status-dot" :class="status.loaded ? 'dot-ok' : 'dot-off'" />
        <span>{{ status.loaded ? 'Chargée' : 'Non disponible' }}</span>
      </div>
      <div v-if="status.loaded" class="stat-grid">
        <div class="stat">
          <span class="stat-value">{{ status.md5_count.toLocaleString() }}</span>
          <span class="stat-label">Sig. MD5</span>
        </div>
        <div class="stat">
          <span class="stat-value">{{ status.sha256_count.toLocaleString() }}</span>
          <span class="stat-label">Sig. SHA256</span>
        </div>
      </div>
      <div v-if="status.last_updated" class="hint">
        Mis à jour : {{ status.last_updated }}
      </div>
      <div v-if="status.db_path" class="hint mono">{{ status.db_path }}</div>
    </template>

    <div v-if="updateMsg" class="update-msg" :class="updateMsg.startsWith('Erreur') ? 'err' : 'ok'">
      {{ updateMsg }}
    </div>

    <button class="btn btn-ghost" style="width:100%; margin-top:0.5rem" :disabled="updating" @click="updateDb">
      {{ updating ? 'Téléchargement…' : '↓ Télécharger les signatures' }}
    </button>
    <div class="hint" style="margin-top:0.3rem">
      Source : database.clamav.net (~240 MB)
    </div>
  </div>
</template>

<style scoped>
.clamav-panel { display: flex; flex-direction: column; gap: 0.5rem; }
.status-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.82rem; color: var(--text-secondary); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot-ok { background: var(--safe); }
.dot-off { background: var(--text-muted); }
.stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem; }
.stat { display: flex; flex-direction: column; background: var(--bg-elevated); padding: 0.4rem 0.6rem; border-radius: 6px; }
.stat-value { font-size: 0.9rem; font-weight: 700; color: var(--text-primary); }
.stat-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }
.hint { font-size: 0.68rem; color: var(--text-muted); }
.muted { color: var(--text-muted); font-size: 0.78rem; }
.update-msg { font-size: 0.72rem; padding: 0.4rem 0.6rem; border-radius: 4px; }
.update-msg.ok { background: rgba(34,197,94,0.1); color: var(--safe); }
.update-msg.err { background: rgba(239,68,68,0.1); color: var(--malicious); }
</style>
