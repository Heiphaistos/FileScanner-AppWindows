<script setup lang="ts">
import { ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const confirming = ref(false)
const loading = ref(false)
const success = ref(false)
const error = ref<string | null>(null)
const quarPath = ref('')

function requestConfirm() {
  confirming.value = true
  error.value = null
}

function cancelConfirm() {
  confirming.value = false
}

async function executeQuarantine() {
  if (!store.result) return
  confirming.value = false
  loading.value = true
  error.value = null

  try {
    const path = await invoke<string>('quarantine_file', {
      filePath: store.result.file_path,
      sha256: store.result.hashes.sha256,
    })
    quarPath.value = path
    success.value = true
    // Reset le résultat du scan (fichier n'existe plus)
    store.reset()
  } catch (e) {
    error.value = String(e)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="quarantine-wrapper">

    <!-- Bouton principal — visible uniquement si non déjà mis en quarantaine -->
    <div v-if="!success" class="quarantine-section">
      <button
        v-if="!confirming"
        class="btn-quarantine"
        :disabled="loading"
        @click="requestConfirm"
      >
        <span v-if="loading" class="spinner" />
        <span v-else>🔒 Mettre en quarantaine</span>
      </button>

      <!-- Dialog de confirmation inline -->
      <div v-if="confirming" class="confirm-dialog">
        <p class="confirm-text">
          ⚠️ Le fichier sera <strong>chiffré et déplacé</strong> vers la quarantaine.<br />
          L'original sera <strong>supprimé définitivement</strong>.
        </p>
        <div class="confirm-actions">
          <button class="btn-cancel" @click="cancelConfirm">Annuler</button>
          <button class="btn-confirm-danger" @click="executeQuarantine">Confirmer</button>
        </div>
      </div>

      <!-- Erreur -->
      <p v-if="error" class="quarantine-error">{{ error }}</p>
    </div>

    <!-- Succès -->
    <div v-else class="quarantine-success">
      <span>✓ Fichier mis en quarantaine</span>
      <span class="quar-path">{{ quarPath }}</span>
    </div>

  </div>
</template>

<style scoped>
.quarantine-wrapper { margin-top: 0.5rem; }
.quarantine-section { display: flex; flex-direction: column; gap: 0.5rem; }

.btn-quarantine {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.4);
  border-radius: var(--radius);
  color: #ef4444;
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s;
}
.btn-quarantine:hover:not(:disabled) { background: rgba(239, 68, 68, 0.22); }
.btn-quarantine:disabled { opacity: 0.5; cursor: not-allowed; }

.confirm-dialog {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: var(--radius);
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.confirm-text { font-size: 0.8rem; color: var(--text-secondary); margin: 0; line-height: 1.5; }
.confirm-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }

.btn-cancel {
  padding: 0.3rem 0.75rem;
  background: transparent;
  border: 1px solid #475569;
  border-radius: var(--radius);
  color: var(--text-muted);
  font-size: 0.78rem;
  cursor: pointer;
}
.btn-cancel:hover { background: rgba(255,255,255,0.05); }

.btn-confirm-danger {
  padding: 0.3rem 0.75rem;
  background: #ef4444;
  border: none;
  border-radius: var(--radius);
  color: white;
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
}
.btn-confirm-danger:hover { background: #dc2626; }

.quarantine-error {
  font-size: 0.75rem;
  color: #ef4444;
  margin: 0;
}

.quarantine-success {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.5rem 0.75rem;
  background: rgba(34, 197, 94, 0.08);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: var(--radius);
  font-size: 0.8rem;
  color: #22c55e;
  font-weight: 600;
}
.quar-path {
  font-size: 0.68rem;
  color: var(--text-muted);
  font-family: monospace;
  word-break: break-all;
}

.spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid rgba(239, 68, 68, 0.3);
  border-top-color: #ef4444;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
