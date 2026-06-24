<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { getCurrentWebview } from '@tauri-apps/api/webview'
import { useScanStore } from '../stores/scan'

const store = useScanStore()
const dragging = ref(false)
let unlistenDrop: (() => void) | null = null

onMounted(async () => {
  const webview = getCurrentWebview()
  unlistenDrop = await webview.onDragDropEvent((event) => {
    if (event.payload.type === 'over') {
      dragging.value = true
    } else if (event.payload.type === 'leave') {
      dragging.value = false
    } else if (event.payload.type === 'drop') {
      dragging.value = false
      const paths = event.payload.paths
      if (paths.length > 0) {
        store.scanFile(paths[0])
      }
    }
  })
})

onUnmounted(() => {
  unlistenDrop?.()
})

async function browseFile() {
  const selected = await open({ multiple: false, directory: false })
  if (typeof selected === 'string') {
    store.scanFile(selected)
  }
}
</script>

<template>
  <div
    class="drop-zone"
    :class="{ active: dragging, scanning: store.scanning }"
    @click="!store.scanning && browseFile()"
    @dragover.prevent
    @dragleave.prevent
    @drop.prevent
  >
    <div class="drop-icon">
      <svg v-if="!store.scanning" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="17 8 12 3 7 8"/>
        <line x1="12" y1="3" x2="12" y2="15"/>
      </svg>
      <div v-else class="spinner" />
    </div>
    <p class="drop-label">
      <template v-if="store.scanning">Analyse en cours…</template>
      <template v-else>
        Glisser un fichier ici<br />
        <span class="sub">ou cliquer pour parcourir</span>
      </template>
    </p>
    <div v-if="!store.scanning" class="supported">
      EXE · DLL · BAT · PS1 · VBS · ZIP · et plus
    </div>
  </div>
</template>

<style scoped>
.drop-zone {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  border: 2px dashed var(--border);
  border-radius: var(--radius-lg);
  padding: 3rem;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
  min-height: 200px;
}
.drop-zone:hover,
.drop-zone.active {
  border-color: var(--accent);
  background: rgba(59, 130, 246, 0.05);
}
.drop-zone.scanning {
  cursor: default;
  border-color: var(--border);
}
.drop-icon { color: var(--text-muted); }
.drop-label {
  text-align: center;
  color: var(--text-secondary);
  font-size: 1rem;
}
.sub {
  font-size: 0.8rem;
  color: var(--text-muted);
}
.supported {
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 0.05em;
}
.spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
