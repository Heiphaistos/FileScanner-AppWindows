<script setup lang="ts">
import { ref } from 'vue'
import DropZone from './components/DropZone.vue'
import VerdictDisplay from './components/VerdictDisplay.vue'
import IoCTable from './components/IoCTable.vue'
import PeDetails from './components/PeDetails.vue'
import StringsDetail from './components/StringsDetail.vue'
import SettingsPanel from './components/SettingsPanel.vue'
import ExportMenu from './components/ExportMenu.vue'
import ClamavPanel from './components/ClamavPanel.vue'
import { useScanStore } from './stores/scan'

const store = useScanStore()
const tab = ref<'verdict' | 'ioc' | 'pe' | 'strings'>('verdict')

function resetScan() {
  store.reset()
  tab.value = 'verdict'
}
</script>

<template>
  <div class="app-layout">

    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="logo">
        <span class="logo-icon">🛡</span>
        <span class="logo-text">FileScanner</span>
      </div>

      <SettingsPanel />
      <ClamavPanel />
      <ExportMenu />

      <div v-if="store.hasResult" style="margin-top: auto;">
        <button class="btn btn-ghost" style="width: 100%;" @click="resetScan">
          ↺ Nouveau scan
        </button>
      </div>
    </aside>

    <!-- Main -->
    <main class="main-panel">

      <!-- Header -->
      <div class="top-bar">
        <span class="top-title">Moteur d'Analyse de Sécurité</span>
        <span v-if="store.scanning" class="scanning-label">Analyse en cours…</span>
      </div>

      <!-- Drop zone (si pas de résultat) -->
      <div v-if="!store.hasResult && !store.scanning" class="center-panel">
        <DropZone />
        <div v-if="store.error" class="error-block">
          {{ store.error }}
        </div>
      </div>

      <!-- Scanning -->
      <div v-if="store.scanning" class="center-panel scanning-panel">
        <DropZone />
      </div>

      <!-- Résultat -->
      <div v-if="store.hasResult" class="result-panel">

        <!-- Tabs -->
        <div class="tabs">
          <button :class="['tab', tab === 'verdict' && 'active']" @click="tab = 'verdict'">
            Verdict
          </button>
          <button
            :class="['tab', tab === 'ioc' && 'active']"
            @click="tab = 'ioc'"
          >
            IoC
            <span v-if="store.result && (store.result.ioc_list.length + store.result.yara_matches.length) > 0" class="tab-count">
              {{ store.result.ioc_list.length + store.result.yara_matches.length }}
            </span>
          </button>
          <button
            v-if="store.result?.pe_info || store.result?.script_info"
            :class="['tab', tab === 'pe' && 'active']"
            @click="tab = 'pe'"
          >
            Analyse binaire
          </button>
          <button
            v-if="store.result && (store.result.yara_matches.length > 0 || store.result.script_info?.matched_lines.length || store.result.pe_info?.suspicious_imports.length || store.result.virustotal?.detection_names.length)"
            :class="['tab', tab === 'strings' && 'active']"
            @click="tab = 'strings'"
          >
            Strings
            <span
              v-if="store.result && (store.result.yara_matches.length + (store.result.script_info?.matched_lines.length ?? 0)) > 0"
              class="tab-count"
            >
              {{ store.result.yara_matches.length + (store.result.script_info?.matched_lines.length ?? 0) }}
            </span>
          </button>
        </div>

        <!-- Tab content -->
        <div class="tab-content">
          <VerdictDisplay v-if="tab === 'verdict'" />
          <IoCTable v-if="tab === 'ioc'" />
          <PeDetails v-if="tab === 'pe'" />
          <StringsDetail v-if="tab === 'strings'" />
        </div>

      </div>
    </main>

  </div>
</template>

<style scoped>
.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-primary);
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}
.logo-icon { font-size: 1.3rem; }

.top-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.875rem 1.5rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
}
.top-title { font-size: 0.8rem; font-weight: 600; color: var(--text-secondary); letter-spacing: 0.05em; text-transform: uppercase; }
.scanning-label { font-size: 0.78rem; color: var(--accent); }

.center-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  gap: 1rem;
}

.error-block {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--malicious);
  border-radius: var(--radius);
  padding: 0.75rem 1rem;
  color: var(--malicious);
  font-size: 0.85rem;
  max-width: 500px;
  width: 100%;
}

.result-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.tabs {
  display: flex;
  gap: 0;
  padding: 0 1.5rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
}
.tab {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.75rem 1rem;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 0.82rem;
  font-weight: 500;
  transition: all 0.15s;
}
.tab:hover { color: var(--text-primary); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-count {
  background: var(--malicious);
  color: white;
  padding: 0.1rem 0.4rem;
  border-radius: 10px;
  font-size: 0.65rem;
  font-weight: 700;
}

.tab-content {
  flex: 1;
  overflow-y: auto;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
