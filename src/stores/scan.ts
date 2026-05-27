import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { save } from '@tauri-apps/plugin-dialog'
import type { AppSettings, ExportFormat, ScanResult } from '../types/scan'

type ScanPhase = 'idle' | 'hashing' | 'mime' | 'pe' | 'script' | 'yara' | 'virustotal' | 'verdict' | 'done' | 'error'

export const useScanStore = defineStore('scan', {
  state: () => ({
    result: null as ScanResult | null,
    scanning: false,
    phase: 'idle' as ScanPhase,
    error: null as string | null,
    settings: {
      vt_api_key: '',
      ai_enabled: false,
      clamav_db_path: '',
    } as AppSettings,
    settingsLoaded: false,
  }),

  getters: {
    hasResult: (s) => s.result !== null,
    verdictColor: (s) => {
      if (!s.result) return '#6b7280'
      const map: Record<string, string> = {
        Safe: '#22c55e',
        Suspicious: '#f97316',
        Malicious: '#ef4444',
        Unknown: '#6b7280',
      }
      return map[s.result.verdict] ?? '#6b7280'
    },
    verdictLabel: (s) => {
      if (!s.result) return ''
      const map: Record<string, string> = {
        Safe: 'SAIN',
        Suspicious: 'SUSPECT',
        Malicious: 'MALVEILLANT',
        Unknown: 'INCONNU',
      }
      return map[s.result.verdict] ?? s.result.verdict
    },
  },

  actions: {
    async scanFile(filePath: string) {
      this.scanning = true
      this.error = null
      this.result = null
      this.phase = 'hashing'

      try {
        this.result = await invoke<ScanResult>('scan_file', { filePath })
        this.phase = 'done'
      } catch (e) {
        this.error = String(e)
        this.phase = 'error'
      } finally {
        this.scanning = false
      }
    },

    async loadSettings() {
      try {
        this.settings = await invoke<AppSettings>('get_settings')
        this.settingsLoaded = true
      } catch {
        this.settingsLoaded = true
      }
    },

    async saveSettings() {
      await invoke('save_settings', { appSettings: this.settings })
    },

    async exportReport(format: ExportFormat) {
      if (!this.result) return

      const extensions: Record<ExportFormat, string[]> = {
        json: ['json'],
        html: ['html'],
        txt: ['txt'],
        md: ['md'],
        pdf: ['pdf'],
      }

      const outputPath = await save({
        filters: [{ name: format.toUpperCase(), extensions: extensions[format] }],
        defaultPath: `rapport_${this.result.file_name}.${format}`,
      })

      if (!outputPath) return

      await invoke('export_report', {
        result: this.result,
        format,
        outputPath,
      })
    },

    reset() {
      this.result = null
      this.phase = 'idle'
      this.error = null
    },
  },
})
