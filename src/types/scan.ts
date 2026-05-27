export type Verdict = 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown'
export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

export interface Hashes {
  md5: string
  sha256: string
}

export interface PeSection {
  name: string
  virtual_size: number
  raw_size: number
  entropy: number
  characteristics: number
}

export interface PeInfo {
  is_64bit: boolean
  is_signed: boolean
  sections: PeSection[]
  imports: string[]
  entry_point: number
  entropy_max: number
  suspicious_imports: string[]
  is_packed: boolean
}

export interface ScriptInfo {
  obfuscation_detected: boolean
  dangerous_calls: string[]
  base64_blobs_count: number
  script_type: string
  matched_lines: ScriptMatchedLine[]
  base64_samples: string[]
}

export interface VtResult {
  positives: number
  total: number
  permalink: string
  scan_date: string
  detection_names: string[]
}

export interface YaraMatch {
  rule_name: string
  description: string
  severity: Severity
  matched_strings: string[]
}

export interface ScriptMatchedLine {
  line_number: number
  pattern: string
  line_content: string
}

export interface IoC {
  ioc_type: string
  value: string
  severity: Severity
  description: string
}

export interface ClamavResult {
  malware_name: string
  database: string
}

export interface ClamavStatus {
  loaded: boolean
  md5_count: number
  sha256_count: number
  db_path: string
  last_updated: string | null
}

export interface ScanResult {
  file_path: string
  file_name: string
  file_size: number
  mime_type: string
  hashes: Hashes
  verdict: Verdict
  verdict_score: number
  pe_info: PeInfo | null
  script_info: ScriptInfo | null
  virustotal: VtResult | null
  clamav: ClamavResult | null
  yara_matches: YaraMatch[]
  ai_verdict: string | null
  ioc_list: IoC[]
  scanned_at: string
}

export interface AppSettings {
  vt_api_key: string
  ai_enabled: boolean
  clamav_db_path: string
}

export type ExportFormat = 'json' | 'html' | 'txt' | 'md' | 'pdf'
