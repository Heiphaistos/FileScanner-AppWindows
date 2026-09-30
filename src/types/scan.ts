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

export interface VtEngine {
  engine: string
  category: string
  result: string
}

export interface VtSignature {
  verified: string
  signers: string
  product: string
  description: string
  copyright: string
}

export interface VtResult {
  positives: number
  total: number
  permalink: string
  scan_date: string
  detection_names: string[]
  suspicious: number
  harmless: number
  undetected: number
  engines: VtEngine[]
  popular_threat_label: string | null
  reputation: number
  type_description: string | null
  names: string[]
  tags: string[]
  first_submission: string | null
  times_submitted: number
  signature: VtSignature | null
  trusted_verdict: string | null
  sandbox_verdicts: string[]
  crowdsourced_yara: string[]
}

export type IntelStatus =
  | 'Malicious' | 'Suspicious' | 'Clean' | 'KnownGood' | 'NotFound' | 'Error' | 'NotConfigured'

export interface IntelResult {
  source: string
  kind: string
  status: IntelStatus
  detections: number | null
  total: number | null
  threat_names: string[]
  summary: string
  details: string[]
  link: string | null
}

export interface Factor {
  label: string
  delta: number
}

export interface Detection {
  id: string
  source: string
  title: string
  value: string
  severity: Severity
  confidence: number
  false_positive: number
  verdict: string
  what_it_does: string
  why_malicious: string
  why_legitimate: string
  base_confidence: number
  factors: Factor[]
  evidence: string[]
}

export interface Assessment {
  malicious_probability: number
  false_positive_probability: number
  label: string
  summary: string
  reasons_malicious: string[]
  reasons_legitimate: string[]
  method: string
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
  category: string
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
  explanation: string
  intel: IntelResult[]
  detections: Detection[]
  assessment: Assessment
}

export interface AppSettings {
  vt_api_key: string
  metadefender_api_key: string
  hybrid_analysis_api_key: string
  opentip_api_key: string
  otx_api_key: string
  abusech_api_key: string
  intel_free_lookups: boolean
  ai_enabled: boolean
  clamav_db_path: string
}

export type ExportFormat = 'json' | 'html' | 'txt' | 'md' | 'pdf'

/** Couleur d'une probabilité de menace réelle (mêmes seuils que les rapports). */
export function threatColor(p: number): string {
  if (p < 15) return '#22c55e'
  if (p < 40) return '#eab308'
  if (p < 70) return '#f97316'
  return '#ef4444'
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  Low: 'FAIBLE',
  Medium: 'MOYEN',
  High: 'ÉLEVÉ',
  Critical: 'CRITIQUE',
}

export const INTEL_LABELS: Record<IntelStatus, { label: string; color: string }> = {
  Malicious: { label: 'MALVEILLANT', color: '#ef4444' },
  Suspicious: { label: 'SUSPECT', color: '#eab308' },
  Clean: { label: 'RIEN TROUVÉ', color: '#22c55e' },
  KnownGood: { label: 'LÉGITIME CONNU', color: '#22c55e' },
  NotFound: { label: 'INCONNU', color: '#64748b' },
  Error: { label: 'INDISPONIBLE', color: '#64748b' },
  NotConfigured: { label: 'NON CONFIGURÉ', color: '#475569' },
}
