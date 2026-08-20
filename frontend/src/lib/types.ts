/**
 * Shared TypeScript types — mirrors backend Pydantic schemas.
 */

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

export interface SecurityEvent {
  id: string
  source_ip: string
  destination_ip?: string
  username?: string
  hostname?: string
  event_type: string
  event_category: string
  timestamp: string
  description?: string
  raw_log: string
  source_file?: string
  is_flagged: boolean
  incident_id?: string
}

export interface AttackTechnique {
  id: string
  incident_id: string
  technique_id: string
  technique_name: string
  tactic: string
  sub_technique_id?: string
  sub_technique_name?: string
  confidence: number
  mapping_source: string
  url?: string
}

export interface Evidence {
  id: string
  incident_id: string
  event_id: string
  role: string
  description?: string
  sequence_order?: number
  event?: SecurityEvent
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CLOSED' | 'FALSE_POSITIVE'
export type AttackType =
  | 'BRUTE_FORCE'
  | 'ACCOUNT_COMPROMISE'
  | 'ACCOUNT_COMPROMISE_WITH_ESCALATION'
  | 'PRIVILEGE_ESCALATION'

export interface AttackPhase {
  phase: string
  technique: string
  technique_name: string
  description: string
  event_ids: string[]
  timestamp_start: string
  timestamp_end: string
  event_count: number
}

export interface AttackHypothesis {
  classification: string
  phases: AttackPhase[]
  narrative: string
  confidence: number
}

export interface Incident {
  id: string
  title: string
  description?: string
  attack_type: AttackType
  severity: Severity
  confidence: number
  status: IncidentStatus
  affected_username?: string
  affected_host?: string
  source_ip?: string
  first_seen: string
  last_seen: string
  event_count: number
  attack_hypothesis?: AttackHypothesis
  created_at: string
  updated_at: string
  techniques: AttackTechnique[]
  evidence: Evidence[]
}

export interface IncidentSummary {
  id: string
  title: string
  attack_type: AttackType
  severity: Severity
  confidence: number
  status: IncidentStatus
  affected_username?: string
  source_ip?: string
  first_seen: string
  last_seen: string
  event_count: number
  created_at: string
}

export interface IncidentListResponse {
  total: number
  items: IncidentSummary[]
}

export interface EvidenceListResponse {
  evidence: Evidence[]
}

export interface SessionCreateResponse {
  session_id: string
  incident_id: string
  created_at: string
}

export interface ChatMessage {
  id: string
  session_id: string
  role: 'user' | 'assistant'
  content: string
  evidence_ids?: string[]
  rag_chunks_used?: RagChunk[]
  answer_type?: 'FACTUAL' | 'INFERENCE' | 'RECOMMENDATION'
  ai_confidence?: number
  timestamp: string
}

export interface RagChunk {
  text: string
  title: string
  source: string
  distance: number
}

export interface ChatResponse {
  message_id: string
  answer: string
  evidence_ids: string[]
  mitre_references: string[]
  rag_sources: string[]
  answer_type: 'FACTUAL' | 'INFERENCE' | 'RECOMMENDATION'
  confidence: number
}

export interface MessageListResponse {
  session_id: string
  messages: ChatMessage[]
}

export interface LogUploadResponse {
  job_id: string
  events_parsed: number
  events_flagged: number
  incidents_created: number
  processing_time_ms: number
  source_file: string
}

export interface SecurityEventListResponse {
  total: number
  items: SecurityEvent[]
}

export interface DashboardSummary {
  total_incidents: number
  open_incidents: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  events_processed_total: number
  events_flagged_total: number
  incidents_by_type: Record<string, number>
  severity_distribution: Record<string, number>
  recent_incidents: IncidentSummary[]
}

export interface ReportCreateResponse {
  report_id: string
  download_url: string
}

export interface ReportOut {
  id: string
  incident_id: string
  generated_at: string
  format: string
  content: string
  ai_summary?: string
  recommended_actions?: string[]
}
