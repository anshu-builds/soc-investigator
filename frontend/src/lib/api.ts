import type {
  ChatResponse,
  DashboardSummary,
  EvidenceListResponse,
  Incident,
  IncidentListResponse,
  LogUploadResponse,
  MessageListResponse,
  ReportCreateResponse,
  ReportOut,
  SecurityEventListResponse,
  SessionCreateResponse,
} from './types'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || ''

function getToken(): string {
  if (typeof window === 'undefined') return ''
  return localStorage.getItem('soc_token') || ''
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }

  return res.json()
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return request<DashboardSummary>('/api/dashboard/summary')
}

export interface IncidentFilters {
  page?: number
  limit?: number
  severity?: string
  status?: string
  attack_type?: string
}

export async function getIncidents(filters: IncidentFilters = {}): Promise<IncidentListResponse> {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => v !== undefined && params.set(k, String(v)))
  return request<IncidentListResponse>(`/api/incidents?${params}`)
}

export async function getIncident(id: string): Promise<Incident> {
  return request<Incident>(`/api/incidents/${id}`)
}

export async function updateIncidentStatus(id: string, status: string): Promise<Incident> {
  return request<Incident>(`/api/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export async function getEvidence(incidentId: string): Promise<EvidenceListResponse> {
  return request<EvidenceListResponse>(`/api/incidents/${incidentId}/evidence`)
}

export async function createSession(incidentId: string): Promise<SessionCreateResponse> {
  return request<SessionCreateResponse>(`/api/incidents/${incidentId}/sessions`, {
    method: 'POST',
  })
}

export async function sendMessage(sessionId: string, message: string): Promise<ChatResponse> {
  return request<ChatResponse>(`/api/sessions/${sessionId}/chat`, {
    method: 'POST',
    body: JSON.stringify({ message }),
  })
}

export async function getMessages(sessionId: string): Promise<MessageListResponse> {
  return request<MessageListResponse>(`/api/sessions/${sessionId}/messages`)
}

export async function uploadLogs(file: File, sourceName?: string): Promise<LogUploadResponse> {
  const token = getToken()
  const formData = new FormData()
  formData.append('file', file)
  if (sourceName) formData.append('source_name', sourceName)

  const res = await fetch(`${BASE_URL}/api/logs/upload`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Upload failed')
  }
  return res.json()
}

export async function getLogs(params: Record<string, string> = {}): Promise<SecurityEventListResponse> {
  const qs = new URLSearchParams(params)
  return request<SecurityEventListResponse>(`/api/logs?${qs}`)
}

export async function createReport(
  incidentId: string,
  options: { format?: string; include_ai_summary?: boolean } = {},
): Promise<ReportCreateResponse> {
  return request<ReportCreateResponse>(`/api/incidents/${incidentId}/report`, {
    method: 'POST',
    body: JSON.stringify({ format: 'MARKDOWN', include_ai_summary: true, ...options }),
  })
}

export async function getReport(reportId: string): Promise<ReportOut> {
  return request<ReportOut>(`/api/reports/${reportId}`)
}

export function getReportDownloadUrl(reportId: string): string {
  const token = getToken()
  return `${BASE_URL}/api/reports/${reportId}/download?token=${token}`
}
