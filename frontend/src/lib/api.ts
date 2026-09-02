import type {
  ChatResponse,
  DashboardSummary,
  EvidenceListResponse,
  Incident,
  IncidentListResponse,
  LogUploadResponse,
  MessageListResponse,
  NLQueryResponse,
  ReportCreateResponse,
  ReportOut,
  SecurityEventListResponse,
  SessionCreateResponse,
  UserSession,
  WazuhPollResponse,
  WazuhStatusResponse,
} from './types'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || ''

export function getToken(): string {
  if (typeof window === 'undefined') return ''
  return localStorage.getItem('soc_token') || ''
}

export function parseJwt(token: string): UserSession | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    let base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (base64.length % 4) base64 += '='
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    const payload = JSON.parse(json)
    if (!payload.sub || !payload.exp) return null
    return {
      userId: String(payload.sub),
      email: String(payload.email || 'analyst@soc.local'),
      role: (payload.role || 'analyst').toLowerCase(),
      exp: Number(payload.exp),
    }
  } catch {
    return null
  }
}

export function getCurrentUser(): UserSession | null {
  const token = getToken()
  if (!token) return null
  const user = parseJwt(token)
  if (!user) return null
  if (user.exp * 1000 < Date.now()) {
    logout()
    return null
  }
  return user
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

export interface TTSResponse {
  audio_clips_base64: string[]
  content_type: string
  chunk_count: number
}

export async function getMessageAudio(messageId: string, signal?: AbortSignal): Promise<TTSResponse> {
  return request<TTSResponse>(`/api/messages/${messageId}/tts`, {
    method: 'POST',
    signal,
  })
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

export async function login(
  email: string,
  password: string,
): Promise<{ access_token: string; token_type: string; expires_in: number }> {
  const data = await request<{ access_token: string; token_type: string; expires_in: number }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  if (typeof window !== 'undefined' && data.access_token) {
    localStorage.setItem('soc_token', data.access_token)
  }
  return data
}

export function logout(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('soc_token')
  }
}

export function getReportDownloadUrl(reportId: string): string {
  return `${BASE_URL}/api/reports/${reportId}/download`
}

export async function downloadReportFile(reportId: string): Promise<Blob> {
  const token = getToken()
  const res = await fetch(`${BASE_URL}/api/reports/${reportId}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    throw new Error('Failed to download report')
  }
  return res.blob()
}

export async function getWazuhStatus(): Promise<WazuhStatusResponse> {
  return request<WazuhStatusResponse>('/api/integrations/wazuh/status')
}

export async function triggerWazuhPoll(): Promise<WazuhPollResponse> {
  return request<WazuhPollResponse>('/api/integrations/wazuh/poll', {
    method: 'POST',
  })
}

export async function sendNLQuery(question: string): Promise<NLQueryResponse> {
  return request<NLQueryResponse>('/api/nlu/query', {
    method: 'POST',
    body: JSON.stringify({ question }),
  })
}
