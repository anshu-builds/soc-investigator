'use client'

import React, { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  ChevronLeft,
  Copy,
  ExternalLink,
  FileText,
  Loader2,
  Lock,
  MessageSquare,
  RefreshCw,
  Send,
  Server,
  Shield,
  Sparkles,
  Terminal,
  User,
  Wifi,
} from 'lucide-react'
import { format } from 'date-fns'

import { createSession, getIncident, getMessages, sendMessage } from '@/lib/api'
import type { ChatMessage, Incident } from '@/lib/types'
import { AttackTypeLabel, MitreTechniqueChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { InvestigationReport } from '@/components/ui/InvestigationReport'
import { TtsControls } from '@/components/ui/TtsControls'
import { useToast } from '@/components/ui/Toast'

const SUGGESTIONS = [
  'What triggered this alert and when?',
  'Which MITRE techniques were identified?',
  'What database evidence supports this incident?',
  'What are the recommended containment steps?',
]

const generateMessageId = (): string => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

function Answer({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'

  if (isUser) {
    return (
      <div className="flex justify-end gap-2.5 animate-fade-in">
        <div className="max-w-[80%] sm:max-w-[70%] rounded-lg border border-border/80 bg-elevated/70 px-4 py-2.5 text-xs text-ink-primary leading-relaxed shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-1.5 border-b border-border-subtle pb-1 text-[10px] font-mono text-ink-muted">
            <span className="font-semibold text-ink-secondary uppercase tracking-wider">Security Analyst</span>
            <span>
              {message.timestamp ? format(new Date(message.timestamp), 'HH:mm:ss') : ''}
            </span>
          </div>
          <p className="whitespace-pre-wrap">{message.content}</p>
        </div>
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-elevated border border-border text-ink-muted shadow-sm mt-0.5">
          <User className="h-3.5 w-3.5" />
        </div>
      </div>
    )
  }

  const answerType = message.answer_type || 'FACTUAL'
  const confidence =
    message.ai_confidence !== undefined && message.ai_confidence !== null
      ? Math.round(message.ai_confidence * 100)
      : null

  return (
    <div className="flex gap-2.5 animate-fade-in">
      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald shadow-sm mt-1">
        <Bot className="h-3.5 w-3.5" />
      </div>

      <div className="flex-1 max-w-[95%] lg:max-w-[90%] rounded-lg border border-border/80 bg-panel p-4 sm:p-5 space-y-3.5 shadow-sm">
        {/* Confidence & Answer Type Header */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle pb-2.5 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                answerType === 'FACTUAL'
                  ? 'border border-[#0e7490] bg-[#083344] text-[#38bdf8]'
                  : answerType === 'INFERENCE'
                  ? 'border border-[#713f12] bg-[#422006] text-[#facc15]'
                  : answerType === 'RECOMMENDATION'
                  ? 'border border-[#065f46] bg-[#064e3b] text-[#34d399]'
                  : 'border border-[#581c87] bg-[#3b0764] text-[#c084fc]'
              }`}
            >
              {answerType}
            </span>
            {confidence !== null && (
              <span className="text-ink-muted text-[11px]">
                Grounding Confidence: <strong className="text-ink-primary">{confidence}%</strong>
              </span>
            )}
          </div>
          <span className="text-[10px] text-ink-muted">
            {message.timestamp ? format(new Date(message.timestamp), 'yyyy-MM-dd HH:mm:ss') : ''}
          </span>
        </div>

        {/* Structured Investigation Report Body */}
        <div className="text-xs text-ink-primary leading-relaxed">
          <InvestigationReport
            content={message.content}
            answerType={message.answer_type}
            confidence={message.ai_confidence}
          />
        </div>

        {/* Grounded Evidence Citations */}
        {message.evidence_ids && message.evidence_ids.length > 0 && (
          <div className="border-t border-border-subtle pt-2.5 flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-ink-muted text-[10px] uppercase font-semibold">Grounded Evidence:</span>
            {message.evidence_ids.map((evId) => (
              <span key={evId} className="evidence-chip">
                {evId}
              </span>
            ))}
          </div>
        )}

        {/* MITRE Technique References */}
        {message.mitre_references && message.mitre_references.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-ink-muted text-[10px] uppercase font-semibold">MITRE ATT&CK:</span>
            {message.mitre_references.map((m) => (
              <MitreTechniqueChip key={m} techniqueId={m} />
            ))}
          </div>
        )}

        {/* RAG Knowledge Playbooks Used */}
        {message.rag_sources && message.rag_sources.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono text-ink-secondary">
            <span className="text-ink-muted text-[10px] uppercase font-semibold">Retrieved Playbooks:</span>
            {message.rag_sources.map((src) => (
              <span
                key={src}
                className="rounded bg-elevated px-2 py-0.5 text-[10px] text-ink-secondary border border-border"
              >
                {src}
              </span>
            ))}
          </div>
        )}

        {/* Sarvam TTS Audio Controls */}
        {message.isPersisted && (
          <div className="border-t border-border-subtle pt-2.5">
            <TtsControls messageId={message.id} />
          </div>
        )}
      </div>
    </div>
  )
}

export default function ChatPage({ params }: { params: Promise<{ id: string }> }) {
  const { error: toastError } = useToast()

  const [incident, setIncident] = useState<Incident | null>(null)
  const [session, setSession] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [loading, setLoading] = useState(true)
  const [initError, setInitError] = useState<string | null>(null)

  const bottom = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Initialize incident and session lifecycle
  useEffect(() => {
    let isMounted = true

    params
      .then(async ({ id }) => {
        try {
          const nextIncident = await getIncident(id)
          if (!isMounted) return
          setIncident(nextIncident)

          // If incident is closed or false-positive, session creation is disallowed by backend
          if (nextIncident.status === 'CLOSED' || nextIncident.status === 'FALSE_POSITIVE') {
            setInitError(
              `Incident is currently marked as ${nextIncident.status}. Reopen the incident in the Workspace to resume AI Copilot investigation.`
            )
            setLoading(false)
            return
          }

          // Check if existing session can be reused from sessionStorage
          const storageKey = `soc_copilot_session_${id}`
          const existingSessionId =
            typeof window !== 'undefined' ? sessionStorage.getItem(storageKey) : null

          let activeSessionId = existingSessionId

          if (activeSessionId) {
            try {
              // Attempt to load existing session messages
              const history = await getMessages(activeSessionId)
              if (isMounted) {
                setSession(activeSessionId)
                setMessages(
                  history.messages.map((m) => ({
                    ...m,
                    isPersisted: m.role === 'assistant',
                  }))
                )
              }
            } catch {
              // Existing session invalid or expired; create a new session
              activeSessionId = null
            }
          }

          if (!activeSessionId) {
            const nextSession = await createSession(id)
            if (isMounted) {
              setSession(nextSession.session_id)
              if (typeof window !== 'undefined') {
                sessionStorage.setItem(storageKey, nextSession.session_id)
              }
              setMessages([])
            }
          }
        } catch (e) {
          if (isMounted) {
            setInitError(e instanceof Error ? e.message : 'Unable to initialize investigation session')
          }
        } finally {
          if (isMounted) setLoading(false)
        }
      })
      .catch((e) => {
        if (isMounted) {
          setInitError(e instanceof Error ? e.message : 'Failed to load incident parameters')
          setLoading(false)
        }
      })

    return () => {
      isMounted = false
    }
  }, [params])

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, sending])

  const send = useCallback(
    async (overridePrompt?: string) => {
      const promptToSend = (overridePrompt || input).trim()
      if (!promptToSend || !session || sending) return

      const userMessage: ChatMessage = {
        id: generateMessageId(),
        session_id: session,
        role: 'user',
        content: promptToSend,
        timestamp: new Date().toISOString(),
      }

      setMessages((items) => [...items, userMessage])
      setInput('')
      setSending(true)

      try {
        const response = await sendMessage(session, promptToSend)
        setMessages((items) => [
          ...items,
          {
            id: response.message_id,
            session_id: session,
            role: 'assistant',
            content: response.answer,
            evidence_ids: response.evidence_ids,
            mitre_references: response.mitre_references,
            rag_sources: response.rag_sources,
            answer_type: response.answer_type,
            ai_confidence: response.confidence,
            timestamp: new Date().toISOString(),
            isPersisted: true,
          },
        ])
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : 'Failed to retrieve AI analysis'
        toastError('Copilot Query Failed', errMsg)
        setMessages((items) => [
          ...items,
          {
            id: generateMessageId(),
            session_id: session,
            role: 'assistant',
            content: `Investigation analysis failed: ${errMsg}`,
            timestamp: new Date().toISOString(),
          },
        ])
      } finally {
        setSending(false)
        setTimeout(() => textareaRef.current?.focus(), 50)
      }
    },
    [input, session, sending, toastError]
  )

  if (loading) {
    return (
      <div className="flex min-h-[65vh] flex-col items-center justify-center space-y-3 text-xs text-ink-secondary">
        <Loader2 className="h-6 w-6 animate-spin text-accent-emerald" />
        <p className="font-mono">Establishing secure AI investigation session…</p>
      </div>
    )
  }

  if (initError || !incident) {
    return (
      <div className="card p-8 text-center max-w-lg mx-auto mt-12 border-severity-critical/30 bg-panel">
        <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
        <h2 className="mt-3 text-base font-semibold text-ink-primary">
          Unable to Initialize Investigation Session
        </h2>
        <p className="text-xs text-ink-secondary mt-1.5 leading-relaxed">{initError}</p>
        <div className="mt-5 flex justify-center gap-3">
          <Link
            href={`/incidents/${incident?.id || ''}`}
            className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1"
          >
            <ChevronLeft className="h-3.5 w-3.5" /> Return to Workspace
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-[calc(100vh-100px)] space-y-3">
      {/* Top Workstation Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3 shrink-0">
        <div>
          <Link
            href={`/incidents/${incident.id}`}
            className="inline-flex items-center text-xs font-mono text-ink-secondary hover:text-ink-primary transition-colors group"
          >
            <ChevronLeft className="mr-1 h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
            <span>Back to Incident Workspace</span>
          </Link>

          <div className="mt-1 flex flex-wrap items-center gap-2">
            <h1 className="text-base font-bold text-ink-primary flex items-center gap-1.5">
              <Sparkles className="h-4 w-4 text-accent-emerald" />
              <span>AI Investigation Copilot</span>
            </h1>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <span className="font-mono text-xs text-ink-secondary truncate max-w-md">
              {incident.title}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href={`/incidents/${incident.id}/report`}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Open formal executive report"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Formal Report</span>
          </Link>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* Left Column: Incident Telemetry & Scope Sidebar */}
        <div className="hidden lg:flex w-72 shrink-0 flex-col space-y-3 overflow-y-auto pr-1">
          {/* Incident Telemetry Card */}
          <div className="card p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="font-mono text-[10px] uppercase font-semibold text-ink-muted">
                Investigation Scope
              </span>
              <span className="inline-flex items-center gap-1 text-[10px] font-mono text-accent-emerald">
                <span className="h-1.5 w-1.5 rounded-full bg-accent-emerald animate-pulse" />
                <span>Connected</span>
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-[11px]">
              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Attack Vector</span>
                <div className="mt-0.5">
                  <AttackTypeLabel attackType={incident.attack_type} />
                </div>
              </div>

              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Target User</span>
                <span className="text-[#facc15] font-semibold block mt-0.5 truncate">
                  {incident.affected_username || '—'}
                </span>
              </div>

              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Host</span>
                <span className="text-ink-primary font-semibold block mt-0.5 truncate">
                  {incident.affected_host || '—'}
                </span>
              </div>

              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Source IP</span>
                <span className="text-accent-cyan font-semibold block mt-0.5 truncate">
                  {incident.source_ip || '—'}
                </span>
              </div>

              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Evidence Base</span>
                <span className="text-accent-emerald font-semibold block mt-0.5">
                  {incident.event_count} telemetry events
                </span>
              </div>
            </div>
          </div>

          {/* Quick Investigation Inquiries */}
          <div className="card p-4 space-y-2.5 flex-1">
            <span className="font-mono text-[10px] uppercase font-semibold text-ink-muted block">
              Suggested Inquiries
            </span>
            <div className="space-y-1.5">
              {SUGGESTIONS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => send(q)}
                  disabled={sending}
                  className="w-full rounded-lg border border-border-subtle bg-elevated/60 p-2 text-left text-xs text-ink-secondary hover:text-ink-primary hover:border-border hover:bg-elevated transition active:scale-[0.98] disabled:opacity-50"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Chat Messages & Input Composer */}
        <div className="flex-1 flex flex-col min-w-0 card p-4 overflow-hidden">
          {/* Scrollable Message History */}
          <div className="flex-1 space-y-4 overflow-y-auto pr-2 pb-2">
            {messages.length === 0 && (
              <div className="rounded-xl border border-border-subtle bg-canvas/40 p-6">
                <div className="flex gap-3.5">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-accent-emerald/40 bg-accent-emerald/10 text-accent-emerald">
                    <Bot className="h-5 w-5" />
                  </div>
                  <div className="space-y-3">
                    <div>
                      <h3 className="text-sm font-semibold text-ink-primary">
                        Evidence-Grounded AI Security Copilot
                      </h3>
                      <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
                        Formulate hypotheses, dissect attack patterns, and review containment options.
                        Every response is grounded in correlated security events, mapped to MITRE ATT&CK
                        techniques, and supported by security playbooks.
                      </p>
                    </div>

                    <div className="space-y-2 pt-1">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-ink-muted block">
                        Click to initiate inquiry:
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {SUGGESTIONS.map((q) => (
                          <button
                            key={q}
                            type="button"
                            onClick={() => send(q)}
                            disabled={sending}
                            className="rounded-lg border border-border bg-elevated px-3 py-1.5 text-xs text-ink-secondary hover:text-ink-primary hover:border-border-active transition text-left"
                          >
                            {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {messages.map((m) => (
              <Answer key={m.id} message={m} />
            ))}

            {/* AI Synthesizing State */}
            {sending && (
              <div className="flex gap-3 animate-fade-in">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-accent-emerald/40 bg-accent-emerald/10 text-accent-emerald shadow-sm">
                  <Bot className="h-4 w-4" />
                </div>
                <div className="rounded-2xl border border-border bg-panel px-4 py-3 text-xs text-ink-secondary flex items-center gap-2 shadow-sm">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-accent-emerald" />
                  <span>Analyzing evidence telemetry and synthesizing tactical response…</span>
                </div>
              </div>
            )}

            <div ref={bottom} />
          </div>

          {/* Sticky Analyst Composer */}
          <div className="border-t border-border pt-3 shrink-0">
            <div className="flex gap-2">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    send()
                  }
                }}
                placeholder="Ask AI Copilot about this incident (e.g. 'Identify lateral movement indicators')..."
                rows={2}
                disabled={sending}
                className="input flex-1 resize-none font-sans text-xs py-2.5 disabled:opacity-50"
              />

              <button
                type="button"
                onClick={() => send()}
                disabled={!input.trim() || sending}
                className="btn-primary px-4 self-end h-10 disabled:opacity-30 flex items-center justify-center"
                title="Send inquiry"
              >
                {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              </button>
            </div>

            <p className="mt-1.5 flex items-center gap-1 font-mono text-[10px] text-ink-muted">
              <AlertCircle className="h-3 w-3 shrink-0" />
              <span>Press Enter to send · Shift+Enter for new line · Grounded in verified telemetry</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
