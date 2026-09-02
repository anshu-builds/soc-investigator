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
      <div className="border-l-2 border-accent-emerald/80 bg-elevated/50 p-3.5 rounded-r text-xs animate-fade-in">
        <div className="flex items-center justify-between text-[11px] font-mono text-ink-muted mb-1">
          <span className="font-semibold text-accent-emerald uppercase tracking-wider">
            ANALYST INQUIRY
          </span>
          <span>
            {message.timestamp ? format(new Date(message.timestamp), 'HH:mm:ss') : ''} UTC
          </span>
        </div>
        <p className="text-ink-primary whitespace-pre-wrap leading-relaxed">{message.content}</p>
      </div>
    )
  }

  const answerType = message.answer_type || 'FACTUAL'
  const confidence =
    message.ai_confidence !== undefined && message.ai_confidence !== null
      ? Math.round(message.ai_confidence * 100)
      : null

  return (
    <div className="border border-border/80 rounded bg-panel p-4 sm:p-5 space-y-3 animate-fade-in shadow-sm">
      {/* Dossier Assessment Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
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
        <span className="text-[10px] text-ink-muted font-mono">
          {message.timestamp ? format(new Date(message.timestamp), 'yyyy-MM-dd HH:mm:ss') : ''} UTC
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

      {/* Grounded Evidence References */}
      {message.evidence_ids && message.evidence_ids.length > 0 && (
        <div className="pt-2.5 border-t border-border-subtle/80 flex flex-wrap items-center gap-1.5 text-xs font-mono">
          <span className="text-ink-muted text-[10px] uppercase">Grounded Evidence:</span>
          {message.evidence_ids.map((eid) => (
            <span key={eid} className="evidence-chip">
              {eid}
            </span>
          ))}
        </div>
      )}

      {/* MITRE References */}
      {message.mitre_references && message.mitre_references.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
          <span className="text-ink-muted text-[10px] uppercase">MITRE Mapping:</span>
          {message.mitre_references.map((m) => (
            <span key={m} className="mitre-chip">
              {m}
            </span>
          ))}
        </div>
      )}

      {/* Audio Synthesis Playback Controls */}
      <div className="pt-2 border-t border-border-subtle/60">
        <TtsControls messageId={message.id} />
      </div>
    </div>
  )
}

export default function IncidentChatPage({ params }: { params: Promise<{ id: string }> }) {
  const { error: toastError } = useToast()

  const [incident, setIncident] = useState<Incident | null>(null)
  const [session, setSession] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [initError, setInitError] = useState<string | null>(null)

  const bottom = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    let isMounted = true
    params
      .then(async ({ id }) => {
        try {
          const inc = await getIncident(id)
          if (!isMounted) return
          setIncident(inc)

          const sess = await createSession(id)
          if (!isMounted) return
          setSession(sess.session_id)

          const list = await getMessages(sess.session_id)
          if (!isMounted) return
          setMessages(list.messages || [])
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
      <div className="p-8 text-center max-w-lg mx-auto mt-12 border border-severity-critical/30 rounded-lg bg-panel">
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
      {/* 1. TOP INCIDENT CONTEXT HEADER (Open Canvas) */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-3 shrink-0">
        <div>
          <Link
            href={`/incidents/${incident.id}`}
            className="inline-flex items-center text-xs font-mono text-ink-secondary hover:text-ink-primary transition-colors group"
          >
            <ChevronLeft className="mr-1 h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
            <span>Incident Workspace (INC-{incident.id.slice(0, 8)})</span>
          </Link>

          <div className="flex flex-wrap items-center gap-2 mt-1">
            <h1 className="text-base font-bold text-ink-primary truncate max-w-xl">
              {incident.title}
            </h1>
            <SeverityBadge severity={incident.severity} />
            <span className="font-mono text-xs text-ink-muted">·</span>
            <span className="font-mono text-xs text-ink-secondary">
              Confidence: <strong className="text-ink-primary">{Math.round(incident.confidence * 100)}%</strong>
            </span>
          </div>
        </div>

        <Link
          href={`/incidents/${incident.id}/report`}
          className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5"
        >
          <FileText className="h-3.5 w-3.5" />
          <span>Formal Report</span>
        </Link>
      </div>

      {/* 2. INVESTIGATION WORKBENCH FEED */}
      <div className="flex-1 overflow-y-auto pr-1 space-y-4">
        {messages.length === 0 ? (
          <div className="p-8 text-center border border-border/80 rounded bg-panel/40 space-y-3 max-w-2xl mx-auto my-8">
            <Sparkles className="mx-auto h-7 w-7 text-accent-emerald" />
            <h3 className="text-sm font-bold text-ink-primary">
              AI Investigation Copilot Active
            </h3>
            <p className="text-xs text-ink-secondary leading-relaxed max-w-lg mx-auto">
              Ask questions to correlate evidence, evaluate attack vectors, and inspect remediation protocols grounded directly in this incident&apos;s database telemetry.
            </p>
            <div className="pt-2 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((sug) => (
                <button
                  key={sug}
                  type="button"
                  onClick={() => send(sug)}
                  disabled={sending}
                  className="rounded border border-border/80 bg-elevated/60 px-2.5 py-1 text-xs text-ink-secondary hover:text-ink-primary hover:border-border-active transition-colors text-left"
                >
                  {sug}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((m) => <Answer key={m.id} message={m} />)
        )}

        {sending && (
          <div className="border border-accent-emerald/30 rounded bg-panel p-4 space-y-2 animate-pulse-subtle">
            <div className="flex items-center gap-2 text-xs font-mono text-accent-emerald">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>Correlating database evidence and synthesizing response…</span>
            </div>
          </div>
        )}

        <div ref={bottom} />
      </div>

      {/* 3. INVESTIGATION COMPOSER TOOLBAR */}
      <div className="pt-2 border-t border-border/80 shrink-0 space-y-2">
        {/* Quick Suggestion Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[10px] uppercase text-ink-muted">Inquiries:</span>
          {SUGGESTIONS.map((sug) => (
            <button
              key={sug}
              type="button"
              onClick={() => send(sug)}
              disabled={sending}
              className="rounded bg-elevated/70 px-2 py-0.5 text-[11px] text-ink-secondary hover:text-ink-primary border border-border/60 hover:border-border transition-colors truncate max-w-[260px]"
            >
              {sug}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="relative flex items-center">
          <textarea
            ref={textareaRef}
            rows={2}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Formulate investigation inquiry (Press Cmd+Enter to execute)…"
            className="input w-full pr-28 py-2 resize-none bg-panel/70 text-xs"
          />
          <div className="absolute right-2.5 flex items-center gap-2">
            <button
              type="button"
              onClick={() => send()}
              disabled={!input.trim() || sending}
              className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5 disabled:opacity-40"
            >
              {sending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <>
                  <span>Execute</span>
                  <Send className="h-3 w-3" />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
