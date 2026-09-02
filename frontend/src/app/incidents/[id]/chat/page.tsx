'use client'

import React, { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  Bot,
  ChevronLeft,
  FileText,
  Loader2,
  Send,
  Shield,
  Sparkles,
  Terminal,
  User,
} from 'lucide-react'

import { createSession, getIncident, sendMessage } from '@/lib/api'
import type { ChatMessage, Incident } from '@/lib/types'
import { MitreTechniqueChip, SeverityBadge } from '@/components/ui/badges'
import { InvestigationReport } from '@/components/ui/InvestigationReport'
import { TtsControls } from '@/components/ui/TtsControls'

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
      <div className="flex justify-end gap-2.5">
        <div className="max-w-[80%] rounded-xl border border-[#10b981]/30 bg-[#10b981]/15 px-4 py-3 text-xs text-[#f3f4f6] leading-relaxed">
          {message.content}
        </div>
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[#171e28] border border-[#1f2937] text-[#10b981]">
          <User className="h-3.5 w-3.5" />
        </span>
      </div>
    )
  }

  const answerType = message.answer_type || 'FACTUAL'
  const confidence = message.ai_confidence !== undefined ? Math.round(message.ai_confidence * 100) : null

  return (
    <div className="flex gap-3">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981] mt-1">
        <Bot className="h-4 w-4" />
      </span>

      <div className="flex-1 max-w-[90%] rounded-xl border border-[#1f2937] bg-[#11161d] p-4 sm:p-5 space-y-3">
        {/* Confidence & Answer Type Header */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1f2937] pb-2.5 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                answerType === 'FACTUAL'
                  ? 'border border-[#0e7490] bg-[#083344] text-[#38bdf8]'
                  : answerType === 'INFERENCE'
                  ? 'border border-[#713f12] bg-[#422006] text-[#facc15]'
                  : 'border border-[#581c87] bg-[#3b0764] text-[#c084fc]'
              }`}
            >
              {answerType}
            </span>
            {confidence !== null && (
              <span className="text-[#9ca3af] text-[11px]">
                Confidence: <strong className="text-[#f3f4f6]">{confidence}%</strong>
              </span>
            )}
          </div>
          <span className="text-[10px] text-[#6b7280]">
            {new Date(message.timestamp).toLocaleTimeString()}
          </span>
        </div>

        {/* Structured Investigation Report Body */}
        <div className="text-xs text-[#d1d5db]">
          <InvestigationReport
            content={message.content}
            answerType={message.answer_type}
            confidence={message.ai_confidence}
          />
        </div>

        {/* Grounded Evidence Citations */}
        {message.evidence_ids && message.evidence_ids.length > 0 && (
          <div className="border-t border-[#1f2937] pt-2.5 flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-[#6b7280] text-[10px] uppercase">Grounded Evidence:</span>
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
            <span className="text-[#6b7280] text-[10px] uppercase">ATT&CK References:</span>
            {message.mitre_references.map((m) => (
              <MitreTechniqueChip key={m} techniqueId={m} />
            ))}
          </div>
        )}

        {/* RAG Knowledge Playbooks Used */}
        {message.rag_sources && message.rag_sources.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono text-[#9ca3af]">
            <span className="text-[#6b7280] text-[10px] uppercase">Playbook Sources:</span>
            {message.rag_sources.map((src) => (
              <span key={src} className="rounded bg-[#171e28] px-1.5 py-0.5 text-[10px] text-[#9ca3af] border border-[#1f2937]">
                {src}
              </span>
            ))}
          </div>
        )}

        {/* Sarvam TTS Audio Controls */}
        {message.isPersisted && (
          <div className="border-t border-[#1f2937] pt-2.5">
            <TtsControls messageId={message.id} />
          </div>
        )}
      </div>
    </div>
  )
}

export default function ChatPage({ params }: { params: Promise<{ id: string }> }) {
  const [incident, setIncident] = useState<Incident | null>(null)
  const [session, setSession] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [loading, setLoading] = useState(true)

  const bottom = useRef<HTMLDivElement>(null)

  useEffect(() => {
    params
      .then(({ id }) => Promise.all([getIncident(id), createSession(id)]))
      .then(([nextIncident, nextSession]) => {
        setIncident(nextIncident)
        setSession(nextSession.session_id)
      })
      .finally(() => setLoading(false))
  }, [params])

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, sending])

  const send = async (overridePrompt?: string) => {
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
      setMessages((items) => [
        ...items,
        {
          id: generateMessageId(),
          session_id: session,
          role: 'assistant',
          content: `Investigation query failed: ${e instanceof Error ? e.message : 'Unknown error'}`,
          timestamp: new Date().toISOString(),
        },
      ])
    } finally {
      setSending(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-xs text-[#9ca3af]">
        <Loader2 className="mr-2 h-4 w-4 animate-spin text-[#10b981]" />
        Initializing AI Copilot investigation session…
      </div>
    )
  }

  return (
    <div className="flex min-h-[calc(100vh-80px)] flex-col space-y-4">
      {/* Investigation Session Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-4">
        <div>
          <Link
            href={`/incidents/${incident?.id || ''}`}
            className="inline-flex items-center text-xs font-mono text-[#9ca3af] hover:text-[#f3f4f6] transition-colors"
          >
            <ChevronLeft className="mr-1 h-3.5 w-3.5" /> Back to Incident Workspace
          </Link>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <h1 className="text-base font-bold text-[#f3f4f6] flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-[#10b981]" />
              AI Investigation Copilot
            </h1>
            {incident && <SeverityBadge severity={incident.severity} />}
            <span className="font-mono text-xs text-[#9ca3af] truncate max-w-sm">
              {incident?.title}
            </span>
          </div>
        </div>

        {incident && (
          <Link
            href={`/incidents/${incident.id}/report`}
            className="btn-ghost text-xs py-1.5 px-3"
          >
            <FileText className="mr-1.5 h-3.5 w-3.5" />
            Executive Report
          </Link>
        )}
      </div>

      {/* Messages Viewport */}
      <div className="flex-1 space-y-4 overflow-y-auto">
        {messages.length === 0 && (
          <div className="card p-6 border-[#1f2937] bg-[#11161d]">
            <div className="flex gap-3">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981]">
                <Bot className="h-4 w-4" />
              </span>
              <div className="space-y-3">
                <div>
                  <h3 className="text-sm font-semibold text-[#f3f4f6]">
                    Evidence-Grounded Threat Analyst
                  </h3>
                  <p className="mt-1 text-xs text-[#9ca3af] leading-relaxed">
                    Ask questions regarding this incident. Answers are grounded in actual database logs,
                    mapped to MITRE ATT&CK techniques, and cite retrieved playbooks.
                  </p>
                </div>

                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#6b7280]">
                    Recommended Inquiries:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {SUGGESTIONS.map((q) => (
                      <button
                        key={q}
                        type="button"
                        onClick={() => send(q)}
                        className="rounded-lg border border-[#1f2937] bg-[#171e28] px-3 py-1.5 text-xs text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition text-left"
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

        {sending && (
          <div className="flex gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981]">
              <Bot className="h-4 w-4" />
            </span>
            <div className="rounded-xl border border-[#1f2937] bg-[#11161d] px-4 py-3 text-xs text-[#9ca3af] flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#10b981]" />
              Correlating evidence and synthesizing analysis…
            </div>
          </div>
        )}

        <div ref={bottom} />
      </div>

      {/* Sticky Chat Prompt Bar */}
      <div className="sticky bottom-0 border-t border-[#1f2937] bg-[#0b0f14]/90 pt-3 pb-2 backdrop-blur-md">
        <div className="flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Ask AI Copilot about this incident (e.g. 'Identify lateral movement attempts')..."
            rows={1}
            className="input flex-1 min-h-[44px] resize-none font-sans text-xs py-2.5"
          />

          <button
            type="button"
            onClick={() => send()}
            disabled={!input.trim() || sending}
            className="btn-primary px-4 py-2 self-end disabled:opacity-30"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>

        <p className="mt-1.5 flex items-center gap-1 font-mono text-[10px] text-[#6b7280]">
          <AlertCircle className="h-3 w-3" />
          Enter to send · Shift+Enter for newline · Grounded in verified telemetry
        </p>
      </div>
    </div>
  )
}
