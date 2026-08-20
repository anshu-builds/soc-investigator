'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  ChevronLeft, Send, Bot, User as UserIcon, Database,
  Shield, Lightbulb, CheckCircle, AlertCircle, Loader2
} from 'lucide-react'
import { createSession, sendMessage, getMessages, getIncident } from '@/lib/api'
import type { ChatMessage, Incident } from '@/lib/types'
import { SeverityBadge } from '@/components/ui/badges'
import { MitreTechniqueChip } from '@/components/ui/badges'
import { format } from 'date-fns'

const SUGGESTED_QUESTIONS = [
  'What triggered this alert and when?',
  'What happened after the successful login?',
  'Which MITRE techniques were used?',
  'What evidence supports the privilege escalation?',
  'What are the recommended containment steps?',
  'How confident are we this is real vs. false positive?',
]

const ANSWER_TYPE_CONFIG = {
  FACTUAL:        { icon: CheckCircle,  color: 'text-green-400',  label: 'Evidence-Based' },
  INFERENCE:      { icon: Lightbulb,   color: 'text-yellow-400', label: 'AI Inference' },
  RECOMMENDATION: { icon: Shield,       color: 'text-blue-400',   label: 'Recommendation' },
}

function EvidenceCitation({ id, index }: { id: string; index: number }) {
  return (
    <span className="evidence-chip" title={id}>
      EV-{String(index + 1).padStart(3, '0')}
    </span>
  )
}

function MessageBubble({
  message,
  evidenceMap,
}: {
  message: ChatMessage
  evidenceMap: Map<string, number>
}) {
  const isUser = message.role === 'user'
  const typeConfig = message.answer_type
    ? ANSWER_TYPE_CONFIG[message.answer_type]
    : null

  // Render answer with clickable [EV-NNN] citations highlighted
  const renderContent = (text: string) => {
    const parts = text.split(/(\[EV-\d{3,}\])/g)
    return parts.map((part, i) => {
      if (part.match(/^\[EV-\d{3,}\]$/)) {
        return (
          <span key={i} className="evidence-chip mx-0.5 cursor-default" title="Evidence citation">
            {part}
          </span>
        )
      }
      return <span key={i}>{part}</span>
    })
  }

  return (
    <div className={`flex gap-3 animate-slide-in ${isUser ? 'justify-end' : 'justify-start'}`}>
      {!isUser && (
        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-glow-sm">
          <Bot className="w-4 h-4 text-white" />
        </div>
      )}

      <div className={`max-w-[85%] ${isUser ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
        {/* Message bubble */}
        <div className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
          isUser
            ? 'bg-accent-blue text-white rounded-tr-sm'
            : 'bg-bg-card border border-border text-slate-200 rounded-tl-sm'
        }`}>
          {isUser ? (
            <span>{message.content}</span>
          ) : (
            <div className="whitespace-pre-wrap">{renderContent(message.content)}</div>
          )}
        </div>

        {/* Metadata row for assistant messages */}
        {!isUser && (
          <div className="flex items-center flex-wrap gap-2 px-1">
            {/* Answer type */}
            {typeConfig && (
              <div className={`flex items-center gap-1 text-xs ${typeConfig.color}`}>
                <typeConfig.icon className="w-3 h-3" />
                {typeConfig.label}
              </div>
            )}

            {/* Confidence */}
            {message.ai_confidence !== undefined && (
              <span className="text-xs text-slate-500">
                {Math.round(message.ai_confidence * 100)}% confidence
              </span>
            )}

            {/* MITRE references */}
            {/* Evidence citation count */}
            {message.evidence_ids && message.evidence_ids.length > 0 && (
              <span className="text-xs text-cyan-500 flex items-center gap-1">
                <Database className="w-3 h-3" />
                {message.evidence_ids.length} evidence cited
              </span>
            )}

            {/* Timestamp */}
            <span className="text-xs text-slate-600">
              {format(new Date(message.timestamp), 'HH:mm')}
            </span>
          </div>
        )}
      </div>

      {isUser && (
        <div className="w-8 h-8 rounded-full bg-bg-tertiary border border-border flex items-center justify-center flex-shrink-0 mt-0.5">
          <UserIcon className="w-4 h-4 text-slate-400" />
        </div>
      )}
    </div>
  )
}

function TypingIndicator() {
  return (
    <div className="flex gap-3 justify-start animate-slide-in">
      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center flex-shrink-0 shadow-glow-sm">
        <Bot className="w-4 h-4 text-white" />
      </div>
      <div className="bg-bg-card border border-border rounded-2xl rounded-tl-sm px-4 py-3">
        <div className="flex items-center gap-1">
          {[0, 1, 2].map(i => (
            <div key={i} className="w-1.5 h-1.5 rounded-full bg-slate-500 typing-dot" style={{ animationDelay: `${i * 0.2}s` }} />
          ))}
          <span className="ml-2 text-xs text-slate-500">Analyzing evidence...</span>
        </div>
      </div>
    </div>
  )
}

export default function ChatPage({ params }: { params: { id: string } }) {
  const [incident, setIncident] = useState<Incident | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    Promise.all([
      getIncident(params.id),
      createSession(params.id),
    ]).then(([inc, session]) => {
      setIncident(inc)
      setSessionId(session.session_id)
    }).finally(() => setInitializing(false))
  }, [params.id])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, sending])

  const handleSend = async () => {
    if (!input.trim() || !sessionId || sending) return
    const userMsg: ChatMessage = {
      id: crypto.randomUUID(), session_id: sessionId, role: 'user',
      content: input.trim(), timestamp: new Date().toISOString(),
    }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setSending(true)
    try {
      const res = await sendMessage(sessionId, userMsg.content)
      const assistantMsg: ChatMessage = {
        id: res.message_id, session_id: sessionId, role: 'assistant',
        content: res.answer, evidence_ids: res.evidence_ids,
        answer_type: res.answer_type, ai_confidence: res.confidence,
        timestamp: new Date().toISOString(),
      }
      setMessages(prev => [...prev, assistantMsg])
    } catch (e: any) {
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(), session_id: sessionId, role: 'assistant',
        content: `⚠️ Error: ${e.message}`, timestamp: new Date().toISOString(),
      }])
    } finally {
      setSending(false)
    }
  }

  if (initializing) return (
    <div className="flex items-center justify-center h-screen">
      <div className="text-center">
        <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <p className="text-slate-400 text-sm">Initializing AI investigation session...</p>
      </div>
    </div>
  )

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="flex-shrink-0 px-5 py-4 border-b border-border bg-bg-secondary flex items-center gap-4">
        <Link href={`/incidents/${params.id}`} className="text-slate-400 hover:text-slate-200 transition-colors">
          <ChevronLeft className="w-5 h-5" />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse-slow" />
            <span className="text-sm font-semibold text-white truncate">
              AI Investigation: {incident?.title}
            </span>
          </div>
          {incident && (
            <div className="flex items-center gap-2 mt-0.5">
              <SeverityBadge severity={incident.severity} />
              <span className="text-xs text-slate-500">{incident.attack_type.replace(/_/g, ' ')}</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-cyan-400 bg-cyan-950/30 border border-cyan-800/40 px-2.5 py-1 rounded-full">
          <Bot className="w-3 h-3" />
          Evidence-Grounded AI
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Welcome message */}
        {messages.length === 0 && (
          <div className="animate-fade-in">
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center flex-shrink-0 shadow-glow-sm">
                <Bot className="w-4 h-4 text-white" />
              </div>
              <div className="bg-bg-card border border-border rounded-2xl rounded-tl-sm px-4 py-3 max-w-lg">
                <p className="text-sm text-slate-200 leading-relaxed">
                  I'm analyzing <span className="text-cyan-400 font-medium">{incident?.title}</span>.
                  Every answer I provide will cite specific evidence from the database using{' '}
                  <span className="evidence-chip text-xs">[EV-NNN]</span> references — no invented facts.
                </p>
                <p className="text-xs text-slate-500 mt-2">Ask me anything about this incident.</p>
              </div>
            </div>

            {/* Suggested questions */}
            <div className="mt-4 ml-11">
              <p className="text-xs text-slate-500 mb-2">Suggested questions:</p>
              <div className="flex flex-wrap gap-2">
                {SUGGESTED_QUESTIONS.map((q) => (
                  <button
                    key={q}
                    onClick={() => setInput(q)}
                    className="text-xs px-3 py-1.5 rounded-full bg-bg-tertiary border border-border hover:border-border-bright hover:text-slate-200 text-slate-400 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {messages.map((msg) => (
          <MessageBubble key={msg.id} message={msg} evidenceMap={new Map()} />
        ))}
        {sending && <TypingIndicator />}
        <div ref={bottomRef} />
      </div>

      {/* Input area */}
      <div className="flex-shrink-0 px-5 py-4 border-t border-border bg-bg-secondary">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <textarea
              className="input w-full resize-none pr-12 py-3 min-h-[48px] max-h-32"
              placeholder="Ask about this incident... (Enter to send, Shift+Enter for newline)"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
              }}
              rows={1}
            />
          </div>
          <button
            onClick={handleSend}
            disabled={!input.trim() || sending}
            className="w-12 h-12 rounded-xl bg-accent-blue hover:bg-blue-400 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center transition-colors flex-shrink-0"
          >
            {sending ? (
              <Loader2 className="w-5 h-5 text-white animate-spin" />
            ) : (
              <Send className="w-5 h-5 text-white" />
            )}
          </button>
        </div>
        <div className="mt-2 flex items-center gap-1 text-xs text-slate-600">
          <AlertCircle className="w-3 h-3" />
          All answers cite real database evidence. AI inferences are labeled separately.
        </div>
      </div>
    </div>
  )
}
