'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AlertCircle, Bot, ChevronLeft, Loader2, Send, User } from 'lucide-react'
import { createSession, getIncident, sendMessage } from '@/lib/api'
import type { ChatMessage, Incident } from '@/lib/types'
import { SeverityBadge } from '@/components/ui/badges'
import { InvestigationReport } from '@/components/ui/InvestigationReport'

const SUGGESTIONS = ['What triggered this alert and when?', 'Which MITRE techniques were used?', 'What evidence supports this incident?', 'What are the recommended containment steps?']
function Answer({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  return (
    <div className={`flex gap-3 ${isUser ? 'justify-end' : ''}`}>
      {!isUser && (
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#f0f8f4] self-start mt-1">
          <Bot className="h-4 w-4 text-[#168a52]" />
        </span>
      )}
      {isUser ? (
        <div className="max-w-[85%] rounded-xl px-4 py-3 text-sm leading-6 bg-[#168a52] text-white">
          {message.content}
        </div>
      ) : (
        <div className="flex-1 max-w-[85%] border border-[#e6e8eb] bg-white rounded-xl px-5 py-4">
          <InvestigationReport
            content={message.content}
            answerType={message.answer_type}
            confidence={message.ai_confidence}
          />
        </div>
      )}
      {isUser && (
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#eaf4ee]">
          <User className="h-4 w-4 text-[#168a52]" />
        </span>
      )}
    </div>
  )
}

export default function ChatPage({ params }: { params: Promise<{ id: string }> }) {
  const [incident, setIncident] = useState<Incident | null>(null); const [session, setSession] = useState<string | null>(null); const [messages, setMessages] = useState<ChatMessage[]>([]); const [input, setInput] = useState(''); const [sending, setSending] = useState(false); const [loading, setLoading] = useState(true); const bottom = useRef<HTMLDivElement>(null)
  useEffect(() => { params.then(({ id }) => Promise.all([getIncident(id), createSession(id)])).then(([nextIncident, nextSession]) => { setIncident(nextIncident); setSession(nextSession.session_id) }).finally(() => setLoading(false)) }, [params])
  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, sending])
  const send = async () => { if (!input.trim() || !session || sending) return; const content = input.trim(); const userMessage: ChatMessage = { id: crypto.randomUUID(), session_id: session, role: 'user', content, timestamp: new Date().toISOString() }; setMessages((items) => [...items, userMessage]); setInput(''); setSending(true); try { const response = await sendMessage(session, content); setMessages((items) => [...items, { id: response.message_id, session_id: session, role: 'assistant', content: response.answer, evidence_ids: response.evidence_ids, answer_type: response.answer_type, ai_confidence: response.confidence, timestamp: new Date().toISOString() }]) } catch (e) { setMessages((items) => [...items, { id: crypto.randomUUID(), session_id: session, role: 'assistant', content: `Unable to complete investigation: ${e instanceof Error ? e.message : 'Unknown error'}`, timestamp: new Date().toISOString() }]) } finally { setSending(false) } }
  if (loading) return <div className="flex min-h-screen items-center justify-center text-sm text-[#667085]"><Loader2 className="mr-2 h-4 w-4 animate-spin text-[#168a52]" />Preparing investigation…</div>
  return <div className="flex min-h-screen flex-col"><header className="border-b border-[#e6e8eb] bg-white px-5 py-4 sm:px-8"><Link href={`/incidents/${incident?.id || ''}`} className="inline-flex items-center text-sm text-[#667085] hover:text-[#111827]"><ChevronLeft className="mr-1 h-4 w-4" />Incident</Link><div className="mt-2 flex flex-wrap items-center gap-2"><h1 className="text-lg font-semibold text-[#111827]">Investigation</h1>{incident && <SeverityBadge severity={incident.severity} />}<span className="text-sm text-[#667085]">{incident?.title}</span></div></header><main className="mx-auto flex w-full max-w-4xl flex-1 flex-col p-5 sm:p-8"><div className="flex-1 space-y-5">{messages.length === 0 && <div className="card p-5"><div className="flex gap-3"><Bot className="mt-0.5 h-5 w-5 shrink-0 text-[#168a52]" /><div><p className="text-sm leading-6 text-[#344054]">Ask questions about this incident. Answers cite available database evidence and label inferences separately.</p><div className="mt-4 flex flex-wrap gap-2">{SUGGESTIONS.map((question) => <button key={question} onClick={() => setInput(question)} className="btn-ghost !px-3 !py-1.5 !text-xs">{question}</button>)}</div></div></div></div>}{messages.map((message) => <Answer key={message.id} message={message} />)}{sending && <div className="flex gap-3"><span className="flex h-8 w-8 items-center justify-center rounded-full bg-[#f0f8f4]"><Bot className="h-4 w-4 text-[#168a52]" /></span><div className="rounded-xl border border-[#e6e8eb] bg-white px-4 py-3 text-sm text-[#667085]">Analyzing evidence…</div></div>}<div ref={bottom} /></div><div className="sticky bottom-0 mt-5 border-t border-[#e6e8eb] bg-[#f7f8fa] pt-4"><div className="flex gap-3"><textarea value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }} className="input min-h-[48px] flex-1 resize-none" placeholder="Ask about this incident…" rows={1} /><button onClick={send} disabled={!input.trim() || sending} className="btn-primary self-end" aria-label="Send message"><Send className="h-4 w-4" /></button></div><p className="mt-2 flex items-center gap-1 text-xs text-[#667085]"><AlertCircle className="h-3.5 w-3.5" />Enter sends; Shift + Enter adds a line.</p></div></main></div>
}
