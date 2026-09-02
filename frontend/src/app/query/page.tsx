'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Code,
  Copy,
  Database,
  ExternalLink,
  Filter,
  History,
  Info,
  Loader2,
  RefreshCw,
  Search,
  Send,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  User,
  Wifi,
  X,
  Zap,
} from 'lucide-react'

import { sendNLQuery } from '@/lib/api'
import type { NLQueryResponse } from '@/lib/types'
import { useToast } from '@/components/ui/Toast'

const EXAMPLE_QUERIES = [
  'Show failed logins from 10.10.5.200',
  'Find privilege escalation events for admin',
  'List critical severity incidents',
  'Events with action AUTH_FAILURE',
]

const MAX_HISTORY = 5

export default function QueryPage() {
  const { success, error: toastError } = useToast()

  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [response, setResponse] = useState<NLQueryResponse | null>(null)
  const [lastQuery, setLastQuery] = useState('')
  const [copiedAnswer, setCopiedAnswer] = useState(false)

  // Local session-only history
  const [history, setHistory] = useState<string[]>(() => {
    if (typeof window === 'undefined') return []
    try {
      const raw = sessionStorage.getItem('soc_query_session_history')
      return raw ? JSON.parse(raw) : []
    } catch {
      return []
    }
  })

  const saveToHistory = (queryText: string) => {
    const clean = queryText.trim()
    if (!clean) return
    setHistory((prev) => {
      const updated = [clean, ...prev.filter((item) => item !== clean)].slice(0, MAX_HISTORY)
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('soc_query_session_history', JSON.stringify(updated))
      }
      return updated
    })
  }

  const clearHistory = () => {
    setHistory([])
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('soc_query_session_history')
    }
  }

  const handleQuery = async (queryText?: string) => {
    const q = (queryText || question).trim()
    if (!q || loading) return

    setLoading(true)
    setError(null)
    setLastQuery(q)
    saveToHistory(q)

    try {
      const res = await sendNLQuery(q)
      setResponse(res)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'NLU query execution failed'
      setError(msg)
      toastError('Execution Error', msg)
    } finally {
      setLoading(false)
    }
  }

  const copyAnswer = () => {
    if (!response?.answer) return
    navigator.clipboard.writeText(response.answer)
    setCopiedAnswer(true)
    success('Copied to Clipboard', 'Query result answer copied')
    setTimeout(() => setCopiedAnswer(false), 2000)
  }

  const extractedIps: string[] = response?.resolved_filters?.ips || []
  const extractedUsers: string[] = response?.resolved_filters?.usernames || []
  const extractedSeverities: string[] = response?.resolved_filters?.severities || []
  const extractedEventTypes: string[] = response?.resolved_filters?.event_types || []

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* 1. HEADER */}
      <div className="border-b border-border/80 pb-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-xl font-bold tracking-tight text-ink-primary">
            NLU Query Studio
          </h1>
          <span className="rounded bg-elevated px-2 py-0.5 font-mono text-[11px] font-semibold text-accent-emerald border border-border">
            Deterministic Zero-LLM SQL Translation
          </span>
        </div>
        <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
          Ask security investigation questions in natural language. Deterministically translated into SQL QuerySpecs and executed directly against the SIEM database.
        </p>
      </div>

      {/* 2. QUERY TERMINAL CONSOLE */}
      <div className="rounded-lg border border-border/80 bg-panel/80 p-4 space-y-3 shadow-sm">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            handleQuery()
          }}
          className="space-y-3"
        >
          <div className="relative">
            <div className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-accent-emerald font-mono text-sm font-bold">
              &gt;
            </div>
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Enter investigation query (e.g. 'Show failed logins from 10.10.5.200')…"
              className="input w-full pl-8 pr-24 font-mono text-xs py-2.5 bg-canvas/60"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
              {question && (
                <button
                  type="button"
                  onClick={() => setQuestion('')}
                  aria-label="Clear query"
                  className="p-1 text-ink-muted hover:text-ink-primary transition-colors"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
              <button
                type="submit"
                disabled={!question.trim() || loading}
                className="btn-primary text-xs py-1 px-3 disabled:opacity-40 flex items-center gap-1.5"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-3 w-3 animate-spin" />
                    <span>Querying…</span>
                  </>
                ) : (
                  <>
                    <span>Execute</span>
                    <Send className="h-3 w-3" />
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Quick Example Queries */}
          <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
            <span className="text-[10px] font-mono uppercase text-ink-muted">Inquiries:</span>
            {EXAMPLE_QUERIES.map((example) => (
              <button
                key={example}
                type="button"
                onClick={() => {
                  setQuestion(example)
                  handleQuery(example)
                }}
                disabled={loading}
                className="rounded border border-border/80 bg-elevated/50 px-2 py-0.5 font-sans text-[11px] text-ink-secondary hover:text-ink-primary hover:border-border-active transition-colors disabled:opacity-50"
              >
                {example}
              </button>
            ))}
          </div>

          {/* Session History Strip */}
          {history.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-t border-border-subtle pt-2.5 text-[11px] font-mono">
              <span className="text-ink-muted flex items-center gap-1 text-[10px] uppercase">
                <History className="h-3 w-3" />
                <span>Recent:</span>
              </span>
              <div className="flex flex-wrap items-center gap-1.5 flex-1">
                {history.map((h, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => {
                      setQuestion(h)
                      handleQuery(h)
                    }}
                    disabled={loading}
                    className="rounded bg-elevated px-2 py-0.5 text-[10px] text-ink-secondary hover:text-ink-primary border border-border-subtle/80 hover:border-border transition-colors truncate max-w-[200px]"
                    title={h}
                  >
                    {h}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={clearHistory}
                className="text-[10px] text-ink-muted hover:text-severity-critical transition-colors"
                title="Clear local session history"
              >
                Clear
              </button>
            </div>
          )}
        </form>
      </div>

      {/* Non-blocking Error Notice */}
      {error && (
        <div className="flex items-center gap-3 rounded border border-severity-critical/30 bg-severity-critical/10 p-3 text-xs text-severity-critical animate-fade-in">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="p-8 text-center border border-border/80 rounded bg-panel space-y-2 animate-pulse-subtle">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-accent-emerald" />
          <h3 className="text-xs font-bold text-ink-primary font-mono">
            Translating Natural Query to SQL QuerySpec…
          </h3>
        </div>
      )}

      {/* 3. STRUCTURED QUERY RESULTS & EVIDENCE WORKBENCH */}
      {response && !loading && (
        <div className="space-y-4 animate-fade-in">
          {/* Query Resolution Header */}
          <div className="rounded border border-border/80 bg-panel/70 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
              <div>
                <span className="font-mono text-[10px] uppercase text-ink-muted block">Query Scope</span>
                <p className="font-mono text-xs font-bold text-ink-primary mt-0.5">
                  &ldquo;{lastQuery}&rdquo;
                </p>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="rounded bg-elevated px-2 py-0.5 border border-border text-ink-primary">
                  Matches: <strong className="text-accent-emerald">{response.result_count}</strong>
                </span>
                {response.resolved_intent && (
                  <span className="rounded border border-[#0e7490] bg-[#083344]/80 px-2 py-0.5 text-accent-cyan uppercase text-[10px] font-bold">
                    {response.resolved_intent}
                  </span>
                )}
              </div>
            </div>

            {/* Extracted Entity Tags */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-ink-muted text-[10px] uppercase">Extracted Entities:</span>
              {extractedIps.length === 0 &&
                extractedUsers.length === 0 &&
                extractedSeverities.length === 0 &&
                extractedEventTypes.length === 0 && (
                  <span className="text-ink-muted text-[11px]">—</span>
                )}
              {extractedIps.map((ip: string) => (
                <span key={ip} className="rounded bg-elevated px-1.5 py-0.5 text-accent-cyan border border-border">
                  IP: {ip}
                </span>
              ))}
              {extractedUsers.map((u: string) => (
                <span key={u} className="rounded bg-elevated px-1.5 py-0.5 text-[#facc15] border border-border">
                  User: {u}
                </span>
              ))}
              {extractedSeverities.map((s: string) => (
                <span key={s} className="rounded bg-elevated px-1.5 py-0.5 text-severity-high border border-border">
                  Sev: {s}
                </span>
              ))}
              {extractedEventTypes.map((e: string) => (
                <span key={e} className="rounded bg-elevated px-1.5 py-0.5 text-accent-emerald border border-border">
                  Type: {e}
                </span>
              ))}
            </div>

            {/* Natural Language Response Body */}
            <div className="p-3.5 rounded bg-canvas/70 border border-border/80 flex items-start justify-between gap-3 text-xs leading-relaxed text-ink-primary">
              <p className="whitespace-pre-wrap">{response.answer}</p>
              <button
                type="button"
                onClick={copyAnswer}
                className="text-ink-muted hover:text-ink-primary transition-colors shrink-0 p-1"
                title="Copy Answer"
              >
                {copiedAnswer ? (
                  <Check className="h-3.5 w-3.5 text-accent-emerald" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>

          {/* 4. DYNAMIC INVESTIGATION PIVOTS */}
          <div className="flex flex-wrap items-center justify-end gap-2 text-xs">
            <Link href="/logs" className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5" />
              <span>Explore All Logs</span>
            </Link>

            {extractedIps.map((ip: string) => (
              <Link
                key={ip}
                href={`/logs?source_ip=${encodeURIComponent(ip)}`}
                className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5 text-accent-cyan border-accent-cyan/30"
              >
                <Wifi className="h-3.5 w-3.5" />
                <span>Filter Logs: {ip}</span>
              </Link>
            ))}

            <Link href="/incidents" className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              <span>Incident Queue</span>
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
