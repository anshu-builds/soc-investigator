'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock,
  Code2,
  Copy,
  Database,
  ExternalLink,
  Filter,
  HelpCircle,
  History,
  Loader2,
  RotateCcw,
  Search,
  Send,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  User,
  Wifi,
  X,
} from 'lucide-react'

import { sendNLQuery } from '@/lib/api'
import type { NLQueryResponse } from '@/lib/types'
import { SeverityBadge } from '@/components/ui/badges'
import { useToast } from '@/components/ui/Toast'

const EXAMPLE_QUERIES = [
  'Show failed logins from 192.168.1.100',
  'List critical incidents involving admin',
  'Find sudo privilege escalations',
  'Show brute force attacks in the last 24 hours',
]

const MAX_HISTORY = 6

export default function QueryStudioPage() {
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

  // Derive contextual pivots based on extracted query filters
  const extractedIps = response?.resolved_filters?.ips || []
  const extractedUsers = response?.resolved_filters?.usernames || []
  const extractedSeverities = response?.resolved_filters?.severities || []
  const extractedEventTypes = response?.resolved_filters?.event_types || []

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="border-b border-border pb-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-xl font-bold tracking-tight text-ink-primary">
            Deterministic NLU Query Studio
          </h1>
          <span className="flex items-center gap-1 rounded-full border border-accent-emerald/30 bg-accent-emerald/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold text-accent-emerald">
            <Terminal className="h-3 w-3" />
            <span>Zero-LLM SQL Translation</span>
          </span>
        </div>
        <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
          Formulate security investigation questions in natural language. Translated deterministically
          into SQL QuerySpecs and executed directly against the database with zero hallucination risk.
        </p>
      </div>

      {/* Query Terminal Input Card */}
      <div className="card p-5 sm:p-6 border-border bg-panel space-y-4 shadow-sm">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            handleQuery()
          }}
          className="space-y-3.5"
        >
          <div className="relative">
            <div className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-accent-emerald font-mono text-sm font-bold">
              &gt;
            </div>
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Enter investigation query (e.g. 'Show failed logins from 10.10.5.200')..."
              className="input w-full pl-9 pr-28 font-mono text-xs py-3 bg-canvas/70"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
              {question && (
                <button
                  type="button"
                  onClick={() => setQuestion('')}
                  aria-label="Clear query text"
                  className="p-1 text-ink-muted hover:text-ink-primary transition"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
              <button
                type="submit"
                disabled={!question.trim() || loading}
                className="btn-primary text-xs py-1.5 px-3.5 disabled:opacity-40 flex items-center gap-1.5"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Executing</span>
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

          {/* Sample Query Inquiries */}
          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-ink-muted">
              Sample Queries:
            </span>
            {EXAMPLE_QUERIES.map((example) => (
              <button
                key={example}
                type="button"
                onClick={() => {
                  setQuestion(example)
                  handleQuery(example)
                }}
                disabled={loading}
                className="rounded-lg border border-border bg-elevated/70 px-2.5 py-1 font-mono text-[11px] text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95 disabled:opacity-50"
              >
                {example}
              </button>
            ))}
          </div>

          {/* Local Session History */}
          {history.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-t border-border-subtle pt-3 text-[11px] font-mono">
              <span className="text-ink-muted flex items-center gap-1 text-[10px] uppercase tracking-wider">
                <History className="h-3 w-3" />
                <span>Session History:</span>
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
                    className="rounded bg-elevated px-2 py-0.5 text-[10px] text-ink-secondary hover:text-ink-primary border border-border-subtle hover:border-border transition truncate max-w-[200px]"
                    title={h}
                  >
                    {h}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={clearHistory}
                className="text-[10px] text-ink-muted hover:text-severity-critical transition"
                title="Clear local session query history"
              >
                Clear
              </button>
            </div>
          )}
        </form>
      </div>

      {/* Non-blocking Error Notice */}
      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4 text-xs text-severity-critical animate-fade-in">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading Execution Progress State */}
      {loading && (
        <div className="card p-10 text-center border-border bg-panel space-y-3 animate-pulse-subtle">
          <Loader2 className="mx-auto h-7 w-7 animate-spin text-accent-emerald" />
          <h3 className="text-sm font-bold text-ink-primary">
            Parsing Natural Language & Executing SQL QuerySpec
          </h3>
          <p className="text-xs text-ink-secondary max-w-sm mx-auto leading-relaxed">
            Extracting entities, resolving investigation intent, and querying structured security logs…
          </p>
        </div>
      )}

      {/* Query Result Card */}
      {response && !loading && (
        <div className="card p-5 sm:p-6 border-border bg-panel space-y-5 animate-fade-in shadow-sm">
          {/* Query Result Header Strip */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-4">
            <div>
              <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider block">
                Executed Natural Query
              </span>
              <p className="font-mono text-xs text-accent-cyan font-semibold mt-0.5">
                &ldquo;{lastQuery}&rdquo;
              </p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="rounded-md bg-elevated px-2.5 py-1 border border-border text-ink-primary">
                Matches: <strong className="text-accent-emerald">{response.result_count}</strong>
              </span>
              {response.resolved_intent && (
                <span className="rounded-md border border-[#0e7490] bg-[#083344] px-2.5 py-1 text-accent-cyan uppercase text-[10px] font-bold">
                  Intent: {response.resolved_intent}
                </span>
              )}
            </div>
          </div>

          {/* Clarification State if requested by NLU engine */}
          {response.needs_clarification && (
            <div className="rounded-xl border border-[#713f12] bg-[#422006]/40 p-4 space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#facc15]">
                <HelpCircle className="h-4 w-4" />
                <span>Clarification Required by Engine</span>
              </div>
              <p className="text-xs text-ink-primary">
                {response.clarification_question || 'Please specify the exact entity or intent for your query.'}
              </p>
              {response.clarification_options && response.clarification_options.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {response.clarification_options.map((opt) => (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => {
                        setQuestion(opt)
                        handleQuery(opt)
                      }}
                      className="rounded-lg border border-[#713f12] bg-elevated px-3 py-1.5 text-xs text-[#facc15] hover:bg-[#422006] transition font-mono"
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Database Fact Answer Box */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider block">
                Database Answer (Deterministic Fact)
              </span>
              <button
                type="button"
                onClick={copyAnswer}
                className="inline-flex items-center gap-1 font-mono text-[11px] text-ink-secondary hover:text-ink-primary transition"
              >
                {copiedAnswer ? (
                  <>
                    <Check className="h-3 w-3 text-accent-emerald" />
                    <span className="text-accent-emerald">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" />
                    <span>Copy Answer</span>
                  </>
                )}
              </button>
            </div>

            <div className="rounded-xl border border-border bg-canvas/70 p-4 font-mono text-xs text-ink-primary leading-relaxed whitespace-pre-wrap">
              {response.answer}
            </div>
          </div>

          {/* Extracted QuerySpec Entities Grid */}
          {response.resolved_filters && (
            <div className="border-t border-border-subtle pt-4 space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-ink-primary">
                <Code2 className="h-3.5 w-3.5 text-accent-emerald" />
                <span>Extracted QuerySpec Entities & Constraints</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5 font-mono text-[11px]">
                {Object.entries(response.resolved_filters).map(([k, v]) => {
                  if (v === null || v === undefined || (Array.isArray(v) && v.length === 0)) return null
                  const displayVal = Array.isArray(v) ? v.join(', ') : String(v)
                  return (
                    <div key={k} className="rounded-lg border border-border-subtle bg-elevated/40 p-2.5">
                      <span className="text-ink-muted block text-[10px] uppercase">{k}</span>
                      <span className="text-accent-cyan font-medium block mt-0.5 truncate" title={displayVal}>
                        {displayVal}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Investigation Pivots Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle pt-4 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              {extractedIps.length > 0 && (
                <Link
                  href={`/logs?source_ip=${extractedIps[0]}`}
                  className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1.5"
                  title={`Pivot to SIEM logs for IP ${extractedIps[0]}`}
                >
                  <Wifi className="h-3.5 w-3.5 text-accent-cyan" />
                  <span>Filter Logs: {extractedIps[0]}</span>
                </Link>
              )}

              {extractedUsers.length > 0 && (
                <Link
                  href={`/logs?username=${extractedUsers[0]}`}
                  className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1.5"
                  title={`Pivot to SIEM logs for user ${extractedUsers[0]}`}
                >
                  <User className="h-3.5 w-3.5 text-[#facc15]" />
                  <span>Filter Logs: {extractedUsers[0]}</span>
                </Link>
              )}

              {extractedSeverities.length > 0 && (
                <Link
                  href={`/incidents?severity=${extractedSeverities[0]}`}
                  className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1.5"
                  title={`Pivot to incidents with severity ${extractedSeverities[0]}`}
                >
                  <ShieldAlert className="h-3.5 w-3.5 text-severity-critical" />
                  <span>View {extractedSeverities[0]} Incidents</span>
                </Link>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Link href="/logs" className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1">
                <Database className="h-3.5 w-3.5" />
                <span>SIEM Explorer</span>
              </Link>
              <Link href="/incidents" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1">
                <Shield className="h-3.5 w-3.5" />
                <span>Incident Queue</span>
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
