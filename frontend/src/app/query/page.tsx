'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Code2,
  Database,
  Filter,
  HelpCircle,
  Loader2,
  Search,
  Send,
  Shield,
  Sparkles,
  Terminal,
} from 'lucide-react'

import { sendNLQuery } from '@/lib/api'
import type { NLQueryResponse } from '@/lib/types'

const EXAMPLE_QUERIES = [
  'Show failed logins from 192.168.1.100',
  'List critical incidents involving admin',
  'Find sudo privilege escalations',
  'Show brute force attacks in the last 24 hours',
]

export default function QueryStudioPage() {
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [response, setResponse] = useState<NLQueryResponse | null>(null)
  const [lastQuery, setLastQuery] = useState('')

  const handleQuery = async (queryText?: string) => {
    const q = (queryText || question).trim()
    if (!q || loading) return

    setLoading(true)
    setError(null)
    setLastQuery(q)

    try {
      const res = await sendNLQuery(q)
      setResponse(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'NLU query execution failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="border-b border-[#1f2937] pb-5">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
            Deterministic NLU Query Studio
          </h1>
          <span className="flex items-center gap-1 rounded border border-[#10b981]/30 bg-[#10b981]/10 px-2 py-0.5 font-mono text-[10px] font-medium text-[#34d399]">
            <Terminal className="h-3 w-3" /> Audit-Verifiable SQL
          </span>
        </div>
        <p className="mt-1 text-xs text-[#9ca3af]">
          Query security telemetry with natural language. Translates deterministically into SQL QuerySpecs
          without LLM hallucination risk.
        </p>
      </div>

      {/* Query Terminal Input Card */}
      <div className="card p-5 border-[#1f2937] bg-[#11161d] space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            handleQuery()
          }}
          className="space-y-3"
        >
          <div className="relative">
            <div className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#10b981] font-mono text-sm">
              &gt;
            </div>
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Enter security query (e.g. 'Show failed logins from 192.168.1.50')..."
              className="input w-full pl-9 pr-24 font-mono text-xs py-3"
            />
            <button
              type="submit"
              disabled={!question.trim() || loading}
              className="btn-primary absolute right-2 top-1/2 -translate-y-1/2 text-xs py-1.5 px-3 disabled:opacity-40"
            >
              {loading ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <>
                  <span>Execute</span>
                  <Send className="ml-1.5 h-3 w-3" />
                </>
              )}
            </button>
          </div>

          {/* Prompt Suggestion Pills */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#6b7280]">
              Sample Inquiries:
            </span>
            {EXAMPLE_QUERIES.map((example) => (
              <button
                key={example}
                type="button"
                onClick={() => {
                  setQuestion(example)
                  handleQuery(example)
                }}
                className="rounded border border-[#1f2937] bg-[#171e28] px-2.5 py-1 font-mono text-[11px] text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
              >
                {example}
              </button>
            ))}
          </div>
        </form>
      </div>

      {error && (
        <div className="flex gap-3 rounded-lg border border-[#7f1d1d] bg-[#450a0a]/50 p-4 text-xs text-[#fca5a5]">
          <AlertCircle className="h-4 w-4 shrink-0 text-[#ef4444]" />
          <span>{error}</span>
        </div>
      )}

      {/* Query Result Card */}
      {response && (
        <div className="card p-5 sm:p-6 border-[#1f2937] bg-[#11161d] space-y-5 animate-fade-in">
          {/* Query Result Header */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1f2937] pb-4">
            <div>
              <span className="font-mono text-[10px] uppercase text-[#6b7280] tracking-wider block">
                Original Query
              </span>
              <p className="font-mono text-xs text-[#38bdf8] font-semibold mt-0.5">
                &ldquo;{lastQuery}&rdquo;
              </p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="rounded bg-[#171e28] px-2.5 py-1 border border-[#1f2937] text-[#f3f4f6]">
                Matches: <strong className="text-[#10b981]">{response.result_count}</strong>
              </span>
              {response.resolved_intent && (
                <span className="rounded border border-[#0e7490] bg-[#083344] px-2.5 py-1 text-[#38bdf8] uppercase text-[10px] font-semibold">
                  Intent: {response.resolved_intent}
                </span>
              )}
            </div>
          </div>

          {/* Clarification State if requested by NLU engine */}
          {response.needs_clarification && (
            <div className="rounded-lg border border-[#713f12] bg-[#422006]/40 p-4 space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#facc15]">
                <HelpCircle className="h-4 w-4" />
                <span>Clarification Required</span>
              </div>
              <p className="text-xs text-[#f3f4f6]">
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
                      className="rounded border border-[#713f12] bg-[#171e28] px-3 py-1 text-xs text-[#facc15] hover:bg-[#422006] transition"
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Answer Text */}
          <div className="space-y-2">
            <span className="font-mono text-[10px] uppercase text-[#9ca3af] tracking-wider block">
              Database Answer (Deterministic Fact)
            </span>
            <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-4 font-mono text-xs text-[#d1d5db] leading-relaxed whitespace-pre-wrap">
              {response.answer}
            </div>
          </div>

          {/* Resolved QuerySpec Breakdown */}
          {response.resolved_filters && (
            <div className="border-t border-[#1f2937] pt-4 space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#f3f4f6]">
                <Code2 className="h-3.5 w-3.5 text-[#10b981]" />
                <span>Extracted QuerySpec Entities & Constraints</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5 font-mono text-[11px]">
                {Object.entries(response.resolved_filters).map(([k, v]) => {
                  if (v === null || v === undefined || (Array.isArray(v) && v.length === 0)) return null
                  const displayVal = Array.isArray(v) ? v.join(', ') : String(v)
                  return (
                    <div key={k} className="rounded border border-[#1f2937] bg-[#141b24] p-2.5">
                      <span className="text-[#6b7280] block text-[10px] uppercase">{k}</span>
                      <span className="text-[#38bdf8] font-medium block mt-0.5 truncate" title={displayVal}>
                        {displayVal}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Quick links to deeper investigation */}
          <div className="flex justify-end gap-3 border-t border-[#1f2937] pt-3 text-xs">
            <Link href="/logs" className="btn-ghost text-xs py-1 px-3">
              <Database className="mr-1 h-3 w-3" /> View In SIEM Logs
            </Link>
            <Link href="/incidents" className="btn-ghost text-xs py-1 px-3">
              <Shield className="mr-1 h-3 w-3" /> Triage Incidents
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
