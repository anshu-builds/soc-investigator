'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Filter,
  Flame,
  MessageSquare,
  RefreshCw,
  Search,
  Shield,
  Target,
  User,
  Wifi,
  X,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

import { getIncidents } from '@/lib/api'
import type { IncidentSummary } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'

const PAGE_SIZE = 15

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Server-backed filters
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [attackType, setAttackType] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  const loadIncidents = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const offset = (page - 1) * PAGE_SIZE
      const res = await getIncidents({
        severity: severity || undefined,
        status: status || undefined,
        attack_type: attackType || undefined,
        limit: PAGE_SIZE,
      })
      setIncidents(res.items || [])
      setTotal(res.total || 0)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to retrieve incidents')
    } finally {
      setLoading(false)
    }
  }, [severity, status, attackType, page])

  useEffect(() => {
    loadIncidents()
  }, [loadIncidents])

  // Client-side text refinement across title, target user, IP
  const filtered = incidents.filter((inc) => {
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      inc.title.toLowerCase().includes(q) ||
      (inc.affected_username || '').toLowerCase().includes(q) ||
      (inc.source_ip || '').toLowerCase().includes(q) ||
      inc.id.toLowerCase().includes(q)
    )
  })

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const resetFilters = () => {
    setSeverity('')
    setStatus('')
    setAttackType('')
    setSearch('')
    setPage(1)
  }

  const hasFilters = Boolean(severity || status || attackType || search)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
            Incident Triage Queue
          </h1>
          <p className="mt-1 text-xs text-[#9ca3af]">
            Detected security events correlated into actionable threat investigations
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={loadIncidents}
            disabled={loading}
            className="btn-ghost text-xs py-1.5 px-3"
          >
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loading ? 'animate-spin text-[#10b981]' : 'text-[#9ca3af]'}`} />
            Refresh
          </button>
          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3">
            Upload Telemetry
          </Link>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search title, user, IP or UUID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input w-full pl-9 font-mono text-xs"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
            className="input text-xs"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value)
              setPage(1)
            }}
            className="input text-xs"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CLOSED">Closed</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Attack Type Filter */}
          <select
            value={attackType}
            onChange={(e) => {
              setAttackType(e.target.value)
              setPage(1)
            }}
            className="input text-xs"
          >
            <option value="">All Attack Types</option>
            <option value="BRUTE_FORCE">Brute Force</option>
            <option value="ACCOUNT_COMPROMISE">Account Compromise</option>
            <option value="ACCOUNT_COMPROMISE_WITH_ESCALATION">Compromise + Escalation</option>
            <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
          </select>

          {hasFilters && (
            <button
              type="button"
              onClick={resetFilters}
              className="flex items-center gap-1 text-xs text-[#f87171] hover:underline px-2 py-1"
            >
              <X className="h-3 w-3" /> Clear
            </button>
          )}
        </div>

        {/* Results Count Bar */}
        <div className="flex items-center justify-between text-[11px] font-mono text-[#9ca3af] pt-1">
          <span>
            Showing {filtered.length} of {total} incident{total === 1 ? '' : 's'}
          </span>
          <span>
            Page {page} of {totalPages}
          </span>
        </div>
      </div>

      {/* Main Table Card */}
      <div className="card overflow-hidden">
        {loading ? (
          <SkeletonTable rows={PAGE_SIZE} cols={7} />
        ) : error ? (
          <div className="p-8 text-center">
            <AlertTriangle className="mx-auto h-8 w-8 text-[#ef4444]" />
            <p className="mt-2 text-sm font-semibold text-[#f3f4f6]">Failed to load incidents</p>
            <p className="text-xs text-[#9ca3af] mt-1">{error}</p>
            <button onClick={loadIncidents} className="btn-ghost mt-4 text-xs">
              Retry
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No matching incidents"
            description={
              hasFilters
                ? 'No incidents match your filter criteria. Try adjusting the search filters.'
                : 'No security incidents found in the database. Ingest security logs to run detection.'
            }
            actionLabel={hasFilters ? 'Reset Filters' : 'Upload Logs'}
            onAction={hasFilters ? resetFilters : undefined}
            actionHref={hasFilters ? undefined : '/upload-logs'}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs">
              <thead className="border-b border-[#1f2937] bg-[#141b24] text-[11px] font-mono uppercase tracking-wider text-[#9ca3af]">
                <tr>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Incident Title</th>
                  <th className="py-2.5 px-4">Attack Vector</th>
                  <th className="py-2.5 px-4">Target Scope</th>
                  <th className="py-2.5 px-4">Confidence</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Detected</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182230]">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-[#141b24] transition-colors cursor-pointer group"
                    onClick={() => {
                      window.location.href = `/incidents/${inc.id}`
                    }}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 px-4 max-w-sm">
                      <span className="font-medium text-[#f3f4f6] block truncate group-hover:text-[#10b981] transition-colors">
                        {inc.title}
                      </span>
                      <span className="font-mono text-[10px] text-[#6b7280]">
                        {inc.id.slice(0, 8)} · {inc.event_count} events
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <AttackTypeLabel attackType={inc.attack_type} />
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px]">
                      {inc.affected_username ? (
                        <span className="flex items-center gap-1 text-[#facc15]">
                          <User className="h-3 w-3" /> {inc.affected_username}
                        </span>
                      ) : inc.source_ip ? (
                        <span className="flex items-center gap-1 text-[#38bdf8]">
                          <Wifi className="h-3 w-3" /> {inc.source_ip}
                        </span>
                      ) : (
                        <span className="text-[#6b7280]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="rounded bg-[#171e28] px-2 py-0.5 font-mono text-xs text-[#f3f4f6]">
                        {Math.round((inc.confidence || 0) * 100)}%
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-[#9ca3af]">
                      {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <Link
                          href={`/incidents/${inc.id}/chat`}
                          className="inline-flex items-center gap-1 rounded border border-[#10b981]/30 bg-[#10b981]/10 px-2 py-1 text-[11px] font-medium text-[#34d399] hover:bg-[#10b981]/20 transition"
                          title="Launch AI Copilot investigation"
                        >
                          <MessageSquare className="h-3 w-3" />
                          <span>Copilot</span>
                        </Link>
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="inline-flex items-center rounded border border-[#1f2937] bg-[#171e28] px-2 py-1 text-[11px] font-medium text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
                        >
                          Workspace
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-[#1f2937] px-4 py-3 bg-[#141b24] text-xs">
            <span className="text-[#9ca3af] font-mono">
              Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(total, page * PAGE_SIZE)} of {total} entries
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-30"
              >
                <ChevronLeft className="h-3.5 w-3.5 mr-0.5" /> Prev
              </button>
              <span className="font-mono text-xs text-[#f3f4f6] px-2">
                {page} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="btn-ghost text-xs py-1 px-2.5 disabled:opacity-30"
              >
                Next <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
