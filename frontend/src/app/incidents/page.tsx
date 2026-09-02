'use client'

import React, { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Filter,
  MessageSquare,
  RefreshCw,
  Search,
  Shield,
  Upload,
  User,
  Wifi,
  X,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'

import { getIncidents } from '@/lib/api'
import type { IncidentSummary } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ActiveFilters, type ActiveFilterItem } from '@/components/ui/FilterChips'

const PAGE_SIZE = 15

function IncidentQueueContent() {
  const router = useRouter()
  const searchParams = useSearchParams()

  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Server-backed filters initialized optionally from URL search params
  const [severity, setSeverity] = useState(searchParams.get('severity') || '')
  const [status, setStatus] = useState(searchParams.get('status') || '')
  const [attackType, setAttackType] = useState(searchParams.get('attack_type') || '')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  const loadIncidents = useCallback(
    async (isSilent = false) => {
      if (!isSilent) setLoading(true)
      else setRefreshing(true)
      setError(null)

      try {
        // Correctly pass page and limit to backend API
        const res = await getIncidents({
          page,
          limit: PAGE_SIZE,
          severity: severity || undefined,
          status: status || undefined,
          attack_type: attackType || undefined,
        })
        setIncidents(res.items || [])
        setTotal(res.total || 0)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to retrieve incidents from queue')
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    [severity, status, attackType, page]
  )

  useEffect(() => {
    loadIncidents()
  }, [loadIncidents])

  // Client-side text refinement across title, target user, IP, and UUID
  const filtered = incidents.filter((inc) => {
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      inc.title.toLowerCase().includes(q) ||
      (inc.affected_username || '').toLowerCase().includes(q) ||
      (inc.source_ip || '').toLowerCase().includes(q) ||
      inc.id.toLowerCase().includes(q) ||
      inc.attack_type.toLowerCase().includes(q)
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

  // Build active filter items for FilterChips component
  const activeFilterList: ActiveFilterItem[] = []
  if (search) {
    activeFilterList.push({
      id: 'search',
      label: 'Search',
      value: `"${search}"`,
      onRemove: () => setSearch(''),
    })
  }
  if (severity) {
    activeFilterList.push({
      id: 'severity',
      label: 'Severity',
      value: severity,
      onRemove: () => {
        setSeverity('')
        setPage(1)
      },
    })
  }
  if (status) {
    activeFilterList.push({
      id: 'status',
      label: 'Status',
      value: status.replace(/_/g, ' '),
      onRemove: () => {
        setStatus('')
        setPage(1)
      },
    })
  }
  if (attackType) {
    activeFilterList.push({
      id: 'attack_type',
      label: 'Vector',
      value: attackType.replace(/_/g, ' '),
      onRemove: () => {
        setAttackType('')
        setPage(1)
      },
    })
  }

  const startRange = total > 0 ? (page - 1) * PAGE_SIZE + 1 : 0
  const endRange = Math.min(total, page * PAGE_SIZE)

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              Incident Triage Queue
            </h1>
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-elevated px-2.5 py-0.5 font-mono text-[11px] text-ink-secondary">
              <span className="font-semibold text-ink-primary">{total}</span>
              <span>total</span>
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary">
            Correlated threat incidents awaiting security triage, investigation, and response
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => loadIncidents(true)}
            disabled={loading || refreshing}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Refresh queue from server"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                loading || refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'
              }`}
            />
            <span>{refreshing ? 'Updating…' : 'Sync'}</span>
          </button>
          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest Telemetry</span>
          </Link>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Refine by title, user, source IP, or UUID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input w-full pl-9 pr-8 font-mono text-xs"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                aria-label="Clear search text"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary p-0.5"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
            className="select text-xs font-mono"
            aria-label="Filter by Severity"
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
            className="select text-xs font-mono"
            aria-label="Filter by Status"
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
            className="select text-xs font-mono"
            aria-label="Filter by Attack Vector"
          >
            <option value="">All Attack Vectors</option>
            <option value="BRUTE_FORCE">Brute Force</option>
            <option value="ACCOUNT_COMPROMISE">Account Compromise</option>
            <option value="ACCOUNT_COMPROMISE_WITH_ESCALATION">Compromise + Escalation</option>
            <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
          </select>
        </div>

        {/* Active Filter Chips */}
        {hasFilters && (
          <ActiveFilters
            filters={activeFilterList}
            onClearAll={resetFilters}
            className="border-t border-border-subtle pt-2"
          />
        )}
      </div>

      {/* Main Table Card */}
      <div className="card overflow-hidden">
        {loading && !refreshing ? (
          <SkeletonTable rows={PAGE_SIZE} cols={7} />
        ) : error ? (
          <div className="p-12 text-center">
            <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
            <h3 className="mt-3 text-sm font-semibold text-ink-primary">Failed to load incidents</h3>
            <p className="text-xs text-ink-secondary mt-1">{error}</p>
            <button
              type="button"
              onClick={() => loadIncidents()}
              className="btn-ghost mt-4 text-xs"
            >
              Retry
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title={hasFilters ? 'No incidents match your filters' : 'No security incidents found'}
            description={
              hasFilters
                ? 'No alerts in the current queue matched the active filters. Broaden your criteria or clear active filters.'
                : 'Your environment currently has zero security incidents. Ingest new security logs to trigger detection.'
            }
            actionLabel={hasFilters ? 'Clear all filters' : 'Ingest Logs'}
            onAction={hasFilters ? resetFilters : undefined}
            actionHref={hasFilters ? undefined : '/upload-logs'}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs">
              <thead className="th-soc border-b border-border">
                <tr>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Incident Title & Scope</th>
                  <th className="py-2.5 px-4">Attack Vector</th>
                  <th className="py-2.5 px-4">Target Entity</th>
                  <th className="py-2.5 px-4">Confidence</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Detected</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') router.push(`/incidents/${inc.id}`)
                    }}
                    onClick={() => router.push(`/incidents/${inc.id}`)}
                    className="tr-soc cursor-pointer focus-visible:outline-none focus-visible:bg-highlight"
                  >
                    <td className="td-soc whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="td-soc max-w-sm">
                      <span className="font-semibold text-ink-primary block truncate group-hover:text-accent-emerald">
                        {inc.title}
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted block mt-0.5">
                        ID: {inc.id.slice(0, 8)} · {inc.event_count} evidence events
                      </span>
                    </td>
                    <td className="td-soc whitespace-nowrap">
                      <AttackTypeLabel attackType={inc.attack_type} />
                    </td>
                    <td className="td-soc whitespace-nowrap font-mono text-[11px]">
                      {inc.affected_username ? (
                        <span
                          className="flex items-center gap-1.5 text-[#facc15]"
                          title={`Target User: ${inc.affected_username}`}
                        >
                          <User className="h-3.5 w-3.5 shrink-0" />
                          <span className="truncate max-w-[130px]">{inc.affected_username}</span>
                        </span>
                      ) : inc.source_ip ? (
                        <span
                          className="flex items-center gap-1.5 text-accent-cyan"
                          title={`Source IP: ${inc.source_ip}`}
                        >
                          <Wifi className="h-3.5 w-3.5 shrink-0" />
                          <span>{inc.source_ip}</span>
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>
                    <td className="td-soc whitespace-nowrap">
                      <span className="rounded bg-elevated px-2 py-0.5 font-mono text-[11px] text-ink-primary">
                        {Math.round((inc.confidence || 0) * 100)}%
                      </span>
                    </td>
                    <td className="td-soc whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="td-soc whitespace-nowrap font-mono text-[11px] text-ink-secondary">
                      <span title={format(new Date(inc.created_at), 'yyyy-MM-dd HH:mm:ss')}>
                        {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                      </span>
                    </td>
                    <td
                      className="td-soc text-right whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1.5">
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="inline-flex items-center gap-1 rounded-md border border-border bg-elevated px-2 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95"
                          title="Open incident workspace"
                        >
                          <span>Workspace</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                        <Link
                          href={`/incidents/${inc.id}/chat`}
                          className="inline-flex items-center gap-1 rounded-md border border-accent-cyan/30 bg-accent-cyan/10 px-2 py-1 text-[11px] font-medium text-accent-cyan hover:bg-accent-cyan/20 transition active:scale-95"
                          title="Launch AI Copilot for this incident"
                        >
                          <MessageSquare className="h-3 w-3" />
                          <span>Copilot</span>
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Polished Pagination Footer */}
        {total > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3 bg-panel/40 text-xs">
            <span className="text-ink-secondary font-mono text-[11px]">
              Showing <span className="text-ink-primary font-semibold">{startRange}</span> to{' '}
              <span className="text-ink-primary font-semibold">{endRange}</span> of{' '}
              <span className="text-ink-primary font-semibold">{total}</span> incidents
            </span>

            <div className="flex items-center gap-1.5">
              {/* First Page */}
              <button
                type="button"
                onClick={() => setPage(1)}
                disabled={page === 1 || loading}
                aria-label="Go to first page"
                className="flex h-7 w-7 items-center justify-center rounded border border-border bg-elevated text-ink-muted hover:text-ink-primary hover:border-border-active disabled:opacity-30 disabled:pointer-events-none transition"
              >
                <ChevronsLeft className="h-3.5 w-3.5" />
              </button>

              {/* Prev Page */}
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1 || loading}
                aria-label="Go to previous page"
                className="flex h-7 w-7 items-center justify-center rounded border border-border bg-elevated text-ink-muted hover:text-ink-primary hover:border-border-active disabled:opacity-30 disabled:pointer-events-none transition"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>

              {/* Page Number Indicator */}
              <div className="flex items-center gap-1 px-1 font-mono text-xs text-ink-secondary">
                <span className="text-ink-primary font-semibold">{page}</span>
                <span className="text-ink-muted">/</span>
                <span>{totalPages}</span>
              </div>

              {/* Next Page */}
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || loading}
                aria-label="Go to next page"
                className="flex h-7 w-7 items-center justify-center rounded border border-border bg-elevated text-ink-muted hover:text-ink-primary hover:border-border-active disabled:opacity-30 disabled:pointer-events-none transition"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>

              {/* Last Page */}
              <button
                type="button"
                onClick={() => setPage(totalPages)}
                disabled={page === totalPages || loading}
                aria-label="Go to last page"
                className="flex h-7 w-7 items-center justify-center rounded border border-border bg-elevated text-ink-muted hover:text-ink-primary hover:border-border-active disabled:opacity-30 disabled:pointer-events-none transition"
              >
                <ChevronsRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<SkeletonTable rows={PAGE_SIZE} cols={7} />}>
      <IncidentQueueContent />
    </Suspense>
  )
}
