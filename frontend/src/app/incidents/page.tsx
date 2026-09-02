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
import { AttackTypeLabel } from '@/components/ui/badges'
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

  // Server-backed filters
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

  // Client-side search refinement
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

  const setQuickFilter = (type: 'all' | 'critical' | 'high' | 'open' | 'investigating') => {
    setPage(1)
    if (type === 'all') {
      setSeverity('')
      setStatus('')
    } else if (type === 'critical') {
      setSeverity('CRITICAL')
      setStatus('')
    } else if (type === 'high') {
      setSeverity('HIGH')
      setStatus('')
    } else if (type === 'open') {
      setStatus('OPEN')
      setSeverity('')
    } else if (type === 'investigating') {
      setStatus('INVESTIGATING')
      setSeverity('')
    }
  }

  const activeFilterList: ActiveFilterItem[] = []
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
      value: status,
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

  const hasFilters = activeFilterList.length > 0 || search.trim().length > 0
  const startRange = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const endRange = Math.min(page * PAGE_SIZE, total)

  // Severity indicator helper
  const renderSeverity = (sev: string) => {
    const s = (sev || 'LOW').toUpperCase()
    if (s === 'CRITICAL') {
      return (
        <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-severity-critical">
          <span className="h-2 w-2 rounded-full bg-severity-critical" />
          CRITICAL
        </span>
      )
    }
    if (s === 'HIGH') {
      return (
        <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-severity-high">
          <span className="h-2 w-2 rounded-full bg-severity-high" />
          HIGH
        </span>
      )
    }
    if (s === 'MEDIUM') {
      return (
        <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-severity-medium">
          <span className="h-1.5 w-1.5 rounded-full bg-severity-medium" />
          MEDIUM
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-severity-low">
        <span className="h-1.5 w-1.5 rounded-full bg-severity-low" />
        LOW
      </span>
    )
  }

  const renderStatus = (st: string) => {
    const s = (st || 'OPEN').toUpperCase()
    if (s === 'OPEN') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-[#facc15]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#facc15]" />
          OPEN
        </span>
      )
    }
    if (s === 'INVESTIGATING') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-[#60a5fa]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#60a5fa]" />
          INVESTIGATING
        </span>
      )
    }
    if (s === 'CLOSED') {
      return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-[#34d399]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#34d399]" />
          CLOSED
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-ink-muted">
        <span className="h-1.5 w-1.5 rounded-full bg-ink-muted" />
        FALSE POSITIVE
      </span>
    )
  }

  return (
    <div className="space-y-4">
      {/* 1. ENTERPRISE INCIDENT HEADER & QUICK FILTER TABS */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-border/80 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              INCIDENTS
            </h1>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-xs font-semibold text-ink-secondary border border-border">
              {total} ACTIVE
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary">
            Threats requiring security analyst investigation and containment response
          </p>
        </div>

        {/* Quick Scope Filter Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setQuickFilter('all')}
            className={`rounded px-2.5 py-1 text-xs font-sans transition-colors ${
              !severity && !status
                ? 'bg-elevated text-ink-primary font-semibold border border-border-active'
                : 'text-ink-secondary hover:text-ink-primary hover:bg-elevated/40'
            }`}
          >
            All ({total})
          </button>
          <button
            type="button"
            onClick={() => setQuickFilter('critical')}
            className={`rounded px-2.5 py-1 text-xs font-sans transition-colors flex items-center gap-1.5 ${
              severity === 'CRITICAL'
                ? 'bg-[#450a0a]/50 text-severity-critical font-semibold border border-severity-critical/40'
                : 'text-ink-secondary hover:text-severity-critical hover:bg-elevated/40'
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
            <span>Critical</span>
          </button>
          <button
            type="button"
            onClick={() => setQuickFilter('high')}
            className={`rounded px-2.5 py-1 text-xs font-sans transition-colors flex items-center gap-1.5 ${
              severity === 'HIGH'
                ? 'bg-[#431407]/50 text-severity-high font-semibold border border-severity-high/40'
                : 'text-ink-secondary hover:text-severity-high hover:bg-elevated/40'
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-severity-high" />
            <span>High</span>
          </button>
          <button
            type="button"
            onClick={() => setQuickFilter('open')}
            className={`rounded px-2.5 py-1 text-xs font-sans transition-colors flex items-center gap-1.5 ${
              status === 'OPEN'
                ? 'bg-[#422006]/50 text-[#facc15] font-semibold border border-[#713f12]/50'
                : 'text-ink-secondary hover:text-[#facc15] hover:bg-elevated/40'
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-[#facc15]" />
            <span>Open</span>
          </button>

          <div className="h-4 w-px bg-border/80 mx-1 hidden sm:block" />

          <button
            type="button"
            onClick={() => loadIncidents(true)}
            disabled={refreshing}
            className="btn-ghost text-xs py-1 px-2.5 flex items-center gap-1.5"
            title="Refresh queue"
          >
            <RefreshCw
              className={`h-3 w-3 ${refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'}`}
            />
            <span className="hidden sm:inline">{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>
        </div>
      </div>

      {/* 2. REFINED FILTER TOOLBAR */}
      <div className="flex flex-wrap items-center gap-2.5 py-1">
        {/* Search Box */}
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
          <input
            type="text"
            placeholder="Search by title, target user, IP, or ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input w-full pl-9 pr-8 text-xs py-1.5 bg-panel/60"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary p-0.5"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Severity Select */}
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value)
            setPage(1)
          }}
          className="select text-xs font-mono py-1.5"
          aria-label="Filter by Severity"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        {/* Status Select */}
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value)
            setPage(1)
          }}
          className="select text-xs font-mono py-1.5"
          aria-label="Filter by Status"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="CLOSED">Closed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>

        {/* Attack Vector Select */}
        <select
          value={attackType}
          onChange={(e) => {
            setAttackType(e.target.value)
            setPage(1)
          }}
          className="select text-xs font-mono py-1.5"
          aria-label="Filter by Attack Vector"
        >
          <option value="">All Attack Vectors</option>
          <option value="BRUTE_FORCE">Brute Force</option>
          <option value="ACCOUNT_COMPROMISE">Account Compromise</option>
          <option value="ACCOUNT_COMPROMISE_WITH_ESCALATION">Compromise + Escalation</option>
          <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
        </select>

        {hasFilters && (
          <button
            type="button"
            onClick={resetFilters}
            className="text-xs font-mono text-ink-muted hover:text-ink-primary underline px-1"
          >
            Clear
          </button>
        )}
      </div>

      {/* Active Filter Chips */}
      {hasFilters && (
        <ActiveFilters
          filters={activeFilterList}
          onClearAll={resetFilters}
          className="pt-1 pb-2 border-b border-border/60"
        />
      )}

      {/* 3. OPEN CANVAS INCIDENT WORKSPACE TABLE */}
      {loading && !refreshing ? (
        <SkeletonTable rows={PAGE_SIZE} cols={7} />
      ) : error ? (
        <div className="p-12 text-center border border-severity-critical/30 rounded bg-panel/50">
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
          title={hasFilters ? 'No matching incidents found' : 'Incident queue is empty'}
          description={
            hasFilters
              ? 'Try modifying active filters or search terms.'
              : 'No security incidents have been detected. Ingest telemetry logs to initiate automated detection.'
          }
          actionLabel={hasFilters ? 'Clear All Filters' : 'Ingest Telemetry'}
          onAction={hasFilters ? resetFilters : undefined}
          actionHref={hasFilters ? undefined : '/upload-logs'}
        />
      ) : (
        <div className="overflow-x-auto border-y border-border/80">
          <table className="w-full text-left font-sans text-xs">
            <thead className="th-soc">
              <tr>
                <th className="py-2.5 px-3.5 w-28">Severity</th>
                <th className="py-2.5 px-3.5">Incident Title & Scope</th>
                <th className="py-2.5 px-3.5">Target</th>
                <th className="py-2.5 px-3.5">Attack Vector</th>
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3.5">Detected</th>
                <th className="py-2.5 px-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/80">
              {filtered.map((inc) => (
                <tr
                  key={inc.id}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') router.push(`/incidents/${inc.id}`)
                  }}
                  onClick={() => router.push(`/incidents/${inc.id}`)}
                  className="tr-soc cursor-pointer group"
                >
                  {/* Severity Indicator */}
                  <td className="td-soc whitespace-nowrap">
                    {renderSeverity(inc.severity)}
                  </td>

                  {/* Incident Title (Dominant Element) */}
                  <td className="td-soc max-w-md">
                    <span className="text-sm font-semibold text-ink-primary block truncate group-hover:text-accent-emerald transition-colors">
                      {inc.title}
                    </span>
                    <span className="font-mono text-[11px] text-ink-muted block mt-0.5">
                      INC-{inc.id.slice(0, 8)} · {inc.event_count} evidence events · {Math.round((inc.confidence || 0) * 100)}% conf
                    </span>
                  </td>

                  {/* Target Entity */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px]">
                    {inc.affected_username ? (
                      <span className="flex items-center gap-1.5 text-[#facc15]" title={`User: ${inc.affected_username}`}>
                        <User className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate max-w-[120px] font-semibold">{inc.affected_username}</span>
                      </span>
                    ) : inc.source_ip ? (
                      <span className="flex items-center gap-1.5 text-accent-cyan" title={`Source IP: ${inc.source_ip}`}>
                        <Wifi className="h-3.5 w-3.5 shrink-0" />
                        <span>{inc.source_ip}</span>
                      </span>
                    ) : (
                      <span className="text-ink-muted">—</span>
                    )}
                  </td>

                  {/* Attack Vector */}
                  <td className="td-soc whitespace-nowrap">
                    <AttackTypeLabel attackType={inc.attack_type} />
                  </td>

                  {/* Status Indicator */}
                  <td className="td-soc whitespace-nowrap">
                    {renderStatus(inc.status)}
                  </td>

                  {/* Detected Relative Time */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px] text-ink-muted">
                    <span title={format(new Date(inc.created_at), 'yyyy-MM-dd HH:mm:ss')}>
                      {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                    </span>
                  </td>

                  {/* Quick Pivot Actions */}
                  <td
                    className="td-soc text-right whitespace-nowrap"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-center justify-end gap-1.5">
                      <Link
                        href={`/incidents/${inc.id}`}
                        className="btn-ghost text-[11px] py-1 px-2"
                        title="Open full incident dossier workspace"
                      >
                        <span>Workspace</span>
                        <ArrowRight className="h-3 w-3" />
                      </Link>
                      <Link
                        href={`/incidents/${inc.id}/chat`}
                        className="btn-ghost text-[11px] py-1 px-2 border-accent-cyan/30 text-accent-cyan"
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

      {/* 4. FOOTER PAGINATION (Hairline Open Canvas) */}
      {total > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs">
          <span className="text-ink-muted font-mono text-[11px]">
            Showing <strong className="text-ink-primary font-semibold">{startRange}</strong> to{' '}
            <strong className="text-ink-primary font-semibold">{endRange}</strong> of{' '}
            <strong className="text-ink-primary font-semibold">{total}</strong> incidents
          </span>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setPage(1)}
              disabled={page === 1 || loading}
              aria-label="First page"
              className="flex h-7 w-7 items-center justify-center rounded border border-border bg-panel text-ink-muted hover:text-ink-primary disabled:opacity-30 disabled:pointer-events-none transition-colors"
            >
              <ChevronsLeft className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
              aria-label="Previous page"
              className="flex h-7 w-7 items-center justify-center rounded border border-border bg-panel text-ink-muted hover:text-ink-primary disabled:opacity-30 disabled:pointer-events-none transition-colors"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span className="px-2 font-mono text-xs text-ink-secondary">
              Page <strong className="text-ink-primary">{page}</strong> of {totalPages}
            </span>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages || loading}
              aria-label="Next page"
              className="flex h-7 w-7 items-center justify-center rounded border border-border bg-panel text-ink-muted hover:text-ink-primary disabled:opacity-30 disabled:pointer-events-none transition-colors"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setPage(totalPages)}
              disabled={page === totalPages || loading}
              aria-label="Last page"
              className="flex h-7 w-7 items-center justify-center rounded border border-border bg-panel text-ink-muted hover:text-ink-primary disabled:opacity-30 disabled:pointer-events-none transition-colors"
            >
              <ChevronsRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function IncidentsPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-4">
          <div className="h-8 w-48 bg-elevated rounded animate-pulse" />
          <SkeletonTable rows={PAGE_SIZE} cols={7} />
        </div>
      }
    >
      <IncidentQueueContent />
    </Suspense>
  )
}
