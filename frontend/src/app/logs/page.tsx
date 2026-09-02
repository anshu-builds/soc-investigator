'use client'

import React, { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Database,
  ExternalLink,
  Filter,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  Upload,
  User,
  Wifi,
  X,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'

import { getLogs } from '@/lib/api'
import type { SecurityEvent } from '@/lib/types'
import { EventDrawer } from '@/components/ui/EventDrawer'
import { SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ActiveFilters, type ActiveFilterItem } from '@/components/ui/FilterChips'

const PAGE_SIZE = 25

function LogsContent() {
  const router = useRouter()
  const searchParams = useSearchParams()

  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Server-backed filters
  const [eventType, setEventType] = useState(searchParams.get('event_type') || '')
  const [isFlagged, setIsFlagged] = useState<string>(searchParams.get('is_flagged') || '')
  const [sourceIp, setSourceIp] = useState(searchParams.get('source_ip') || '')
  const [username, setUsername] = useState(searchParams.get('username') || '')
  const [localSearch, setLocalSearch] = useState('')
  const [page, setPage] = useState(1)

  // Drawer inspection
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)

  const fetchLogs = useCallback(
    async (isSilent = false) => {
      if (!isSilent) setLoading(true)
      else setRefreshing(true)
      setError(null)

      try {
        const params: Record<string, string> = {
          page: String(page),
          limit: String(PAGE_SIZE),
        }
        if (eventType) params.event_type = eventType
        if (sourceIp.trim()) params.source_ip = sourceIp.trim()
        if (username.trim()) params.username = username.trim()
        if (isFlagged === 'true') params.is_flagged = 'true'
        if (isFlagged === 'false') params.is_flagged = 'false'

        const res = await getLogs(params)
        setEvents(res.items || [])
        setTotal(res.total || 0)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to retrieve security events from SIEM')
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    [page, eventType, sourceIp, username, isFlagged]
  )

  useEffect(() => {
    fetchLogs()
  }, [fetchLogs])

  const filteredEvents = events.filter((ev) => {
    if (!localSearch.trim()) return true
    const q = localSearch.toLowerCase()
    return (
      (ev.description || '').toLowerCase().includes(q) ||
      (ev.raw_log || '').toLowerCase().includes(q) ||
      (ev.hostname || '').toLowerCase().includes(q) ||
      (ev.destination_ip || '').toLowerCase().includes(q)
    )
  })

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const resetFilters = () => {
    setEventType('')
    setIsFlagged('')
    setSourceIp('')
    setUsername('')
    setLocalSearch('')
    setPage(1)
  }

  const activeFilterList: ActiveFilterItem[] = []
  if (eventType) {
    activeFilterList.push({
      id: 'event_type',
      label: 'Type',
      value: eventType,
      onRemove: () => {
        setEventType('')
        setPage(1)
      },
    })
  }
  if (isFlagged) {
    activeFilterList.push({
      id: 'is_flagged',
      label: 'Posture',
      value: isFlagged === 'true' ? 'Flagged Anomalies' : 'Standard Baseline',
      onRemove: () => {
        setIsFlagged('')
        setPage(1)
      },
    })
  }
  if (sourceIp) {
    activeFilterList.push({
      id: 'source_ip',
      label: 'Source IP',
      value: sourceIp,
      onRemove: () => {
        setSourceIp('')
        setPage(1)
      },
    })
  }
  if (username) {
    activeFilterList.push({
      id: 'username',
      label: 'User',
      value: username,
      onRemove: () => {
        setUsername('')
        setPage(1)
      },
    })
  }

  const hasFilters = activeFilterList.length > 0 || localSearch.trim().length > 0
  const startRange = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const endRange = Math.min(page * PAGE_SIZE, total)

  return (
    <div className="space-y-4">
      {/* 1. TOP HEADER & QUICK FILTER BAR */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-border/80 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              SIEM EVENT EXPLORER
            </h1>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-xs font-semibold text-ink-secondary border border-border">
              {total.toLocaleString()} EVENTS RECORDED
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary">
            Unified telemetry stream with attribute filtering, anomaly tracking, and incident correlation
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Flagged Filter Toggle */}
          <button
            type="button"
            onClick={() => {
              setIsFlagged(isFlagged === 'true' ? '' : 'true')
              setPage(1)
            }}
            className={`rounded px-2.5 py-1 text-xs font-sans transition-colors flex items-center gap-1.5 ${
              isFlagged === 'true'
                ? 'bg-[#450a0a]/60 text-severity-critical font-semibold border border-severity-critical/40'
                : 'text-ink-secondary hover:text-severity-critical hover:bg-elevated/40'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-severity-critical" />
            <span>Flagged Only</span>
          </button>

          <Link
            href="/query"
            className="btn-ghost text-xs py-1 px-2.5 flex items-center gap-1.5"
            title="Translate natural language to SQL"
          >
            <Terminal className="h-3 w-3" />
            <span>Query Studio</span>
          </Link>

          <button
            type="button"
            onClick={() => fetchLogs(true)}
            disabled={refreshing}
            className="btn-ghost text-xs py-1 px-2.5 flex items-center gap-1.5"
            title="Refresh stream"
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
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
          <input
            type="text"
            placeholder="Search description, raw log, host…"
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            className="input w-full pl-9 pr-8 text-xs py-1.5 bg-panel/60"
          />
          {localSearch && (
            <button
              type="button"
              onClick={() => setLocalSearch('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary p-0.5"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Event Type Filter */}
        <select
          value={eventType}
          onChange={(e) => {
            setEventType(e.target.value)
            setPage(1)
          }}
          className="select text-xs font-mono py-1.5"
          aria-label="Filter by Event Type"
        >
          <option value="">All Event Types</option>
          <option value="AUTH_FAILURE">AUTH_FAILURE</option>
          <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
          <option value="PRIV_CHANGE">PRIV_CHANGE</option>
          <option value="FILE_ACCESS">FILE_ACCESS</option>
          <option value="PROCESS_EXEC">PROCESS_EXEC</option>
        </select>

        {/* Source IP Filter */}
        <input
          type="text"
          placeholder="Filter Source IP…"
          value={sourceIp}
          onChange={(e) => {
            setSourceIp(e.target.value)
            setPage(1)
          }}
          className="input w-36 text-xs font-mono py-1.5 bg-panel/60"
        />

        {/* Username Filter */}
        <input
          type="text"
          placeholder="Filter User…"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value)
            setPage(1)
          }}
          className="input w-32 text-xs font-mono py-1.5 bg-panel/60"
        />

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

      {/* 3. OPEN CANVAS HIGH-DENSITY EVENT TABLE */}
      {loading && !refreshing ? (
        <SkeletonTable rows={PAGE_SIZE} cols={7} />
      ) : error ? (
        <div className="p-12 text-center border border-severity-critical/30 rounded bg-panel/50">
          <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
          <h3 className="mt-3 text-sm font-semibold text-ink-primary">Failed to load security telemetry</h3>
          <p className="text-xs text-ink-secondary mt-1">{error}</p>
          <button
            type="button"
            onClick={() => fetchLogs()}
            className="btn-ghost mt-4 text-xs"
          >
            Retry
          </button>
        </div>
      ) : filteredEvents.length === 0 ? (
        <EmptyState
          title={hasFilters ? 'No matching security events found' : 'No telemetry events recorded'}
          description={
            hasFilters
              ? 'Try modifying your search query or removing active filters.'
              : 'The SIEM database contains zero security events. Ingest logs to populate the database.'
          }
          actionLabel={hasFilters ? 'Clear All Filters' : 'Ingest Logs'}
          onAction={hasFilters ? resetFilters : undefined}
          actionHref={hasFilters ? undefined : '/upload-logs'}
        />
      ) : (
        <div className="overflow-x-auto border-y border-border/80">
          <table className="w-full text-left font-sans text-xs">
            <thead className="th-soc">
              <tr>
                <th className="py-2.5 px-3.5 w-24">Posture</th>
                <th className="py-2.5 px-3.5">Timestamp (UTC)</th>
                <th className="py-2.5 px-3.5">Event Type</th>
                <th className="py-2.5 px-3.5">Source IP</th>
                <th className="py-2.5 px-3.5">Target / User</th>
                <th className="py-2.5 px-3.5">Description</th>
                <th className="py-2.5 px-3.5">Correlated Incident</th>
                <th className="py-2.5 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/80">
              {filteredEvents.map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => setSelectedEvent(ev)}
                  className={`tr-soc cursor-pointer ${
                    ev.is_flagged ? 'bg-severity-critical/5' : ''
                  }`}
                >
                  {/* Posture Dot */}
                  <td className="td-soc whitespace-nowrap">
                    {ev.is_flagged ? (
                      <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold text-severity-critical">
                        <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
                        FLAGGED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-ink-muted">
                        <span className="h-1.5 w-1.5 rounded-full bg-border-active" />
                        NORMAL
                      </span>
                    )}
                  </td>

                  {/* Timestamp */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px] text-ink-secondary">
                    {format(new Date(ev.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                  </td>

                  {/* Event Type */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px] font-semibold text-ink-primary">
                    {ev.event_type}
                  </td>

                  {/* Source IP */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px] text-accent-cyan">
                    {ev.source_ip || '—'}
                  </td>

                  {/* Target / User */}
                  <td className="td-soc whitespace-nowrap font-mono text-[11px]">
                    {ev.username ? (
                      <span className="text-[#facc15] font-semibold">{ev.username}</span>
                    ) : ev.hostname ? (
                      <span className="text-ink-secondary">{ev.hostname}</span>
                    ) : (
                      <span className="text-ink-muted">—</span>
                    )}
                  </td>

                  {/* Description */}
                  <td className="td-soc max-w-xs truncate text-ink-secondary" title={ev.description || ''}>
                    {ev.description || '—'}
                  </td>

                  {/* Correlated Incident */}
                  <td
                    className="td-soc whitespace-nowrap"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {ev.incident_id ? (
                      <Link
                        href={`/incidents/${ev.incident_id}`}
                        className="inline-flex items-center gap-1 rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-accent-emerald border border-accent-emerald/30 hover:bg-accent-emerald/10 transition-colors"
                        title="View linked security incident"
                      >
                        <Shield className="h-3 w-3" />
                        <span>INC-{ev.incident_id.slice(0, 8)}</span>
                      </Link>
                    ) : (
                      <span className="text-ink-muted font-mono text-[10px]">—</span>
                    )}
                  </td>

                  {/* Inspect Action */}
                  <td
                    className="td-soc text-right whitespace-nowrap"
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedEvent(ev)
                    }}
                  >
                    <button
                      type="button"
                      className="btn-ghost text-[11px] py-0.5 px-2"
                    >
                      Raw &gt;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 4. FOOTER PAGINATION */}
      {total > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs">
          <span className="text-ink-muted font-mono text-[11px]">
            Showing <strong className="text-ink-primary font-semibold">{startRange}</strong> to{' '}
            <strong className="text-ink-primary font-semibold">{endRange}</strong> of{' '}
            <strong className="text-ink-primary font-semibold">{total}</strong> security events
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

      {/* Raw Event Detail Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}

export default function LogsPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-4">
          <div className="h-8 w-48 bg-elevated rounded animate-pulse" />
          <SkeletonTable rows={PAGE_SIZE} cols={8} />
        </div>
      }
    >
      <LogsContent />
    </Suspense>
  )
}
