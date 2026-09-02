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

  // Server-backed filters initialized optionally from URL search params
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

  // Client-side quick refinement across description, raw log, and target host for currently loaded slice
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

  const hasFilters = Boolean(eventType || isFlagged || sourceIp || username || localSearch)

  // Build active filter items for FilterChips
  const activeFilterList: ActiveFilterItem[] = []
  if (localSearch) {
    activeFilterList.push({
      id: 'search',
      label: 'Search',
      value: `"${localSearch}"`,
      onRemove: () => setLocalSearch(''),
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
      label: 'Status',
      value: isFlagged === 'true' ? 'Flagged Anomalies' : 'Standard Events',
      onRemove: () => {
        setIsFlagged('')
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
              SIEM Event Explorer
            </h1>
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-elevated px-2.5 py-0.5 font-mono text-[11px] text-ink-secondary">
              <span className="font-semibold text-ink-primary">{total}</span>
              <span>ingested events</span>
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary">
            Ingested security telemetry, audit event streams, and anomaly detection logs
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => fetchLogs(true)}
            disabled={loading || refreshing}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Refresh logs from server"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                loading || refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'
              }`}
            />
            <span>{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>
          <Link
            href="/upload-logs"
            className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest Telemetry</span>
          </Link>
        </div>
      </div>

      {/* Filter Controls Toolbar */}
      <div className="card p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {/* Source IP Exact Search */}
          <div className="relative">
            <Wifi className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Source IP (exact)..."
              value={sourceIp}
              onChange={(e) => {
                setSourceIp(e.target.value)
                setPage(1)
              }}
              className="input w-full pl-9 pr-7 font-mono text-xs"
            />
            {sourceIp && (
              <button
                type="button"
                onClick={() => {
                  setSourceIp('')
                  setPage(1)
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          {/* Username Exact Search */}
          <div className="relative">
            <User className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Target User (exact)..."
              value={username}
              onChange={(e) => {
                setUsername(e.target.value)
                setPage(1)
              }}
              className="input w-full pl-9 pr-7 font-mono text-xs"
            />
            {username && (
              <button
                type="button"
                onClick={() => {
                  setUsername('')
                  setPage(1)
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          {/* Event Type Select */}
          <div>
            <select
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value)
                setPage(1)
              }}
              className="select w-full font-mono text-xs"
              aria-label="Filter by Event Type"
            >
              <option value="">All Event Types</option>
              <option value="AUTH_FAILURE">AUTH_FAILURE</option>
              <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
              <option value="SUDO_EXECUTION">SUDO_EXECUTION</option>
              <option value="SSH_LOGIN">SSH_LOGIN</option>
              <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
              <option value="FILE_ACCESS">FILE_ACCESS</option>
              <option value="PORT_SCAN">PORT_SCAN</option>
            </select>
          </div>

          {/* Flagged Status Select */}
          <div>
            <select
              value={isFlagged}
              onChange={(e) => {
                setIsFlagged(e.target.value)
                setPage(1)
              }}
              className="select w-full font-mono text-xs"
              aria-label="Filter by Flagged Status"
            >
              <option value="">All Telemetry</option>
              <option value="true">Flagged Anomalies Only</option>
              <option value="false">Standard Telemetry Only</option>
            </select>
          </div>

          {/* Local Description/Payload Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Refine payload/desc..."
              value={localSearch}
              onChange={(e) => setLocalSearch(e.target.value)}
              className="input w-full pl-9 pr-7 font-mono text-xs"
            />
            {localSearch && (
              <button
                type="button"
                onClick={() => setLocalSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
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

      {/* Main Events Table Card */}
      <div className="card overflow-hidden">
        {loading && !refreshing ? (
          <SkeletonTable rows={PAGE_SIZE} cols={8} />
        ) : error ? (
          <div className="p-12 text-center">
            <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
            <h3 className="mt-3 text-sm font-semibold text-ink-primary">Failed to load events</h3>
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
            title={hasFilters ? 'No matching security events' : 'No telemetry ingested yet'}
            description={
              hasFilters
                ? 'No events match your current query parameters. Try broadening your filters or clearing search.'
                : 'No security events found in the database. Ingest CSV or JSON telemetry logs to populate the SIEM.'
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
                  <th className="py-2.5 px-4">Timestamp (UTC)</th>
                  <th className="py-2.5 px-4">Posture</th>
                  <th className="py-2.5 px-4">Event Type</th>
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4">Target User</th>
                  <th className="py-2.5 px-4">Source IP</th>
                  <th className="py-2.5 px-4">Host / Destination</th>
                  <th className="py-2.5 px-4">Correlated Incident</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle font-mono text-xs">
                {filteredEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') setSelectedEvent(ev)
                    }}
                    onClick={() => setSelectedEvent(ev)}
                    className="tr-soc cursor-pointer focus-visible:outline-none focus-visible:bg-highlight"
                  >
                    <td className="td-soc whitespace-nowrap text-ink-secondary">
                      <span title={format(new Date(ev.timestamp), 'yyyy-MM-dd HH:mm:ss')}>
                        {format(new Date(ev.timestamp), 'HH:mm:ss')}
                      </span>
                      <span className="text-[10px] text-ink-muted block mt-0.5 font-sans">
                        {formatDistanceToNow(new Date(ev.timestamp), { addSuffix: true })}
                      </span>
                    </td>

                    <td className="td-soc whitespace-nowrap">
                      {ev.is_flagged ? (
                        <span className="inline-flex items-center gap-1 rounded border border-severity-critical/40 bg-severity-critical/15 px-2 py-0.5 text-[10px] font-bold text-severity-critical">
                          <Shield className="h-3 w-3" />
                          <span>Flagged</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded border border-border bg-elevated px-2 py-0.5 text-[10px] text-ink-muted">
                          Standard
                        </span>
                      )}
                    </td>

                    <td className="td-soc whitespace-nowrap">
                      <span className="font-semibold text-ink-primary group-hover:text-accent-emerald transition-colors">
                        {ev.event_type}
                      </span>
                    </td>

                    <td className="td-soc whitespace-nowrap text-ink-muted text-[11px]">
                      <span className="rounded bg-elevated px-1.5 py-0.5 border border-border-subtle">
                        {ev.event_category}
                      </span>
                    </td>

                    <td className="td-soc whitespace-nowrap font-mono text-[11px]">
                      {ev.username ? (
                        <span className="flex items-center gap-1 text-[#facc15]">
                          <User className="h-3 w-3 shrink-0" />
                          <span>{ev.username}</span>
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>

                    <td className="td-soc whitespace-nowrap text-accent-cyan">
                      <span className="flex items-center gap-1">
                        <Wifi className="h-3 w-3 shrink-0" />
                        <span>{ev.source_ip}</span>
                      </span>
                    </td>

                    <td className="td-soc whitespace-nowrap text-ink-secondary font-mono text-[11px]">
                      {ev.hostname || ev.destination_ip ? (
                        <span className="flex items-center gap-1">
                          <Server className="h-3 w-3 shrink-0 text-ink-muted" />
                          <span>{ev.hostname || ev.destination_ip}</span>
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>

                    <td
                      className="td-soc whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {ev.incident_id ? (
                        <Link
                          href={`/incidents/${ev.incident_id}`}
                          className="inline-flex items-center gap-1 rounded border border-accent-emerald/30 bg-accent-emerald/10 px-2 py-0.5 font-mono text-[10px] text-accent-emerald hover:bg-accent-emerald/20 transition active:scale-95"
                          title="Open correlated incident workspace"
                        >
                          <ShieldAlert className="h-3 w-3 shrink-0" />
                          <span>{ev.incident_id.slice(0, 8)}</span>
                          <ExternalLink className="h-2.5 w-2.5" />
                        </Link>
                      ) : (
                        <span className="text-ink-muted font-mono text-[11px]">—</span>
                      )}
                    </td>

                    <td
                      className="td-soc text-right whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(ev)}
                        className="inline-flex items-center gap-1 rounded-md border border-border bg-elevated px-2 py-1 text-[11px] font-sans font-medium text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95"
                        title="Inspect full raw event and structured metadata"
                      >
                        <Terminal className="h-3 w-3 text-accent-emerald" />
                        <span>Inspect</span>
                      </button>
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
              <span className="text-ink-primary font-semibold">{total}</span> events
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

      {/* Raw Event Inspector Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}

export default function LogsPage() {
  return (
    <Suspense fallback={<SkeletonTable rows={PAGE_SIZE} cols={8} />}>
      <LogsContent />
    </Suspense>
  )
}
