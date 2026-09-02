'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Database,
  Filter,
  RefreshCw,
  Search,
  Shield,
  Terminal,
  Upload,
  User,
  Wifi,
  X,
} from 'lucide-react'
import { format } from 'date-fns'

import { getLogs } from '@/lib/api'
import type { SecurityEvent } from '@/lib/types'
import { EventDrawer } from '@/components/ui/EventDrawer'
import { SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'

const PAGE_SIZE = 25

export default function LogsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [eventType, setEventType] = useState('')
  const [isFlagged, setIsFlagged] = useState<string>('')
  const [sourceIp, setSourceIp] = useState('')
  const [username, setUsername] = useState('')
  const [page, setPage] = useState(1)

  // Drawer
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)

  const fetchLogs = useCallback(async () => {
    setLoading(true)
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
      setError(e instanceof Error ? e.message : 'Failed to retrieve security events')
    } finally {
      setLoading(false)
    }
  }, [page, eventType, sourceIp, username, isFlagged])

  useEffect(() => {
    fetchLogs()
  }, [fetchLogs])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const resetFilters = () => {
    setEventType('')
    setIsFlagged('')
    setSourceIp('')
    setUsername('')
    setPage(1)
  }

  const hasFilters = Boolean(eventType || isFlagged || sourceIp || username)

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
            SIEM Event Explorer
          </h1>
          <p className="mt-1 text-xs text-[#9ca3af]">
            Ingested security telemetry, audit logs, and anomaly detection events
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={fetchLogs}
            disabled={loading}
            className="btn-ghost text-xs py-1.5 px-3"
          >
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loading ? 'animate-spin text-[#10b981]' : 'text-[#9ca3af]'}`} />
            Refresh
          </button>
          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3">
            <Upload className="mr-1.5 h-3.5 w-3.5" />
            Ingest Telemetry
          </Link>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="card p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Source IP Search */}
          <div className="relative">
            <Wifi className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Filter by Source IP..."
              value={sourceIp}
              onChange={(e) => {
                setSourceIp(e.target.value)
                setPage(1)
              }}
              className="input w-full pl-9 font-mono text-xs"
            />
          </div>

          {/* Username Search */}
          <div className="relative">
            <User className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Filter by Username..."
              value={username}
              onChange={(e) => {
                setUsername(e.target.value)
                setPage(1)
              }}
              className="input w-full pl-9 font-mono text-xs"
            />
          </div>

          {/* Event Type Select */}
          <div>
            <select
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value)
                setPage(1)
              }}
              className="input w-full font-mono text-xs"
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

          {/* Flagged Filter */}
          <div className="flex items-center gap-2">
            <select
              value={isFlagged}
              onChange={(e) => {
                setIsFlagged(e.target.value)
                setPage(1)
              }}
              className="input flex-1 font-mono text-xs"
            >
              <option value="">All Telemetry</option>
              <option value="true">Flagged Anomalies Only</option>
              <option value="false">Standard Events Only</option>
            </select>

            {hasFilters && (
              <button
                type="button"
                onClick={resetFilters}
                className="flex items-center gap-1 text-xs text-[#f87171] hover:underline px-2 py-1 shrink-0"
              >
                <X className="h-3 w-3" /> Clear
              </button>
            )}
          </div>
        </div>

        {/* Status Bar */}
        <div className="flex items-center justify-between text-[11px] font-mono text-[#9ca3af] pt-1">
          <span>
            Displaying {events.length} of {total} security event{total === 1 ? '' : 's'}
          </span>
          <span>
            Page {page} of {totalPages}
          </span>
        </div>
      </div>

      {/* Events Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <SkeletonTable rows={PAGE_SIZE} cols={6} />
        ) : error ? (
          <div className="p-8 text-center">
            <AlertTriangle className="mx-auto h-8 w-8 text-[#ef4444]" />
            <p className="mt-2 text-sm font-semibold text-[#f3f4f6]">Failed to load events</p>
            <p className="text-xs text-[#9ca3af] mt-1">{error}</p>
            <button onClick={fetchLogs} className="btn-ghost mt-4 text-xs">
              Retry
            </button>
          </div>
        ) : events.length === 0 ? (
          <EmptyState
            title="No events found"
            description={
              hasFilters
                ? 'No security events match your filter criteria. Try adjusting your query parameters.'
                : 'No telemetry ingested yet. Ingest CSV or JSON logs to populate the SIEM.'
            }
            actionLabel={hasFilters ? 'Clear Filters' : 'Ingest Logs'}
            onAction={hasFilters ? resetFilters : undefined}
            actionHref={hasFilters ? undefined : '/upload-logs'}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs">
              <thead className="border-b border-[#1f2937] bg-[#141b24] text-[11px] font-mono uppercase tracking-wider text-[#9ca3af]">
                <tr>
                  <th className="py-2.5 px-4">Timestamp (UTC)</th>
                  <th className="py-2.5 px-4">Event Type</th>
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4">Target User</th>
                  <th className="py-2.5 px-4">Source IP</th>
                  <th className="py-2.5 px-4">Hostname</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Raw Log</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182230] font-mono text-xs">
                {events.map((ev) => (
                  <tr
                    key={ev.id}
                    className="hover:bg-[#141b24] transition-colors cursor-pointer group"
                    onClick={() => setSelectedEvent(ev)}
                  >
                    <td className="py-3 px-4 whitespace-nowrap text-[#9ca3af]">
                      {format(new Date(ev.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="font-semibold text-[#f3f4f6] group-hover:text-[#10b981] transition-colors">
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-[#6b7280]">
                      {ev.event_category}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {ev.username ? (
                        <span className="text-[#facc15]">{ev.username}</span>
                      ) : (
                        <span className="text-[#6b7280]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="text-[#38bdf8]">{ev.source_ip}</span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-[#9ca3af]">
                      {ev.hostname || '—'}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {ev.is_flagged ? (
                        <span className="inline-flex items-center gap-1 rounded border border-[#7f1d1d] bg-[#450a0a] px-1.5 py-0.5 text-[10px] text-[#f87171]">
                          <Shield className="h-2.5 w-2.5" /> Flagged
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded border border-[#1f2937] bg-[#171e28] px-1.5 py-0.5 text-[10px] text-[#9ca3af]">
                          Standard
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(ev)}
                        className="inline-flex items-center gap-1 rounded border border-[#1f2937] bg-[#171e28] px-2 py-1 text-[11px] text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
                      >
                        <Terminal className="h-3 w-3 text-[#10b981]" />
                        Inspect
                      </button>
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

      {/* Raw Event Inspector Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}
