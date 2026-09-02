'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Clock,
  ExternalLink,
  Flame,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  Upload,
  User,
  Wifi,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

import { getDashboardSummary } from '@/lib/api'
import type { DashboardSummary, IncidentSummary } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { SkeletonCard, SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const load = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await getDashboardSummary()
      setSummary(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to retrieve SOC metrics')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // Auto-refresh interval (every 30 seconds if enabled)
  useEffect(() => {
    if (!autoRefresh) return
    const timer = setInterval(() => {
      load(true)
    }, 30000)
    return () => clearInterval(timer)
  }, [autoRefresh, load])

  if (loading && !summary) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-6 w-48 bg-[#1e293b] rounded animate-pulse" />
            <div className="h-4 w-72 bg-[#1e293b]/60 rounded animate-pulse" />
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
        <SkeletonTable rows={5} cols={5} />
      </div>
    )
  }

  if (error && !summary) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center p-6">
        <div className="card max-w-md p-6 text-center border-[#7f1d1d] bg-[#11161d]">
          <AlertTriangle className="mx-auto h-8 w-8 text-[#ef4444]" />
          <h2 className="mt-3 text-base font-semibold text-[#f3f4f6]">
            Telemetry Unavailable
          </h2>
          <p className="mt-1 text-xs text-[#9ca3af]">{error}</p>
          <button onClick={() => load()} className="btn-primary mt-5">
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Reconnect
          </button>
        </div>
      </div>
    )
  }

  const s = summary!
  const processed = s.events_processed_total || 0
  const flagged = s.events_flagged_total || 0
  const totalInc = s.total_incidents || 0
  const flagRate = processed > 0 ? ((flagged / processed) * 100).toFixed(1) : '0'

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
              SOC Command Center
            </h1>
            <span className="flex items-center gap-1 rounded border border-[#10b981]/30 bg-[#10b981]/10 px-2 py-0.5 font-mono text-[10px] font-medium text-[#34d399]">
              <Radio className="h-2.5 w-2.5 animate-pulse text-[#10b981]" /> Live Stream
            </span>
          </div>
          <p className="mt-1 text-xs text-[#9ca3af]">
            Real-time threat monitoring, detection telemetry, and incident queue
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Auto Refresh Toggle */}
          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition ${
              autoRefresh
                ? 'border-[#10b981]/40 bg-[#10b981]/10 text-[#34d399]'
                : 'border-[#1f2937] bg-[#171e28] text-[#6b7280]'
            }`}
          >
            <Clock className="h-3 w-3" />
            <span>Auto: {autoRefresh ? '30s' : 'Off'}</span>
          </button>

          {/* Manual Refresh */}
          <button
            type="button"
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-ghost text-xs py-1.5 px-3"
          >
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${refreshing ? 'animate-spin text-[#10b981]' : 'text-[#9ca3af]'}`} />
            Sync
          </button>

          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3">
            <Upload className="mr-1.5 h-3.5 w-3.5" />
            Ingest Logs
          </Link>
        </div>
      </div>

      {/* KPI Severity & Status Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Critical Card */}
        <div className="card p-4 border-[#7f1d1d]/40 bg-[#11161d] hover:border-[#7f1d1d] transition">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#f87171]">
              Critical Incidents
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#7f1d1d] bg-[#450a0a]">
              <Flame className="h-3.5 w-3.5 text-[#ef4444]" />
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#f3f4f6] tabular-nums">
              {s.critical_count}
            </span>
            <span className="text-xs text-[#9ca3af]">action required</span>
          </div>
        </div>

        {/* High Card */}
        <div className="card p-4 border-[#7c2d12]/40 bg-[#11161d] hover:border-[#7c2d12] transition">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#fb923c]">
              High Incidents
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#7c2d12] bg-[#431407]">
              <AlertTriangle className="h-3.5 w-3.5 text-[#f97316]" />
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#f3f4f6] tabular-nums">
              {s.high_count}
            </span>
            <span className="text-xs text-[#9ca3af]">elevated threat</span>
          </div>
        </div>

        {/* Open Incidents */}
        <div className="card p-4 border-[#1f2937] bg-[#11161d] hover:border-[#374151] transition">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#eab308]">
              Active Triage
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#713f12] bg-[#422006]">
              <ShieldAlert className="h-3.5 w-3.5 text-[#eab308]" />
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#f3f4f6] tabular-nums">
              {s.open_incidents}
            </span>
            <span className="text-xs text-[#9ca3af]">of {s.total_incidents} total</span>
          </div>
        </div>

        {/* Telemetry Funnel */}
        <div className="card p-4 border-[#1f2937] bg-[#11161d] hover:border-[#374151] transition">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#38bdf8]">
              Events Processed
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#0e7490] bg-[#083344]">
              <Activity className="h-3.5 w-3.5 text-[#38bdf8]" />
            </span>
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#f3f4f6] tabular-nums">
              {processed.toLocaleString()}
            </span>
            <span className="text-xs font-mono text-[#f87171]">{flagged} flagged</span>
          </div>
        </div>
      </div>

      {/* Analytics Rows: Detection Funnel & Attack Vectors */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Detection Pipeline Funnel */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
            <div>
              <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-[#10b981]" />
                Detection Pipeline Throughput
              </h2>
              <p className="mt-0.5 text-xs text-[#9ca3af]">
                Raw telemetry ingestion to correlated incident conversion
              </p>
            </div>
            <span className="font-mono text-xs text-[#10b981] bg-[#10b981]/10 px-2 py-0.5 rounded border border-[#10b981]/20">
              {flagRate}% Anomaly Rate
            </span>
          </div>

          <div className="mt-5 space-y-4 font-mono text-xs">
            {/* Ingested */}
            <div>
              <div className="flex justify-between text-[#9ca3af] mb-1">
                <span>1. Raw Logs Ingested</span>
                <span className="text-[#f3f4f6] font-semibold">{processed.toLocaleString()}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-[#171e28]">
                <div className="h-2 rounded-full bg-[#3b82f6]" style={{ width: '100%' }} />
              </div>
            </div>

            {/* Flagged */}
            <div>
              <div className="flex justify-between text-[#9ca3af] mb-1">
                <span>2. Security Rules Flagged</span>
                <span className="text-[#f87171] font-semibold">{flagged.toLocaleString()}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-[#171e28]">
                <div
                  className="h-2 rounded-full bg-[#ef4444]"
                  style={{ width: `${Math.min(100, Math.max(4, Number(flagRate)))}%` }}
                />
              </div>
            </div>

            {/* Correlated Incidents */}
            <div>
              <div className="flex justify-between text-[#9ca3af] mb-1">
                <span>3. Correlated Incidents Created</span>
                <span className="text-[#facc15] font-semibold">{totalInc}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-[#171e28]">
                <div
                  className="h-2 rounded-full bg-[#eab308]"
                  style={{ width: `${Math.min(100, Math.max(2, totalInc * 5))}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Attack Vector Distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
            <div>
              <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
                <Shield className="h-4 w-4 text-[#10b981]" />
                Threat Vector Breakdown
              </h2>
              <p className="mt-0.5 text-xs text-[#9ca3af]">
                Observed attacker techniques and classifications
              </p>
            </div>
            <span className="font-mono text-xs text-[#9ca3af]">
              {Object.keys(s.incidents_by_type || {}).length} Types
            </span>
          </div>

          <div className="mt-4 space-y-3">
            {Object.entries(s.incidents_by_type || {}).length === 0 ? (
              <p className="text-xs text-[#6b7280] py-6 text-center">No attack categories detected yet.</p>
            ) : (
              Object.entries(s.incidents_by_type || {}).map(([type, count]) => {
                const pct = totalInc > 0 ? Math.round((count / totalInc) * 100) : 0
                return (
                  <div key={type} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <AttackTypeLabel attackType={type} />
                      <span className="font-mono text-[11px] text-[#6b7280]">({pct}%)</span>
                    </div>
                    <span className="rounded bg-[#171e28] px-2 py-0.5 font-mono text-xs font-semibold text-[#f3f4f6]">
                      {count}
                    </span>
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>

      {/* Recent Incidents Queue */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#1f2937] p-5">
          <div>
            <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
              <Clock className="h-4 w-4 text-[#10b981]" />
              Recent Incidents Triage Queue
            </h2>
            <p className="mt-0.5 text-xs text-[#9ca3af]">
              High-priority security alerts pending analyst review
            </p>
          </div>
          <Link href="/incidents" className="btn-ghost text-xs py-1 px-3">
            View All ({s.total_incidents}) <ArrowRight className="ml-1 h-3 w-3" />
          </Link>
        </div>

        {s.recent_incidents.length === 0 ? (
          <EmptyState
            title="No recent incidents"
            description="No active alerts recorded. Upload security logs to initiate detection."
            actionLabel="Upload Logs"
            actionHref="/upload-logs"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs">
              <thead className="border-b border-[#1f2937] bg-[#141b24] text-[11px] font-mono uppercase tracking-wider text-[#9ca3af]">
                <tr>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Incident Title</th>
                  <th className="py-2.5 px-4">Type</th>
                  <th className="py-2.5 px-4">Target Scope</th>
                  <th className="py-2.5 px-4">Detected</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182230]">
                {s.recent_incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-[#141b24] transition-colors cursor-pointer"
                    onClick={() => {
                      window.location.href = `/incidents/${inc.id}`
                    }}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <span className="font-medium text-[#f3f4f6] block truncate hover:text-[#10b981]">
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
                    <td className="py-3 px-4 whitespace-nowrap text-[#9ca3af]">
                      {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <Link
                        href={`/incidents/${inc.id}`}
                        className="inline-flex items-center gap-1 rounded border border-[#1f2937] bg-[#171e28] px-2 py-1 text-[11px] font-medium text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
                      >
                        Triage <ExternalLink className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
