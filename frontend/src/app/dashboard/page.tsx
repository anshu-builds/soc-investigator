'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Clock,
  ExternalLink,
  Flame,
  Layers,
  MessageSquare,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  Upload,
  User,
  Wifi,
  Zap,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'

import { getDashboardSummary, getWazuhStatus } from '@/lib/api'
import type { DashboardSummary, IncidentSummary, WazuhStatusResponse } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { SkeletonCard, SkeletonTable } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'

export default function DashboardPage() {
  const router = useRouter()
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [wazuh, setWazuh] = useState<WazuhStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const load = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true)
    else setRefreshing(true)
    setError(null)

    try {
      const [dashData, wazuhData] = await Promise.all([
        getDashboardSummary(),
        getWazuhStatus().catch(() => null),
      ])
      setSummary(dashData)
      setWazuh(wazuhData)
      setLastUpdated(new Date())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to retrieve SOC telemetry metrics')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

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
        <div className="flex items-center justify-between border-b border-border/60 pb-4">
          <div className="space-y-2">
            <div className="h-6 w-52 bg-elevated rounded animate-pulse" />
            <div className="h-3.5 w-72 bg-elevated/60 rounded animate-pulse" />
          </div>
        </div>
        <div className="h-20 bg-elevated/40 rounded border border-border/60 animate-pulse" />
        <SkeletonTable rows={6} cols={7} />
        <div className="grid gap-6 lg:grid-cols-2">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </div>
    )
  }

  if (error && !summary) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center p-6">
        <div className="max-w-md p-6 text-center border border-severity-critical/30 bg-panel rounded-lg">
          <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
          <h2 className="mt-3 text-base font-semibold text-ink-primary">
            Command Center Telemetry Offline
          </h2>
          <p className="mt-1 text-xs text-ink-secondary">{error}</p>
          <button
            type="button"
            onClick={() => load()}
            className="btn-primary mt-5 inline-flex items-center gap-1.5"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Reconnect Telemetry
          </button>
        </div>
      </div>
    )
  }

  const s = summary!
  const processed = s.events_processed_total || 0
  const flagged = s.events_flagged_total || 0
  const totalInc = s.total_incidents || 0
  const openInc = s.open_incidents || 0
  const criticalCount = s.critical_count || 0
  const highCount = s.high_count || 0
  const mediumCount = s.medium_count || 0
  const lowCount = s.low_count || 0

  const flagRate = processed > 0 ? ((flagged / processed) * 100).toFixed(1) : '0.0'
  const conversionRate = flagged > 0 ? ((totalInc / flagged) * 100).toFixed(1) : '0.0'

  const posture =
    criticalCount > 0
      ? { label: 'CRITICAL ATTENTION REQUIRED', text: 'text-severity-critical', dot: 'bg-severity-critical' }
      : highCount > 0
      ? { label: 'ELEVATED THREAT DETECTED', text: 'text-severity-high', dot: 'bg-severity-high' }
      : openInc > 0
      ? { label: 'ACTIVE TRIAGE IN PROGRESS', text: 'text-severity-medium', dot: 'bg-severity-medium' }
      : { label: 'SYSTEM NOMINAL — NO ACTIVE INCIDENTS', text: 'text-accent-emerald', dot: 'bg-accent-emerald' }

  const sortedAttackTypes = Object.entries(s.incidents_by_type || {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-6">
      {/* Background refresh non-blocking error banner */}
      {error && summary && (
        <div
          role="alert"
          className="flex items-center justify-between rounded border border-severity-critical/30 bg-[#450a0a]/40 px-4 py-2 text-xs text-severity-critical animate-fade-in"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>Telemetry update failed: {error}. Retaining previously cached snapshot.</span>
          </div>
          <button
            type="button"
            onClick={() => load(true)}
            className="underline hover:text-ink-primary font-mono text-[11px]"
          >
            Retry
          </button>
        </div>
      )}

      {/* STAGE 1: COMMAND CENTER HEADER & SYNC CONTROLS */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              SOC Command Center
            </h1>
            <div className="flex items-center gap-1.5 text-xs font-mono">
              <span className={`h-2 w-2 rounded-full ${posture.dot}`} />
              <span className={`font-semibold ${posture.text}`}>{posture.label}</span>
            </div>
          </div>
          <p className="mt-1 text-xs text-ink-secondary">
            Continuous enterprise threat monitoring, automated event correlation, and triage dispatch
          </p>
        </div>

        {/* Sync Controls & Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          {lastUpdated && (
            <span className="hidden sm:inline font-mono text-[11px] text-ink-muted">
              Updated {format(lastUpdated, 'HH:mm:ss')} UTC
            </span>
          )}

          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            title="Toggle automated 30-second telemetry polling"
            className={`flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs font-mono transition-colors ${
              autoRefresh
                ? 'border-accent-emerald/40 bg-accent-emerald/10 text-accent-emerald'
                : 'border-border bg-panel text-ink-muted hover:text-ink-secondary'
            }`}
          >
            <Clock className="h-3 w-3" />
            <span>{autoRefresh ? '30s Polling' : 'Manual'}</span>
          </button>

          <button
            type="button"
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5"
          >
            <RefreshCw
              className={`h-3 w-3 ${refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'}`}
            />
            <span>{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>

          <Link href="/upload-logs" className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest Telemetry</span>
          </Link>
        </div>
      </div>

      {/* STAGE 2: UNIFIED HORIZONTAL POSTURE & METRICS STRIP */}
      <div className="rounded-lg border border-border/80 bg-panel/70 grid grid-cols-2 sm:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-border/60">
        <Link
          href="/incidents?severity=CRITICAL"
          className="p-3.5 hover:bg-elevated/40 transition-colors group"
        >
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-severity-critical shrink-0" />
            <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-ink-muted group-hover:text-ink-secondary">
              Critical
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {criticalCount}
            </span>
            <span className="text-[11px] text-severity-critical">immediate</span>
          </div>
        </Link>

        <Link
          href="/incidents?severity=HIGH"
          className="p-3.5 hover:bg-elevated/40 transition-colors group"
        >
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-severity-high shrink-0" />
            <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-ink-muted group-hover:text-ink-secondary">
              High
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {highCount}
            </span>
            <span className="text-[11px] text-severity-high">escalated</span>
          </div>
        </Link>

        <Link
          href="/incidents"
          className="p-3.5 hover:bg-elevated/40 transition-colors group"
        >
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-severity-medium shrink-0" />
            <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-ink-muted group-hover:text-ink-secondary">
              Active Triage
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {openInc}
            </span>
            <span className="text-[11px] text-ink-muted">of {totalInc} total</span>
          </div>
        </Link>

        <Link
          href="/logs"
          className="p-3.5 hover:bg-elevated/40 transition-colors group"
        >
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-severity-low shrink-0" />
            <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-ink-muted group-hover:text-ink-secondary">
              Telemetry Processed
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {processed.toLocaleString()}
            </span>
            <span className="text-[11px] text-ink-muted font-mono">{flagged} flagged</span>
          </div>
        </Link>

        <div className="p-3.5">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-accent-emerald shrink-0" />
            <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-ink-muted">
              Pipeline State
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-accent-emerald tabular-nums">
              {flagRate}%
            </span>
            <span className="text-[11px] text-ink-muted">anomaly ratio</span>
          </div>
        </div>
      </div>

      {/* STAGE 3: PRIMARY PRIORITY INCIDENTS TABLE (ANALYST WORKSPACE FOCUS) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-border/80 pb-2.5">
          <div className="flex items-center gap-2.5">
            <h2 className="text-sm font-semibold text-ink-primary">
              Priority Incidents Requiring Triage
            </h2>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-xs text-ink-secondary border border-border">
              {s.recent_incidents.length} active
            </span>
          </div>
          <Link
            href="/incidents"
            className="text-xs font-medium text-ink-secondary hover:text-ink-primary flex items-center gap-1 transition-colors"
          >
            <span>Open Incident Queue ({totalInc})</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {s.recent_incidents.length === 0 ? (
          <EmptyState
            title="No open incidents"
            description="All security incidents have been resolved or triaged. Telemetry ingest will automatically synthesize new threats."
            actionLabel="Ingest Telemetry"
            actionHref="/upload-logs"
          />
        ) : (
          <div className="overflow-x-auto border-y border-border/80">
            <table className="w-full text-left font-sans text-xs">
              <thead className="th-soc">
                <tr>
                  <th className="py-2.5 px-3.5">Severity</th>
                  <th className="py-2.5 px-3.5">Incident Title & Scope</th>
                  <th className="py-2.5 px-3.5">Attack Vector</th>
                  <th className="py-2.5 px-3.5">Target Entity</th>
                  <th className="py-2.5 px-3.5">Status</th>
                  <th className="py-2.5 px-3.5">Detected</th>
                  <th className="py-2.5 px-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/80">
                {s.recent_incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') router.push(`/incidents/${inc.id}`)
                    }}
                    onClick={() => router.push(`/incidents/${inc.id}`)}
                    className="tr-soc cursor-pointer"
                  >
                    <td className="td-soc whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="td-soc max-w-sm">
                      <span className="font-semibold text-ink-primary block truncate hover:text-accent-emerald transition-colors">
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
                        <span className="flex items-center gap-1.5 text-[#facc15]" title={`User: ${inc.affected_username}`}>
                          <User className="h-3.5 w-3.5 shrink-0" />
                          <span className="truncate max-w-[120px]">{inc.affected_username}</span>
                        </span>
                      ) : inc.source_ip ? (
                        <span className="flex items-center gap-1.5 text-accent-cyan" title={`IP: ${inc.source_ip}`}>
                          <Wifi className="h-3.5 w-3.5 shrink-0" />
                          <span>{inc.source_ip}</span>
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>
                    <td className="td-soc whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="td-soc whitespace-nowrap font-mono text-[11px] text-ink-muted">
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
                          className="btn-ghost text-[11px] py-1 px-2"
                          title="Open full incident investigation workspace"
                        >
                          <span>Triage</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                        <Link
                          href={`/incidents/${inc.id}/chat`}
                          className="btn-ghost text-[11px] py-1 px-2 border-accent-cyan/30 text-accent-cyan"
                          title="Consult AI Investigation Copilot"
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
      </div>

      {/* STAGE 4: TWO-COLUMN TELEMETRY & PIPELINE OBSERVABILITY */}
      <div className="grid gap-6 lg:grid-cols-2 pt-2">
        {/* Left Column: Detection Pipeline Conversion Funnel */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-accent-emerald" />
              <span>Telemetry Ingestion & Detection Funnel</span>
            </h3>
            <span className="font-mono text-[11px] text-ink-muted">
              {conversionRate}% Flag Conversion
            </span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1.5">
              <div className="flex justify-between text-ink-secondary">
                <span>1. Raw Security Telemetry</span>
                <span className="text-ink-primary font-semibold">{processed.toLocaleString()} events</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-canvas overflow-hidden">
                <div className="h-full bg-accent-blue" style={{ width: '100%' }} />
              </div>
            </div>

            <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1.5">
              <div className="flex justify-between text-ink-secondary">
                <span>2. Suspicious Anomaly Triggers</span>
                <span className="text-severity-critical font-semibold">
                  {flagged.toLocaleString()} ({flagRate}%)
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-canvas overflow-hidden">
                <div
                  className="h-full bg-severity-critical"
                  style={{ width: `${Math.min(100, Math.max(3, Number(flagRate)))}%` }}
                />
              </div>
            </div>

            <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1.5">
              <div className="flex justify-between text-ink-secondary">
                <span>3. Correlated Threat Incidents</span>
                <span className="text-severity-medium font-semibold">
                  {totalInc} incidents ({conversionRate}%)
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-canvas overflow-hidden">
                <div
                  className="h-full bg-severity-medium"
                  style={{ width: `${Math.min(100, Math.max(2, totalInc * 6))}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Telemetry & Wazuh Integration Health */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Server className="h-3.5 w-3.5 text-accent-cyan" />
              <span>Sensors & Daemon Health</span>
            </h3>
            <Link
              href="/integrations/wazuh"
              className="text-[11px] font-mono text-accent-cyan hover:underline flex items-center gap-1"
            >
              Configure <ExternalLink className="h-3 w-3" />
            </Link>
          </div>

          <div className="space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 rounded border border-border/80 bg-panel/50">
              <span className="text-ink-secondary">Wazuh SIEM Ingestion Link</span>
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${
                    wazuh?.status === 'ready'
                      ? 'bg-accent-emerald'
                      : wazuh
                      ? 'bg-severity-critical'
                      : 'bg-severity-medium'
                  }`}
                />
                <span className="text-ink-primary capitalize">{wazuh?.status || 'Standby'}</span>
              </div>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded border border-border/80 bg-panel/50">
              <span className="text-ink-secondary">Deduplication LRU Cache</span>
              <span className="text-ink-primary font-semibold">
                {wazuh?.dedup_cache_size ?? 0} signatures
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded border border-border/80 bg-panel/50">
              <span className="text-ink-secondary">Ingestion Poller Loop</span>
              <span
                className={`font-semibold ${
                  wazuh?.api_polling?.running
                    ? 'text-accent-emerald'
                    : wazuh?.api_polling?.enabled
                    ? 'text-accent-cyan'
                    : 'text-ink-muted'
                }`}
              >
                {wazuh?.api_polling?.running
                  ? 'Actively Ingesting'
                  : wazuh?.api_polling?.enabled
                  ? 'Daemon Ready'
                  : 'Idle'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
