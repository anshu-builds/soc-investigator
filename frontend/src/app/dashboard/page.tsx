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

  // Auto-refresh interval (every 30 seconds if enabled)
  useEffect(() => {
    if (!autoRefresh) return
    const timer = setInterval(() => {
      load(true)
    }, 30000)
    return () => clearInterval(timer)
  }, [autoRefresh, load])

  // Initial skeleton view
  if (loading && !summary) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-4">
          <div className="space-y-2">
            <div className="h-6 w-52 bg-elevated rounded animate-pulse" />
            <div className="h-3.5 w-72 bg-elevated/60 rounded animate-pulse" />
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
        <div className="grid gap-6 lg:grid-cols-2">
          <SkeletonCard />
          <SkeletonCard />
        </div>
        <SkeletonTable rows={5} cols={7} />
      </div>
    )
  }

  // Full error view on first load failure
  if (error && !summary) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center p-6">
        <div className="card max-w-md p-6 text-center border-severity-critical/30 bg-panel">
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

  // Deterministic posture state
  const posture =
    criticalCount > 0
      ? { label: 'CRITICAL ATTENTION REQUIRED', border: 'border-[#7f1d1d]', bg: 'bg-[#450a0a]', text: 'text-[#f87171]', dot: 'bg-[#ef4444]' }
      : highCount > 0
      ? { label: 'ELEVATED THREAT DETECTED', border: 'border-[#7c2d12]', bg: 'bg-[#431407]', text: 'text-[#fb923c]', dot: 'bg-[#f97316]' }
      : openInc > 0
      ? { label: 'ACTIVE TRIAGE IN PROGRESS', border: 'border-[#713f12]', bg: 'bg-[#422006]', text: 'text-[#facc15]', dot: 'bg-[#eab308]' }
      : { label: 'SYSTEM NOMINAL — NO ACTIVE INCIDENTS', border: 'border-[#064e3b]', bg: 'bg-[#022c22]', text: 'text-[#34d399]', dot: 'bg-[#10b981]' }

  // Sorted attack types
  const sortedAttackTypes = Object.entries(s.incidents_by_type || {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-6">
      {/* Background refresh non-blocking error banner */}
      {error && summary && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-lg border border-severity-critical/40 bg-[#450a0a]/80 px-4 py-2 text-xs text-severity-critical animate-fade-in"
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

      {/* LEVEL 1: COMMAND CENTER HEADER & POSTURE */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              SOC Command Center
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold tracking-wide ${posture.border} ${posture.bg} ${posture.text}`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${posture.dot} animate-pulse`} />
              {posture.label}
            </span>
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

          {/* Auto Refresh Toggle */}
          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            title="Toggle automated 30-second telemetry polling"
            className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition active:scale-95 ${
              autoRefresh
                ? 'border-accent-emerald/40 bg-accent-emerald/10 text-accent-emerald'
                : 'border-border bg-panel text-ink-muted hover:text-ink-secondary'
            }`}
          >
            <Clock className="h-3 w-3" />
            <span>{autoRefresh ? 'Auto: 30s' : 'Polling: Off'}</span>
          </button>

          {/* Manual Refresh */}
          <button
            type="button"
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'}`}
            />
            <span>{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>

          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest Logs</span>
          </Link>
        </div>
      </div>

      {/* LEVEL 2: CRITICAL ATTENTION / KPI STRIP */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Critical Card */}
        <Link
          href="/incidents"
          className={`card p-4 transition-all duration-150 hover:border-border-active cursor-pointer ${
            criticalCount > 0
              ? 'border-severity-critical/40 bg-panel hover:border-severity-critical/70'
              : 'border-border bg-panel'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-severity-critical">
              Critical Threats
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-severity-critical/50 bg-[#450a0a]">
              <Flame className="h-3.5 w-3.5 text-severity-critical" />
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {criticalCount}
            </span>
            <span className="text-xs text-ink-secondary">
              {criticalCount > 0 ? 'immediate response required' : 'no critical backlog'}
            </span>
          </div>
        </Link>

        {/* High Threat Card */}
        <Link
          href="/incidents"
          className={`card p-4 transition-all duration-150 hover:border-border-active cursor-pointer ${
            highCount > 0
              ? 'border-severity-high/40 bg-panel hover:border-severity-high/70'
              : 'border-border bg-panel'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-severity-high">
              High Severity
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-severity-high/50 bg-[#431407]">
              <AlertTriangle className="h-3.5 w-3.5 text-severity-high" />
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {highCount}
            </span>
            <span className="text-xs text-ink-secondary">active attack progression</span>
          </div>
        </Link>

        {/* Active Triage Queue Card */}
        <Link
          href="/incidents"
          className="card p-4 border-border bg-panel transition-all duration-150 hover:border-border-active cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-severity-medium">
              Active Triage
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-severity-medium/50 bg-[#422006]">
              <ShieldAlert className="h-3.5 w-3.5 text-severity-medium" />
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {openInc}
            </span>
            <span className="text-xs text-ink-secondary">of {totalInc} total incidents</span>
          </div>
        </Link>

        {/* Total Telemetry Processed */}
        <Link
          href="/logs"
          className="card p-4 border-border bg-panel transition-all duration-150 hover:border-border-active cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-severity-low">
              Events Ingested
            </span>
            <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-severity-low/50 bg-[#083344]">
              <Activity className="h-3.5 w-3.5 text-severity-low" />
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-ink-primary tabular-nums">
              {processed.toLocaleString()}
            </span>
            <span className="text-xs font-mono text-severity-critical">{flagged} flagged</span>
          </div>
        </Link>
      </div>

      {/* LEVEL 3: DETECTION PIPELINE & TELEMETRY HEALTH */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Detection Pipeline Funnel */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <Layers className="h-4 w-4 text-accent-emerald" />
                Detection Pipeline Funnel
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Conversion of raw telemetry streams into correlated security incidents
              </p>
            </div>
            <span className="font-mono text-[11px] text-accent-emerald bg-accent-emerald/10 px-2 py-0.5 rounded border border-accent-emerald/20">
              {flagRate}% Anomaly Ratio
            </span>
          </div>

          <div className="mt-4 space-y-4 font-mono text-xs">
            {/* Stage 1: Ingested */}
            <div className="space-y-1">
              <div className="flex justify-between text-ink-secondary">
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-accent-blue" />
                  1. Raw Security Telemetry
                </span>
                <span className="text-ink-primary font-semibold">{processed.toLocaleString()} events</span>
              </div>
              <div className="h-2 w-full rounded-full bg-canvas overflow-hidden">
                <div className="h-2 rounded-full bg-accent-blue" style={{ width: '100%' }} />
              </div>
            </div>

            {/* Stage 2: Flagged */}
            <div className="space-y-1">
              <div className="flex justify-between text-ink-secondary">
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
                  2. Suspicious Indicators Flagged
                </span>
                <span className="text-severity-critical font-semibold">
                  {flagged.toLocaleString()} ({flagRate}%)
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-canvas overflow-hidden">
                <div
                  className="h-2 rounded-full bg-severity-critical transition-all duration-300"
                  style={{ width: `${Math.min(100, Math.max(3, Number(flagRate)))}%` }}
                />
              </div>
            </div>

            {/* Stage 3: Correlated Incidents */}
            <div className="space-y-1">
              <div className="flex justify-between text-ink-secondary">
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-medium" />
                  3. Correlated Threat Incidents
                </span>
                <span className="text-severity-medium font-semibold">
                  {totalInc} incidents ({conversionRate}% of flagged)
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-canvas overflow-hidden">
                <div
                  className="h-2 rounded-full bg-severity-medium transition-all duration-300"
                  style={{ width: `${Math.min(100, Math.max(2, totalInc * 6))}%` }}
                />
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-[11px] font-mono text-ink-muted">
            <span>Engine: Rule Pattern + Temporal Aggregator</span>
            <Link href="/logs" className="text-accent-emerald hover:underline flex items-center gap-1">
              Inspect Raw Telemetry <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
        </div>

        {/* Integration & Telemetry Health */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <Server className="h-4 w-4 text-accent-cyan" />
                Telemetry & Integration Health
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Active sensor links, dedup state, and daemon heartbeats
              </p>
            </div>
            <Link
              href="/integrations/wazuh"
              className="text-[11px] font-mono text-accent-cyan hover:underline flex items-center gap-1"
            >
              Configure <ExternalLink className="h-3 w-3" />
            </Link>
          </div>

          <div className="mt-4 space-y-3 font-mono text-xs">
            {/* Wazuh Manager State */}
            <div className="flex items-center justify-between p-2.5 rounded-lg border border-border-subtle bg-canvas/60">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${
                    wazuh?.status === 'ready'
                      ? 'bg-accent-emerald animate-pulse-subtle'
                      : wazuh
                      ? 'bg-severity-critical'
                      : 'bg-severity-medium'
                  }`}
                />
                <span className="text-ink-primary font-medium">Wazuh SIEM Ingestion Link</span>
              </div>
              <span className="text-[11px] text-ink-secondary capitalize">
                {wazuh?.status || 'Polling Status…'}
              </span>
            </div>

            {/* Dedup Cache Status */}
            <div className="flex items-center justify-between p-2.5 rounded-lg border border-border-subtle bg-canvas/60">
              <span className="text-ink-secondary">Event Dedup LRU Cache</span>
              <span className="text-ink-primary font-semibold">
                {wazuh?.dedup_cache_size ?? '—'} signatures cached
              </span>
            </div>

            {/* Ingestion Polling Daemon */}
            <div className="flex items-center justify-between p-2.5 rounded-lg border border-border-subtle bg-canvas/60">
              <span className="text-ink-secondary">Background Ingestion Daemon</span>
              <span
                className={`text-[11px] font-semibold ${
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
                  ? 'Enabled (Standby)'
                  : 'Disabled'}
              </span>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-[11px] font-mono text-ink-muted">
            <span>Alerts Processed: {wazuh?.api_polling?.total_alerts_processed ?? 0}</span>
            <span>Errors: {wazuh?.api_polling?.consecutive_errors ?? 0}</span>
          </div>
        </div>
      </div>

      {/* LEVEL 4: THREAT DISTRIBUTION ANALYTICS */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Severity Distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-severity-high" />
                Severity Breakdown
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Current incident distribution by threat severity level
              </p>
            </div>
            <span className="font-mono text-xs text-ink-muted">{totalInc} Total</span>
          </div>

          {/* Segmented Bar */}
          <div className="mt-4">
            <div className="h-3 w-full rounded-full bg-canvas flex overflow-hidden">
              {totalInc > 0 ? (
                <>
                  {criticalCount > 0 && (
                    <div
                      className="h-full bg-severity-critical"
                      style={{ width: `${(criticalCount / totalInc) * 100}%` }}
                      title={`Critical: ${criticalCount}`}
                    />
                  )}
                  {highCount > 0 && (
                    <div
                      className="h-full bg-severity-high"
                      style={{ width: `${(highCount / totalInc) * 100}%` }}
                      title={`High: ${highCount}`}
                    />
                  )}
                  {mediumCount > 0 && (
                    <div
                      className="h-full bg-severity-medium"
                      style={{ width: `${(mediumCount / totalInc) * 100}%` }}
                      title={`Medium: ${mediumCount}`}
                    />
                  )}
                  {lowCount > 0 && (
                    <div
                      className="h-full bg-severity-low"
                      style={{ width: `${(lowCount / totalInc) * 100}%` }}
                      title={`Low: ${lowCount}`}
                    />
                  )}
                </>
              ) : (
                <div className="h-full w-full bg-border-subtle" />
              )}
            </div>

            {/* Distribution Legend & Counts */}
            <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
              <div className="rounded-lg border border-border-subtle bg-canvas/40 p-2.5">
                <div className="flex items-center gap-1.5 text-severity-critical mb-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
                  <span>CRITICAL</span>
                </div>
                <div className="text-base font-bold text-ink-primary">{criticalCount}</div>
                <div className="text-[10px] text-ink-muted">
                  {totalInc > 0 ? Math.round((criticalCount / totalInc) * 100) : 0}%
                </div>
              </div>

              <div className="rounded-lg border border-border-subtle bg-canvas/40 p-2.5">
                <div className="flex items-center gap-1.5 text-severity-high mb-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-high" />
                  <span>HIGH</span>
                </div>
                <div className="text-base font-bold text-ink-primary">{highCount}</div>
                <div className="text-[10px] text-ink-muted">
                  {totalInc > 0 ? Math.round((highCount / totalInc) * 100) : 0}%
                </div>
              </div>

              <div className="rounded-lg border border-border-subtle bg-canvas/40 p-2.5">
                <div className="flex items-center gap-1.5 text-severity-medium mb-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-medium" />
                  <span>MEDIUM</span>
                </div>
                <div className="text-base font-bold text-ink-primary">{mediumCount}</div>
                <div className="text-[10px] text-ink-muted">
                  {totalInc > 0 ? Math.round((mediumCount / totalInc) * 100) : 0}%
                </div>
              </div>

              <div className="rounded-lg border border-border-subtle bg-canvas/40 p-2.5">
                <div className="flex items-center gap-1.5 text-severity-low mb-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-low" />
                  <span>LOW</span>
                </div>
                <div className="text-base font-bold text-ink-primary">{lowCount}</div>
                <div className="text-[10px] text-ink-muted">
                  {totalInc > 0 ? Math.round((lowCount / totalInc) * 100) : 0}%
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Attack Type & Technique Distribution */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <Shield className="h-4 w-4 text-accent-emerald" />
                Attack Vector Classification
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Classified attacker behavior patterns across correlated incidents
              </p>
            </div>
            <span className="font-mono text-xs text-ink-muted">
              {sortedAttackTypes.length} Classes
            </span>
          </div>

          <div className="mt-4 space-y-2.5">
            {sortedAttackTypes.length === 0 ? (
              <p className="text-xs text-ink-muted py-6 text-center">
                No attack categories detected yet.
              </p>
            ) : (
              sortedAttackTypes.map(([type, count]) => {
                const pct = totalInc > 0 ? Math.round((count / totalInc) * 100) : 0
                return (
                  <div
                    key={type}
                    className="flex items-center justify-between rounded-lg border border-border-subtle bg-canvas/40 px-3 py-2 text-xs"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <AttackTypeLabel attackType={type} />
                      <span className="font-mono text-[11px] text-ink-muted">({pct}%)</span>
                    </div>
                    <span className="rounded bg-elevated px-2 py-0.5 font-mono text-xs font-semibold text-ink-primary">
                      {count} {count === 1 ? 'incident' : 'incidents'}
                    </span>
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>

      {/* LEVEL 5: RECENT INCIDENTS QUEUE TABLE */}
      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4 sm:p-5">
          <div>
            <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
              <Clock className="h-4 w-4 text-accent-emerald" />
              Recent Incidents Triage Queue
            </h2>
            <p className="mt-0.5 text-xs text-ink-secondary">
              Latest high-priority security alerts pending analyst investigation
            </p>
          </div>
          <Link href="/incidents" className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1">
            <span>View Full Queue ({totalInc})</span>
            <ArrowRight className="h-3 w-3" />
          </Link>
        </div>

        {s.recent_incidents.length === 0 ? (
          <EmptyState
            title="No recent incidents"
            description="No active security incidents recorded in this environment. Ingest telemetry logs to initiate automated correlation."
            actionLabel="Ingest Logs"
            actionHref="/upload-logs"
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
                  <th className="py-2.5 px-4">Detected</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {s.recent_incidents.map((inc) => (
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
                    <td className="td-soc max-w-xs">
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
                    <td className="td-soc whitespace-nowrap font-mono text-[11px] text-ink-secondary">
                      <span title={format(new Date(inc.created_at), 'yyyy-MM-dd HH:mm:ss')}>
                        {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                      </span>
                    </td>
                    <td className="td-soc whitespace-nowrap">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td
                      className="td-soc text-right whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1.5">
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="inline-flex items-center gap-1 rounded-md border border-border bg-elevated px-2 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95"
                          title="Open full incident investigation workspace"
                        >
                          <span>Triage</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                        <Link
                          href={`/incidents/${inc.id}/chat`}
                          className="inline-flex items-center gap-1 rounded-md border border-accent-cyan/30 bg-accent-cyan/10 px-2 py-1 text-[11px] font-medium text-accent-cyan hover:bg-accent-cyan/20 transition active:scale-95"
                          title="Consult AI Investigation Copilot"
                        >
                          <MessageSquare className="h-3 w-3" />
                          <span className="hidden sm:inline">Copilot</span>
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
    </div>
  )
}
