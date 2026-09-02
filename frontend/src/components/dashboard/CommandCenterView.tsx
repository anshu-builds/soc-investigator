'use client'

import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Activity,
  AlertCircle,
  ArrowRight,
  ArrowUpRight,
  Clock,
  ExternalLink,
  Gauge,
  Layers,
  MessageSquare,
  RefreshCw,
  Server,
  ShieldAlert,
  Upload,
  User,
  Wifi,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'

import type { DashboardSummary, WazuhStatusResponse } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { EmptyState } from '@/components/ui/EmptyState'

export interface CommandCenterViewProps {
  summary: DashboardSummary
  wazuh: WazuhStatusResponse | null
  lastUpdated: Date | null
  autoRefresh: boolean
  refreshing: boolean
  backgroundError?: string | null
  onToggleAutoRefresh: () => void
  onSync: () => void
  onRetryBackground?: () => void
}

interface Posture {
  label: string
  text: string
  dot: string
  ring: string
  band: string
  icon: React.ReactNode
}

export function CommandCenterView({
  summary: s,
  wazuh,
  lastUpdated,
  autoRefresh,
  refreshing,
  backgroundError,
  onToggleAutoRefresh,
  onSync,
  onRetryBackground,
}: CommandCenterViewProps) {
  const router = useRouter()

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

  const posture: Posture =
    criticalCount > 0
      ? {
          label: 'CRITICAL — IMMEDIATE ACTION REQUIRED',
          text: 'text-severity-critical',
          dot: 'bg-severity-critical',
          ring: 'ring-severity-critical/30',
          band: 'from-[#450a0a]/70 via-[#2a0a0a]/30 to-transparent border-severity-critical/40',
          icon: <ShieldAlert className="h-5 w-5 text-severity-critical" />,
        }
      : highCount > 0
      ? {
          label: 'ELEVATED THREAT ACTIVITY DETECTED',
          text: 'text-severity-high',
          dot: 'bg-severity-high',
          ring: 'ring-severity-high/30',
          band: 'from-[#431407]/70 via-[#2a1407]/30 to-transparent border-severity-high/40',
          icon: <ShieldAlert className="h-5 w-5 text-severity-high" />,
        }
      : openInc > 0
      ? {
          label: 'ACTIVE TRIAGE IN PROGRESS',
          text: 'text-severity-medium',
          dot: 'bg-severity-medium',
          ring: 'ring-severity-medium/30',
          band: 'from-[#422006]/60 via-[#2a2006]/25 to-transparent border-severity-medium/40',
          icon: <Activity className="h-5 w-5 text-severity-medium" />,
        }
      : {
          label: 'SYSTEM NOMINAL — NO ACTIVE INCIDENTS',
          text: 'text-accent-emerald',
          dot: 'bg-accent-emerald',
          ring: 'ring-accent-emerald/30',
          band: 'from-[#022c22]/70 via-[#04231b]/30 to-transparent border-accent-emerald/40',
          icon: <Activity className="h-5 w-5 text-accent-emerald" />,
        }

  const sevTotal = criticalCount + highCount + mediumCount + lowCount
  const segments = [
    { key: 'CRITICAL', count: criticalCount, color: 'bg-severity-critical', text: 'text-severity-critical', href: '/incidents?severity=CRITICAL' },
    { key: 'HIGH', count: highCount, color: 'bg-severity-high', text: 'text-severity-high', href: '/incidents?severity=HIGH' },
    { key: 'MEDIUM', count: mediumCount, color: 'bg-severity-medium', text: 'text-severity-medium', href: '/incidents?severity=MEDIUM' },
    { key: 'LOW', count: lowCount, color: 'bg-severity-low', text: 'text-severity-low', href: '/incidents?severity=LOW' },
  ]

  const sortedAttackTypes = Object.entries(s.incidents_by_type || {}).sort((a, b) => b[1] - a[1])
  const maxAttack = sortedAttackTypes.length ? Math.max(...sortedAttackTypes.map(([, v]) => v)) : 0

  return (
    <div className="space-y-6">
      {backgroundError && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-lg border border-severity-critical/30 bg-[#450a0a]/40 px-4 py-2 text-xs text-severity-critical animate-fade-in"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>Telemetry update failed: {backgroundError}. Retaining previously cached snapshot.</span>
          </div>
          {onRetryBackground && (
            <button
              type="button"
              onClick={onRetryBackground}
              className="underline hover:text-ink-primary font-mono text-[11px]"
            >
              Retry
            </button>
          )}
        </div>
      )}

      {/* HEADER */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-elevated">
              <Gauge className="h-4 w-4 text-accent-emerald" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-ink-primary">SOC Command Center</h1>
          </div>
          <p className="text-xs text-ink-secondary max-w-xl">
            Continuous enterprise threat monitoring, automated event correlation, and triage dispatch.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {lastUpdated && (
            <span className="hidden sm:inline font-mono text-[11px] text-ink-muted">
              Updated {format(lastUpdated, 'HH:mm:ss')} UTC
            </span>
          )}
          <button
            type="button"
            onClick={onToggleAutoRefresh}
            title="Toggle automated 30-second telemetry polling"
            className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-mono transition-colors ${
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
            onClick={onSync}
            disabled={refreshing}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
          >
            <RefreshCw className={`h-3 w-3 ${refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'}`} />
            <span>{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>
          <Link href="/upload-logs" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest Telemetry</span>
          </Link>
        </div>
      </div>

      {/* THREAT POSTURE BANNER */}
      <div
        className={`rounded-xl border bg-gradient-to-r ${posture.band} p-5 shadow-panel`}
      >
        <div className="flex flex-wrap items-center justify-between gap-5">
          <div className="flex items-center gap-3.5">
            <span className={`relative flex h-11 w-11 items-center justify-center rounded-lg bg-canvas/60 ring-2 ${posture.ring}`}>
              {posture.icon}
              <span className={`absolute -right-0.5 -top-0.5 h-3 w-3 rounded-full ${posture.dot} ring-2 ring-canvas animate-pulse-subtle`} />
            </span>
            <div>
              <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-ink-muted">Current Threat Posture</div>
              <div className={`mt-0.5 text-base font-bold tracking-tight ${posture.text}`}>{posture.label}</div>
            </div>
          </div>

          {/* Severity distribution segmented bar */}
          <div className="min-w-[280px] flex-1 max-w-md">
            <div className="mb-1.5 flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-ink-muted">
              <span>Severity Distribution</span>
              <span className="text-ink-secondary">{sevTotal} classified</span>
            </div>
            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-canvas ring-1 ring-border/60">
              {sevTotal === 0 ? (
                <div className="h-full w-full bg-border/40" />
              ) : (
                segments.map((seg) =>
                  seg.count > 0 ? (
                    <div
                      key={seg.key}
                      className={`h-full ${seg.color} transition-all`}
                      style={{ width: `${(seg.count / sevTotal) * 100}%` }}
                      title={`${seg.key}: ${seg.count}`}
                    />
                  ) : null
                )
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              {segments.map((seg) => (
                <Link
                  key={seg.key}
                  href={seg.href}
                  className="group flex items-center gap-1.5 text-[11px] font-mono transition-opacity hover:opacity-100 opacity-80"
                >
                  <span className={`h-2 w-2 rounded-full ${seg.color}`} />
                  <span className="text-ink-secondary group-hover:text-ink-primary">{seg.key}</span>
                  <span className={`font-semibold tabular-nums ${seg.text}`}>{seg.count}</span>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* METRIC TILES */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricTile
          href="/incidents"
          accent="bg-severity-medium"
          label="Active Triage"
          value={openInc}
          hint={`of ${totalInc} total incidents`}
        />
        <MetricTile
          href="/logs"
          accent="bg-accent-blue"
          label="Telemetry Processed"
          value={processed.toLocaleString()}
          hint={`${flagged.toLocaleString()} events flagged`}
        />
        <MetricTile
          accent="bg-accent-emerald"
          label="Anomaly Ratio"
          value={`${flagRate}%`}
          hint="flagged ÷ processed"
          valueClass="text-accent-emerald"
        />
        <MetricTile
          accent="bg-accent-purple"
          label="Flag Conversion"
          value={`${conversionRate}%`}
          hint="incidents ÷ flagged"
        />
      </div>

      {/* PRIORITY INCIDENTS */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-border/80 pb-2.5">
          <div className="flex items-center gap-2.5">
            <h2 className="text-sm font-semibold text-ink-primary">Priority Incidents Requiring Triage</h2>
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
          <div className="space-y-2">
            {s.recent_incidents.map((inc) => {
              const sev = (inc.severity || 'LOW').toUpperCase()
              const rail =
                sev === 'CRITICAL'
                  ? 'bg-severity-critical'
                  : sev === 'HIGH'
                  ? 'bg-severity-high'
                  : sev === 'MEDIUM'
                  ? 'bg-severity-medium'
                  : 'bg-severity-low'
              return (
                <div
                  key={inc.id}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') router.push(`/incidents/${inc.id}`)
                  }}
                  onClick={() => router.push(`/incidents/${inc.id}`)}
                  className="group relative flex cursor-pointer items-center gap-4 overflow-hidden rounded-lg border border-border/80 bg-panel/70 pl-4 pr-3 py-3 transition-colors hover:border-border-active hover:bg-elevated/50"
                >
                  <span className={`absolute left-0 top-0 h-full w-1 ${rail}`} />
                  <div className="w-24 shrink-0">
                    <SeverityBadge severity={inc.severity} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-semibold text-ink-primary group-hover:text-accent-emerald transition-colors">
                      {inc.title}
                    </span>
                    <span className="mt-0.5 block font-mono text-[10px] text-ink-muted">
                      INC-{inc.id.slice(0, 8)} · {inc.event_count} evidence events
                    </span>
                  </div>
                  <div className="hidden w-40 shrink-0 md:block">
                    <AttackTypeLabel attackType={inc.attack_type} />
                  </div>
                  <div className="hidden w-36 shrink-0 font-mono text-[11px] lg:block">
                    {inc.affected_username ? (
                      <span className="flex items-center gap-1.5 text-[#facc15]" title={`User: ${inc.affected_username}`}>
                        <User className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate">{inc.affected_username}</span>
                      </span>
                    ) : inc.source_ip ? (
                      <span className="flex items-center gap-1.5 text-accent-cyan" title={`IP: ${inc.source_ip}`}>
                        <Wifi className="h-3.5 w-3.5 shrink-0" />
                        <span>{inc.source_ip}</span>
                      </span>
                    ) : (
                      <span className="text-ink-muted">—</span>
                    )}
                  </div>
                  <div className="hidden w-28 shrink-0 xl:block">
                    <StatusBadge status={inc.status} />
                  </div>
                  <div className="hidden w-24 shrink-0 font-mono text-[11px] text-ink-muted xl:block">
                    <span title={format(new Date(inc.created_at), 'yyyy-MM-dd HH:mm:ss')}>
                      {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                    <Link href={`/incidents/${inc.id}`} className="btn-ghost text-[11px] py-1 px-2" title="Open investigation workspace">
                      <span>Triage</span>
                      <ArrowRight className="h-3 w-3" />
                    </Link>
                    <Link
                      href={`/incidents/${inc.id}/chat`}
                      className="btn-ghost text-[11px] py-1 px-2 border-accent-cyan/30 text-accent-cyan"
                      title="Consult AI Investigation Copilot"
                    >
                      <MessageSquare className="h-3 w-3" />
                      <span className="hidden sm:inline">Copilot</span>
                    </Link>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* TWO-COLUMN OBSERVABILITY */}
      <div className="grid gap-6 pt-2 lg:grid-cols-2">
        {/* Detection funnel */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <Layers className="h-3.5 w-3.5 text-accent-emerald" />
              <span>Ingestion &amp; Detection Funnel</span>
            </h3>
            <span className="font-mono text-[11px] text-ink-muted">{conversionRate}% Flag Conversion</span>
          </div>
          <div className="space-y-2.5 font-mono text-xs">
            <FunnelStage label="1. Raw Security Telemetry" value={`${processed.toLocaleString()} events`} valueClass="text-ink-primary" barClass="bg-accent-blue" width={100} />
            <FunnelStage label="2. Suspicious Anomaly Triggers" value={`${flagged.toLocaleString()} (${flagRate}%)`} valueClass="text-severity-critical" barClass="bg-severity-critical" width={Math.min(100, Math.max(3, Number(flagRate)))} />
            <FunnelStage label="3. Correlated Threat Incidents" value={`${totalInc} incidents (${conversionRate}%)`} valueClass="text-severity-medium" barClass="bg-severity-medium" width={Math.min(100, Math.max(2, totalInc * 6))} />
          </div>

          {sortedAttackTypes.length > 0 && (
            <div className="pt-2 space-y-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-ink-muted">Incidents by Attack Vector</div>
              {sortedAttackTypes.map(([type, count]) => (
                <div key={type} className="flex items-center gap-3">
                  <div className="w-40 shrink-0">
                    <AttackTypeLabel attackType={type} />
                  </div>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-canvas">
                    <div className="h-full bg-accent-purple/70" style={{ width: `${maxAttack ? (count / maxAttack) * 100 : 0}%` }} />
                  </div>
                  <span className="w-6 shrink-0 text-right font-mono text-[11px] text-ink-secondary tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Sensor health */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <Server className="h-3.5 w-3.5 text-accent-cyan" />
              <span>Sensors &amp; Daemon Health</span>
            </h3>
            <Link href="/integrations/wazuh" className="flex items-center gap-1 font-mono text-[11px] text-accent-cyan hover:underline">
              Configure <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between rounded-lg border border-border/80 bg-panel/50 p-3">
              <span className="text-ink-secondary">Wazuh SIEM Ingestion Link</span>
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${
                    wazuh?.status === 'ready' ? 'bg-accent-emerald' : wazuh ? 'bg-severity-critical' : 'bg-severity-medium'
                  }`}
                />
                <span className="capitalize text-ink-primary">{wazuh?.status || 'Standby'}</span>
              </div>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-border/80 bg-panel/50 p-3">
              <span className="text-ink-secondary">Deduplication LRU Cache</span>
              <span className="font-semibold text-ink-primary">{wazuh?.dedup_cache_size ?? 0} signatures</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-border/80 bg-panel/50 p-3">
              <span className="text-ink-secondary">Ingestion Poller Loop</span>
              <span
                className={`font-semibold ${
                  wazuh?.api_polling?.running ? 'text-accent-emerald' : wazuh?.api_polling?.enabled ? 'text-accent-cyan' : 'text-ink-muted'
                }`}
              >
                {wazuh?.api_polling?.running ? 'Actively Ingesting' : wazuh?.api_polling?.enabled ? 'Daemon Ready' : 'Idle'}
              </span>
            </div>
            {wazuh?.api_polling?.total_alerts_processed != null && (
              <div className="flex items-center justify-between rounded-lg border border-border/80 bg-panel/50 p-3">
                <span className="text-ink-secondary">Alerts Processed (lifetime)</span>
                <span className="font-semibold text-ink-primary">
                  {wazuh.api_polling.total_alerts_processed.toLocaleString()}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricTile({
  href,
  accent,
  label,
  value,
  hint,
  valueClass = 'text-ink-primary',
}: {
  href?: string
  accent: string
  label: string
  value: React.ReactNode
  hint: string
  valueClass?: string
}) {
  const inner = (
    <div className="group relative h-full overflow-hidden rounded-lg border border-border/80 bg-panel/70 p-4 transition-colors hover:border-border-active hover:bg-elevated/50">
      <span className={`absolute left-0 top-0 h-full w-1 ${accent}`} />
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-ink-muted group-hover:text-ink-secondary">
          {label}
        </span>
        {href && <ArrowUpRight className="h-3.5 w-3.5 text-ink-muted opacity-0 transition-opacity group-hover:opacity-100" />}
      </div>
      <div className={`mt-2 font-mono text-3xl font-bold tabular-nums ${valueClass}`}>{value}</div>
      <div className="mt-1 text-[11px] text-ink-muted">{hint}</div>
    </div>
  )
  if (href) {
    return (
      <Link href={href} className="block">
        {inner}
      </Link>
    )
  }
  return inner
}

function FunnelStage({
  label,
  value,
  valueClass,
  barClass,
  width,
}: {
  label: string
  value: string
  valueClass: string
  barClass: string
  width: number
}) {
  return (
    <div className="space-y-1.5 rounded-lg border border-border/80 bg-panel/50 p-3">
      <div className="flex justify-between text-ink-secondary">
        <span>{label}</span>
        <span className={`font-semibold ${valueClass}`}>{value}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-canvas">
        <div className={`h-full ${barClass}`} style={{ width: `${width}%` }} />
      </div>
    </div>
  )
}
