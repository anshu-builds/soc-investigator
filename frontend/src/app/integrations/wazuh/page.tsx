'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Database,
  ExternalLink,
  HardDrive,
  Layers,
  Lock,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wifi,
  Zap,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'

import { getCurrentUser, getWazuhStatus, triggerWazuhPoll } from '@/lib/api'
import type { UserSession, WazuhPollResponse, WazuhStatusResponse } from '@/lib/types'
import { useToast } from '@/components/ui/Toast'
import { SkeletonCard } from '@/components/ui/Skeleton'

export default function WazuhIntegrationPage() {
  const { success, error: toastError } = useToast()

  const [user, setUser] = useState<UserSession | null>(null)
  const [status, setStatus] = useState<WazuhStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Polling mutation state
  const [polling, setPolling] = useState(false)
  const [pollResult, setPollResult] = useState<WazuhPollResponse | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)

  const loadStatus = useCallback(
    async (isSilent = false) => {
      if (!isSilent) setLoading(true)
      else setRefreshing(true)
      setError(null)

      try {
        const res = await getWazuhStatus()
        setStatus(res)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Unable to connect to Wazuh telemetry service')
      } finally {
        setLoading(false)
        setRefreshing(false)
      }
    },
    []
  )

  useEffect(() => {
    setUser(getCurrentUser())
    loadStatus()
  }, [loadStatus])

  const handleManualPoll = async () => {
    if (polling) return
    setPolling(true)
    setPollError(null)
    setPollResult(null)

    try {
      const res = await triggerWazuhPoll()
      setPollResult(res)
      success(
        'Wazuh Polling Complete',
        `Fetched ${res.fetched} alerts, processed ${res.processed} into database (${res.duplicates} duplicates)`
      )
      loadStatus(true)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Wazuh poll execution failed'
      setPollError(msg)
      toastError('Polling Failed', msg)
    } finally {
      setPolling(false)
    }
  }

  const isAdmin = user?.role === 'admin'
  const p = status?.api_polling

  const hasErrors = (p?.consecutive_errors ?? 0) > 0
  const isReady = status?.status === 'ready'
  const healthLabel = hasErrors
    ? `Degraded (${p?.consecutive_errors} Errors)`
    : isReady
    ? 'Operational'
    : 'Attention Required'

  if (loading && !status) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-48 bg-elevated rounded animate-pulse" />
        <div className="h-24 bg-elevated/40 rounded border border-border/60 animate-pulse" />
        <div className="h-48 bg-elevated/40 rounded border border-border/60 animate-pulse" />
      </div>
    )
  }

  if (error && !status) {
    return (
      <div className="max-w-md mx-auto p-8 text-center border border-severity-critical/30 rounded-lg bg-panel mt-12 space-y-4">
        <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
        <div className="space-y-1">
          <h2 className="text-base font-bold text-ink-primary">Wazuh Integration Offline</h2>
          <p className="text-xs text-ink-secondary leading-relaxed">{error}</p>
        </div>
        <button
          type="button"
          onClick={() => loadStatus()}
          className="btn-primary text-xs py-1.5 px-4 inline-flex items-center gap-1.5"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Retry Connection</span>
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* 1. HEADER & HEALTH POSTURE */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              Wazuh Telemetry Console
            </h1>
            <div className="flex items-center gap-1.5 text-xs font-mono">
              <span
                className={`h-2 w-2 rounded-full ${
                  isReady && !hasErrors ? 'bg-accent-emerald' : 'bg-severity-critical'
                }`}
              />
              <span
                className={`font-semibold ${
                  isReady && !hasErrors ? 'text-accent-emerald' : 'text-severity-critical'
                }`}
              >
                {healthLabel}
              </span>
            </div>
          </div>
          <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
            HIDS sensor telemetry ingestion, deduplication cache, and REST API polling daemon state
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => loadStatus(true)}
            disabled={loading || refreshing}
            className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5"
            title="Refresh integration status"
          >
            <RefreshCw
              className={`h-3 w-3 ${
                loading || refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'
              }`}
            />
            <span>{refreshing ? 'Syncing…' : 'Sync'}</span>
          </button>
        </div>
      </div>

      {/* 2. UNIFIED 4-METRIC TELEMETRY OPERATIONS STRIP */}
      <div className="rounded-lg border border-border/80 bg-panel/70 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border/60 text-xs font-mono">
        <div className="p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block font-sans">
            Webhook Authentication
          </span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {status?.authentication === 'configured' ? (
              <ShieldCheck className="h-4 w-4 text-accent-emerald shrink-0" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-ink-muted shrink-0" />
            )}
            <span className="text-sm font-bold text-ink-primary truncate">
              {status?.authentication === 'configured' ? 'HMAC Validated' : 'Unconfigured'}
            </span>
          </div>
          <span className="text-[11px] text-ink-secondary block">
            Fail-closed validation
          </span>
        </div>

        <div className="p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block font-sans">
            Dedup LRU Cache
          </span>
          <div className="text-xl font-bold text-ink-primary pt-0.5">
            {status?.dedup_cache_size ?? 0}
          </div>
          <span className="text-[11px] text-ink-secondary block">
            Cached alert signatures
          </span>
        </div>

        <div className="p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block font-sans">
            Alerts Processed
          </span>
          <div className="text-xl font-bold text-accent-emerald pt-0.5">
            {(p?.total_alerts_processed ?? 0).toLocaleString()}
          </div>
          <span className="text-[11px] text-ink-secondary block">
            of {(p?.total_alerts_fetched ?? 0).toLocaleString()} fetched
          </span>
        </div>

        <div className="p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block font-sans">
            Redundancy / Errors
          </span>
          <div className="text-xl font-bold text-ink-primary pt-0.5">
            {p?.total_duplicates ?? 0}
          </div>
          <span className="text-[11px] text-ink-secondary block">
            {p?.consecutive_errors ?? 0} consecutive errors
          </span>
        </div>
      </div>

      {/* 3. PIPELINE ARCHITECTURE FLOW */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-border/80 pb-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5 text-accent-emerald" />
            <span>Telemetry Pipeline Flow & Processing Stages</span>
          </h2>
          <span className="font-mono text-[10px] text-accent-emerald font-semibold">
            Active Runtime Topology
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5 font-mono text-xs">
          <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">1. Origin</span>
            <span className="text-ink-primary font-bold block">Wazuh Manager</span>
            <span className="text-[11px] text-ink-secondary block font-sans">HIDS & Agents</span>
          </div>

          <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">2. Ingest</span>
            <span className="text-accent-cyan font-bold block">API / Webhook</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              {p?.configured ? 'Poller Loop' : 'Webhook Listener'}
            </span>
          </div>

          <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">3. Deduplicate</span>
            <span className="text-[#facc15] font-bold block">LRU Cache</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              {status?.dedup_cache_size ?? 0} keys cached
            </span>
          </div>

          <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">4. Persist</span>
            <span className="text-ink-primary font-bold block">Event Store</span>
            <span className="text-[11px] text-ink-secondary block font-sans">PostgreSQL DB</span>
          </div>

          <div className="p-3 rounded border border-border/80 bg-panel/50 space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">5. Correlate</span>
            <span className="text-severity-critical font-bold block">Detection</span>
            <span className="text-[11px] text-ink-secondary block font-sans">Incident Engine</span>
          </div>
        </div>
      </div>

      {/* 4. ON-DEMAND POLLING EXECUTION & ENGINE AUDIT */}
      <div className="grid gap-6 lg:grid-cols-2 pt-2">
        {/* Left: Manual Polling Action Panel */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-accent-emerald" />
              <span>On-Demand Incremental Sync</span>
            </h3>
            <span className="font-mono text-[10px] text-ink-muted">
              {isAdmin ? 'Admin Authorized' : 'Read-Only Role'}
            </span>
          </div>

          <div className="p-4 rounded border border-border/80 bg-panel/60 space-y-3">
            <p className="text-xs text-ink-secondary leading-relaxed">
              Trigger an instantaneous sync cycle from the Wazuh Manager API using the active watermark offset.
            </p>

            {isAdmin ? (
              <button
                type="button"
                onClick={handleManualPoll}
                disabled={polling}
                className="btn-primary text-xs py-1.5 px-4 disabled:opacity-50 flex items-center gap-2"
              >
                {polling ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Polling Wazuh API…</span>
                  </>
                ) : (
                  <>
                    <Zap className="h-3.5 w-3.5" />
                    <span>Poll Wazuh Now (Admin)</span>
                  </>
                )}
              </button>
            ) : (
              <div className="flex items-center gap-2 rounded border border-border bg-elevated px-3 py-2 text-xs font-mono text-ink-muted">
                <Lock className="h-3.5 w-3.5 text-severity-critical" />
                <span>Admin Authorization Required to Trigger Polling</span>
              </div>
            )}

            {pollError && (
              <div className="flex items-center gap-2 rounded border border-severity-critical/30 bg-severity-critical/10 p-3 text-xs text-severity-critical animate-fade-in">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{pollError}</span>
              </div>
            )}

            {pollResult && (
              <div className="rounded border border-accent-emerald/30 bg-accent-emerald/10 p-3 text-xs font-mono space-y-1.5 animate-fade-in">
                <div className="flex items-center gap-1.5 text-accent-emerald font-bold">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Sync Complete</span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-[11px] text-ink-primary pt-1">
                  <div>Fetched: <strong className="font-bold">{pollResult.fetched}</strong></div>
                  <div>Processed: <strong className="font-bold text-accent-emerald">{pollResult.processed}</strong></div>
                  <div>Duplicates: <strong className="font-bold">{pollResult.duplicates}</strong></div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Engine Parameters Audit Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Server className="h-3.5 w-3.5 text-accent-cyan" />
              <span>Engine Parameters & Watermark</span>
            </h3>
            <span className="font-mono text-[10px] text-ink-muted">Read-Only</span>
          </div>

          <div className="rounded border border-border/80 bg-panel/60 divide-y divide-border-subtle/80 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5">
              <span className="text-ink-secondary">Target Manager URL</span>
              <span className="text-ink-primary font-semibold truncate max-w-[200px]">
                {p?.api_url || 'https://wazuh.manager:55000'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5">
              <span className="text-ink-secondary">TLS Certificate Verification</span>
              <span className="text-ink-primary">{p?.verify_ssl ? 'Strict SSL Enabled' : 'Disabled'}</span>
            </div>

            <div className="flex items-center justify-between p-2.5">
              <span className="text-ink-secondary">Active Telemetry Watermark</span>
              <span className="text-accent-cyan font-bold truncate max-w-[200px]">
                {p?.watermark || '0'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5">
              <span className="text-ink-secondary">Polling Daemon Loop</span>
              <span className="text-ink-primary font-semibold">
                {p?.running ? 'Actively Polling' : p?.enabled ? 'Standby (Interval Active)' : 'Disabled'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5">
              <span className="text-ink-secondary">Last Attempted Sync</span>
              <span className="text-ink-muted">
                {p?.last_attempted_poll
                  ? format(new Date(p.last_attempted_poll), 'HH:mm:ss') + ' UTC'
                  : '—'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
