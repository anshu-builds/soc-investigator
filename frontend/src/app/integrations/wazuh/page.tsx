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
  Cpu,
  Database,
  ExternalLink,
  GitCommit,
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
import { format } from 'date-fns'

import { getCurrentUser, getWazuhStatus, triggerWazuhPoll } from '@/lib/api'
import type { UserSession, WazuhPollResponse, WazuhStatusResponse } from '@/lib/types'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'

export default function WazuhTelemetryPage() {
  const { success, error: toastError } = useToast()

  const [status, setStatus] = useState<WazuhStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [polling, setPolling] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pollResult, setPollResult] = useState<WazuhPollResponse | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const [user, setUser] = useState<UserSession | null>(null)

  const loadStatus = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true)
    else setRefreshing(true)
    setError(null)

    try {
      const res = await getWazuhStatus()
      setStatus(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to retrieve Wazuh integration status')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    setUser(getCurrentUser())
    loadStatus()
  }, [loadStatus])

  const handleManualPoll = async () => {
    setPolling(true)
    setPollError(null)
    setPollResult(null)

    try {
      const res = await triggerWazuhPoll()
      setPollResult(res)
      success('Wazuh Poll Succeeded', `Processed ${res.processed} alerts, ${res.duplicates} duplicates`)
      await loadStatus(true)
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

  // Health assessment
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
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      </div>
    )
  }

  if (error && !status) {
    return (
      <div className="card max-w-md mx-auto p-8 text-center border-severity-critical/40 bg-panel mt-12 space-y-4">
        <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
        <div className="space-y-1">
          <h2 className="text-base font-bold text-ink-primary">Wazuh Integration Offline</h2>
          <p className="text-xs text-ink-secondary leading-relaxed">{error}</p>
        </div>
        <button
          type="button"
          onClick={() => loadStatus()}
          className="btn-primary text-xs py-2 px-4 inline-flex items-center gap-1.5"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Retry Connection</span>
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              Wazuh Telemetry & Integrations
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                hasErrors
                  ? 'border-[#f59e0b]/40 bg-[#f59e0b]/10 text-[#facc15]'
                  : isReady
                  ? 'border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald'
                  : 'border-severity-critical/40 bg-severity-critical/10 text-severity-critical'
              }`}
            >
              <Radio
                className={`h-2.5 w-2.5 ${
                  isReady && !hasErrors ? 'animate-pulse text-accent-emerald' : 'text-severity-critical'
                }`}
              />
              <span>{healthLabel}</span>
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
            Live Wazuh HIDS/SIEM webhook listener and REST API polling engine status.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => loadStatus(true)}
            disabled={loading || refreshing}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Refresh status from backend"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                loading || refreshing ? 'animate-spin text-accent-emerald' : 'text-ink-muted'
              }`}
            />
            <span>{refreshing ? 'Syncing…' : 'Refresh Status'}</span>
          </button>
        </div>
      </div>

      {/* Primary Health & Ingestion KPI Strip */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 font-mono text-xs">
        {/* Webhook Auth Card */}
        <div className="card p-4 border-border bg-panel space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block">
            Webhook Authentication
          </span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {status?.authentication === 'configured' ? (
              <ShieldCheck className="h-4 w-4 text-accent-emerald shrink-0" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-ink-muted shrink-0" />
            )}
            <span className="text-sm font-bold text-ink-primary truncate">
              {status?.authentication === 'configured' ? 'Configured (HMAC)' : 'Unconfigured'}
            </span>
          </div>
          <span className="text-[11px] text-ink-secondary block pt-1">
            Fail-closed signature validation
          </span>
        </div>

        {/* Dedup Cache Card */}
        <div className="card p-4 border-border bg-panel space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block">
            Dedup Cache Entries
          </span>
          <span className="text-base font-bold text-accent-cyan block pt-0.5">
            {status?.dedup_cache_size?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-ink-secondary block pt-1">
            In-memory LRU tracking
          </span>
        </div>

        {/* Alerts Ingested Card */}
        <div className="card p-4 border-border bg-panel space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block">
            Alerts Processed
          </span>
          <span className="text-base font-bold text-accent-emerald block pt-0.5">
            {p?.total_alerts_processed?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-ink-secondary block pt-1">
            {p?.total_alerts_fetched ?? 0} fetched from manager
          </span>
        </div>

        {/* Dedup Rejections Card */}
        <div className="card p-4 border-border bg-panel space-y-1">
          <span className="text-[10px] uppercase text-ink-muted tracking-wider block">
            Duplicate Rejections
          </span>
          <span className="text-base font-bold text-[#facc15] block pt-0.5">
            {p?.total_duplicates?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-ink-secondary block pt-1">
            {p?.consecutive_errors ?? 0} consecutive errors
          </span>
        </div>
      </div>

      {/* Telemetry Ingestion Pipeline Visual Flow */}
      <div className="card p-5 border-border bg-panel space-y-4">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="space-y-0.5">
            <h2 className="text-sm font-bold text-ink-primary flex items-center gap-2">
              <Layers className="h-4 w-4 text-accent-emerald" />
              Wazuh Telemetry Ingestion Pipeline
            </h2>
            <p className="text-xs text-ink-secondary">
              Verified end-to-end telemetry architecture from Wazuh Manager to correlation
            </p>
          </div>
          <span className="font-mono text-[10px] uppercase text-ink-muted font-bold">
            Authoritative Pipeline Flow
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 font-mono text-xs">
          {/* Stage 1: Manager */}
          <div className="rounded-xl border border-border bg-elevated/40 p-3.5 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-ink-muted font-bold">Source</span>
              <Server className="h-3.5 w-3.5 text-accent-cyan" />
            </div>
            <span className="font-bold text-ink-primary block">Wazuh Manager</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              HIDS & Syslog Events
            </span>
          </div>

          {/* Stage 2: Ingestion Vector */}
          <div className="rounded-xl border border-border bg-elevated/40 p-3.5 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-ink-muted font-bold">Ingestion</span>
              <Wifi className="h-3.5 w-3.5 text-accent-emerald" />
            </div>
            <span className="font-bold text-ink-primary block">REST API / Webhook</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              {p?.configured ? 'Poller Configured' : 'Webhook Listener'}
            </span>
          </div>

          {/* Stage 3: Deduplication */}
          <div className="rounded-xl border border-border bg-elevated/40 p-3.5 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-ink-muted font-bold">Deduplication</span>
              <HardDrive className="h-3.5 w-3.5 text-[#facc15]" />
            </div>
            <span className="font-bold text-ink-primary block">Dedup Cache</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              {status?.dedup_cache_size ?? 0} active entries
            </span>
          </div>

          {/* Stage 4: Storage */}
          <div className="rounded-xl border border-border bg-elevated/40 p-3.5 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-ink-muted font-bold">Persistence</span>
              <Database className="h-3.5 w-3.5 text-accent-emerald" />
            </div>
            <span className="font-bold text-ink-primary block">Security Events</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              PostgreSQL Relational DB
            </span>
          </div>

          {/* Stage 5: Correlation */}
          <div className="rounded-xl border border-border bg-elevated/40 p-3.5 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-ink-muted font-bold">Intelligence</span>
              <ShieldAlert className="h-3.5 w-3.5 text-severity-critical" />
            </div>
            <span className="font-bold text-ink-primary block">Detection Engine</span>
            <span className="text-[11px] text-ink-secondary block font-sans">
              Attack Hypothesis Synthesis
            </span>
          </div>
        </div>
      </div>

      {/* Manual Poll Trigger Control Panel */}
      <div className="card p-5 sm:p-6 border-border bg-panel space-y-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
          <div>
            <h2 className="text-sm font-bold text-ink-primary flex items-center gap-2">
              <Zap className="h-4 w-4 text-accent-emerald" />
              On-Demand Polling Execution
            </h2>
            <p className="mt-0.5 text-xs text-ink-secondary">
              Trigger an instantaneous incremental sync from the Wazuh manager API using the current watermark
            </p>
          </div>

          <div>
            {isAdmin ? (
              <button
                type="button"
                onClick={handleManualPoll}
                disabled={polling}
                className="btn-primary text-xs py-2 px-4 disabled:opacity-50 flex items-center gap-2"
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
              <div className="flex items-center gap-2 rounded-lg border border-border bg-elevated px-3 py-2 text-xs font-mono text-ink-muted">
                <Lock className="h-3.5 w-3.5 text-severity-critical" />
                <span>Admin Authorization Required to Trigger Polling</span>
              </div>
            )}
          </div>
        </div>

        {pollError && (
          <div className="flex items-center gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4 text-xs text-severity-critical animate-fade-in">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{pollError}</span>
          </div>
        )}

        {pollResult && (
          <div className="rounded-xl border border-accent-emerald/30 bg-accent-emerald/10 p-4 space-y-2 text-xs font-mono animate-fade-in">
            <div className="flex items-center gap-2 text-accent-emerald font-bold">
              <CheckCircle2 className="h-4 w-4" />
              <span>Poll Cycle Completed Successfully</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-ink-primary">
              <div>
                Fetched: <strong className="text-ink-primary">{pollResult.fetched}</strong>
              </div>
              <div>
                Processed: <strong className="text-accent-emerald">{pollResult.processed}</strong>
              </div>
              <div>
                Duplicates: <strong className="text-[#facc15]">{pollResult.duplicates}</strong>
              </div>
              <div>
                Status: <strong className="text-accent-cyan">{pollResult.status}</strong>
              </div>
            </div>
          </div>
        )}

        {p?.last_error && (
          <div className="rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4 text-xs text-severity-critical space-y-1">
            <span className="font-mono text-[10px] uppercase font-bold tracking-wider block">
              Last Observed Poller Exception
            </span>
            <pre className="font-mono text-xs whitespace-pre-wrap">{p.last_error}</pre>
          </div>
        )}
      </div>

      {/* Engine Configuration & State Details */}
      <div className="card p-5 sm:p-6 border-border bg-panel space-y-4 shadow-sm">
        <h3 className="text-sm font-bold text-ink-primary flex items-center gap-2 border-b border-border-subtle pb-3">
          <Cpu className="h-4 w-4 text-accent-emerald" />
          Poller Engine Parameters & Watermark State
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 font-mono text-xs">
          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">Target Endpoint</span>
            <span className="text-accent-cyan block mt-1 truncate" title={p?.api_url || 'Unset'}>
              {p?.api_url || 'Unconfigured'}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">SSL Verification</span>
            <span className="text-ink-primary block mt-1">
              {p?.verify_ssl ? 'Strict (TLS Verified)' : 'Disabled (Insecure)'}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">Active Watermark</span>
            <span className="text-[#facc15] block mt-1 truncate" title={p?.watermark || 'None'}>
              {p?.watermark || 'No watermark recorded'}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">Last Attempted Poll</span>
            <span className="text-ink-secondary block mt-1">
              {p?.last_attempted_poll
                ? format(new Date(p.last_attempted_poll), 'yyyy-MM-dd HH:mm:ss') + ' UTC'
                : 'Never'}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">Last Successful Poll</span>
            <span className="text-accent-emerald block mt-1">
              {p?.last_successful_poll
                ? format(new Date(p.last_successful_poll), 'yyyy-MM-dd HH:mm:ss') + ' UTC'
                : 'Never'}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-3.5">
            <span className="text-ink-muted text-[10px] uppercase block">Poller Loop Status</span>
            <span className="text-ink-primary block mt-1">
              {p?.running ? 'Running in Background' : 'Idle / On-Demand'}
            </span>
          </div>
        </div>

        {/* Investigation Navigation Pivots */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle pt-4 text-xs">
          <span className="text-ink-muted font-mono text-[11px]">
            Ingested Wazuh telemetry feeds directly into SIEM Event Explorer and Anomaly Detection
          </span>
          <div className="flex items-center gap-2">
            <Link href="/logs" className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5" />
              <span>Explore Ingested Logs</span>
            </Link>
            <Link href="/incidents" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              <span>Incident Queue</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
