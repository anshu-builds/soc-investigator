'use client'

import React, { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  Lock,
  Radio,
  RefreshCw,
  Shield,
  Zap,
} from 'lucide-react'
import { format } from 'date-fns'

import { getCurrentUser, getWazuhStatus, triggerWazuhPoll } from '@/lib/api'
import type { UserSession, WazuhPollResponse, WazuhStatusResponse } from '@/lib/types'
import { SkeletonCard, SkeletonTable } from '@/components/ui/Skeleton'

export default function WazuhTelemetryPage() {
  const [status, setStatus] = useState<WazuhStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [polling, setPolling] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pollResult, setPollResult] = useState<WazuhPollResponse | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const [user, setUser] = useState<UserSession | null>(null)

  const loadStatus = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getWazuhStatus()
      setStatus(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to retrieve Wazuh status')
    } finally {
      setLoading(false)
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
      await loadStatus()
    } catch (e) {
      setPollError(e instanceof Error ? e.message : 'Wazuh poll execution failed')
    } finally {
      setPolling(false)
    }
  }

  const isAdmin = user?.role === 'admin'

  if (loading && !status) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-48 bg-[#1e293b] rounded animate-pulse" />
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
      <div className="card max-w-md mx-auto p-6 text-center border-[#7f1d1d] bg-[#11161d] mt-12">
        <AlertTriangle className="mx-auto h-8 w-8 text-[#ef4444]" />
        <h2 className="mt-2 text-base font-semibold text-[#f3f4f6]">Wazuh Integration Offline</h2>
        <p className="mt-1 text-xs text-[#9ca3af]">{error}</p>
        <button onClick={loadStatus} className="btn-primary mt-4 text-xs">
          <RefreshCw className="mr-1 h-3 w-3" /> Retry Connection
        </button>
      </div>
    )
  }

  const p = status?.api_polling

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
              Wazuh Telemetry & Integrations
            </h1>
            <span
              className={`flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                status?.status === 'ready'
                  ? 'border-[#10b981]/30 bg-[#10b981]/10 text-[#34d399]'
                  : 'border-[#7f1d1d] bg-[#450a0a] text-[#f87171]'
              }`}
            >
              <Radio className={`h-2.5 w-2.5 ${status?.status === 'ready' ? 'animate-pulse text-[#10b981]' : 'text-[#ef4444]'}`} />
              {status?.status === 'ready' ? 'Operational' : 'Attention Required'}
            </span>
          </div>
          <p className="mt-1 text-xs text-[#9ca3af]">
            Live Wazuh HIDS/SIEM webhook listener and REST API polling engine status
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={loadStatus}
            disabled={loading}
            className="btn-ghost text-xs py-1.5 px-3"
          >
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loading ? 'animate-spin text-[#10b981]' : 'text-[#9ca3af]'}`} />
            Refresh Status
          </button>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 font-mono">
        <div className="card p-4 border-[#1f2937] bg-[#11161d]">
          <span className="text-[10px] uppercase text-[#6b7280] tracking-wider block">
            Webhook Authentication
          </span>
          <span className="mt-1.5 text-base font-semibold text-[#f3f4f6] block">
            {status?.authentication || 'Unknown'}
          </span>
          <span className="text-[11px] text-[#9ca3af] mt-1 block">
            Fail-closed signature validation
          </span>
        </div>

        <div className="card p-4 border-[#1f2937] bg-[#11161d]">
          <span className="text-[10px] uppercase text-[#6b7280] tracking-wider block">
            Dedup Cache Entries
          </span>
          <span className="mt-1.5 text-base font-semibold text-[#38bdf8] block">
            {status?.dedup_cache_size?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-[#9ca3af] mt-1 block">
            In-memory LRU tracking
          </span>
        </div>

        <div className="card p-4 border-[#1f2937] bg-[#11161d]">
          <span className="text-[10px] uppercase text-[#6b7280] tracking-wider block">
            Alerts Fetched
          </span>
          <span className="mt-1.5 text-base font-semibold text-[#10b981] block">
            {p?.total_alerts_fetched?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-[#9ca3af] mt-1 block">
            {p?.total_alerts_processed ?? 0} ingested to database
          </span>
        </div>

        <div className="card p-4 border-[#1f2937] bg-[#11161d]">
          <span className="text-[10px] uppercase text-[#6b7280] tracking-wider block">
            Duplicate Rejections
          </span>
          <span className="mt-1.5 text-base font-semibold text-[#facc15] block">
            {p?.total_duplicates?.toLocaleString() ?? 0}
          </span>
          <span className="text-[11px] text-[#9ca3af] mt-1 block">
            {p?.consecutive_errors ?? 0} consecutive errors
          </span>
        </div>
      </div>

      {/* Manual Poll Trigger Control Panel */}
      <div className="card p-5 border-[#1f2937] bg-[#11161d] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-3">
          <div>
            <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
              <Zap className="h-4 w-4 text-[#10b981]" />
              On-Demand Polling Execution
            </h2>
            <p className="mt-0.5 text-xs text-[#9ca3af]">
              Triggers an instantaneous incremental sync from the Wazuh manager API using the current watermark
            </p>
          </div>

          <div>
            {isAdmin ? (
              <button
                type="button"
                onClick={handleManualPoll}
                disabled={polling}
                className="btn-primary text-xs py-2 px-4 disabled:opacity-50"
              >
                {polling ? (
                  <>
                    <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    Polling Wazuh API…
                  </>
                ) : (
                  <>
                    <Zap className="mr-1.5 h-3.5 w-3.5" />
                    Poll Now (Admin)
                  </>
                )}
              </button>
            ) : (
              <div className="flex items-center gap-2 rounded border border-[#1f2937] bg-[#171e28] px-3 py-1.5 text-xs font-mono text-[#9ca3af]">
                <Lock className="h-3.5 w-3.5 text-[#ef4444]" />
                <span>Admin Authorization Required to Poll</span>
              </div>
            )}
          </div>
        </div>

        {pollError && (
          <div className="flex gap-3 rounded-lg border border-[#7f1d1d] bg-[#450a0a]/50 p-3.5 text-xs text-[#fca5a5]">
            <AlertCircle className="h-4 w-4 shrink-0 text-[#ef4444]" />
            <span>{pollError}</span>
          </div>
        )}

        {pollResult && (
          <div className="rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 p-4 space-y-2 text-xs font-mono">
            <div className="flex items-center gap-2 text-[#34d399] font-semibold">
              <CheckCircle2 className="h-4 w-4" />
              <span>Poll Cycle Completed Successfully</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-[#d1d5db]">
              <div>Fetched: <strong className="text-[#f3f4f6]">{pollResult.fetched}</strong></div>
              <div>Processed: <strong className="text-[#10b981]">{pollResult.processed}</strong></div>
              <div>Duplicates: <strong className="text-[#facc15]">{pollResult.duplicates}</strong></div>
              <div>Status: <strong className="text-[#38bdf8]">{pollResult.status}</strong></div>
            </div>
          </div>
        )}

        {p?.last_error && (
          <div className="rounded-lg border border-[#7f1d1d] bg-[#450a0a]/40 p-3.5 text-xs text-[#fca5a5]">
            <span className="font-mono text-[10px] uppercase font-semibold text-[#ef4444] block mb-1">
              Last Observed Poller Exception
            </span>
            <pre className="font-mono text-xs whitespace-pre-wrap">{p.last_error}</pre>
          </div>
        )}
      </div>

      {/* Engine Configuration & State Details */}
      <div className="card p-5 border-[#1f2937] bg-[#11161d] space-y-4">
        <h3 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2 border-b border-[#1f2937] pb-3">
          <Cpu className="h-4 w-4 text-[#10b981]" />
          Poller Engine Parameters & Watermark State
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">Target Endpoint</span>
            <span className="text-[#38bdf8] block mt-1 truncate" title={p?.api_url || 'Unset'}>
              {p?.api_url || 'Unconfigured'}
            </span>
          </div>

          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">SSL Verification</span>
            <span className="text-[#f3f4f6] block mt-1">
              {p?.verify_ssl ? 'Strict (TLS Verified)' : 'Disabled (Insecure)'}
            </span>
          </div>

          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">Active Watermark</span>
            <span className="text-[#facc15] block mt-1 truncate" title={p?.watermark || 'None'}>
              {p?.watermark || 'No watermark recorded'}
            </span>
          </div>

          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">Last Attempted Poll</span>
            <span className="text-[#9ca3af] block mt-1">
              {p?.last_attempted_poll
                ? format(new Date(p.last_attempted_poll), 'yyyy-MM-dd HH:mm:ss') + ' UTC'
                : 'Never'}
            </span>
          </div>

          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">Last Successful Poll</span>
            <span className="text-[#10b981] block mt-1">
              {p?.last_successful_poll
                ? format(new Date(p.last_successful_poll), 'yyyy-MM-dd HH:mm:ss') + ' UTC'
                : 'Never'}
            </span>
          </div>

          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
            <span className="text-[#6b7280] text-[10px] uppercase block">Poller Loop Status</span>
            <span className="text-[#f3f4f6] block mt-1">
              {p?.running ? 'Running in Background' : 'Idle / On-Demand'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
