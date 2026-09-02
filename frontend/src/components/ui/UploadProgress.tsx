'use client'

import React from 'react'
import { AlertCircle, CheckCircle2, FileText, Loader2, Upload } from 'lucide-react'

export type UploadState = 'idle' | 'validating' | 'uploading' | 'processing' | 'completed' | 'failed'

interface UploadProgressProps {
  state: UploadState
  fileName?: string
  fileSize?: number
  errorMessage?: string
  metrics?: {
    eventsParsed?: number
    eventsFlagged?: number
    incidentsCreated?: number
  }
  className?: string
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function UploadProgress({
  state,
  fileName,
  fileSize,
  errorMessage,
  metrics,
  className = '',
}: UploadProgressProps) {
  if (state === 'idle') return null

  const isBusy = state === 'validating' || state === 'uploading' || state === 'processing'

  return (
    <div
      role="status"
      className={`rounded-xl border border-border bg-elevated p-4 animate-scale-in space-y-3 ${className}`}
    >
      {/* File info bar */}
      <div className="flex items-center justify-between gap-3 border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-panel text-ink-secondary shrink-0">
            <FileText className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <p className="text-xs font-semibold text-ink-primary truncate">{fileName || 'Telemetry File'}</p>
            {fileSize !== undefined && (
              <p className="text-[10px] font-mono text-ink-muted">{formatBytes(fileSize)}</p>
            )}
          </div>
        </div>

        {/* State Pill */}
        <div className="shrink-0">
          {state === 'validating' && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-severity-medium/30 bg-severity-medium/10 px-2.5 py-0.5 text-[11px] font-mono text-severity-medium">
              <Loader2 className="h-3 w-3 animate-spin" /> Validating
            </span>
          )}
          {state === 'uploading' && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-accent-blue/30 bg-accent-blue/10 px-2.5 py-0.5 text-[11px] font-mono text-accent-blue">
              <Upload className="h-3 w-3 animate-pulse" /> Uploading
            </span>
          )}
          {state === 'processing' && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-accent-emerald/30 bg-accent-emerald/10 px-2.5 py-0.5 text-[11px] font-mono text-accent-emerald">
              <Loader2 className="h-3 w-3 animate-spin" /> Normalizing & Ingesting
            </span>
          )}
          {state === 'completed' && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[#064e3b] bg-[#022c22] px-2.5 py-0.5 text-[11px] font-mono text-[#34d399]">
              <CheckCircle2 className="h-3 w-3" /> Ingestion Complete
            </span>
          )}
          {state === 'failed' && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-severity-critical/30 bg-severity-critical/10 px-2.5 py-0.5 text-[11px] font-mono text-severity-critical">
              <AlertCircle className="h-3 w-3" /> Failed
            </span>
          )}
        </div>
      </div>

      {/* Progress Bar or Result Grid */}
      {isBusy && (
        <div className="space-y-1.5">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-panel">
            <div className="h-full bg-accent-emerald rounded-full animate-pulse" style={{ width: state === 'validating' ? '30%' : state === 'uploading' ? '65%' : '90%' }} />
          </div>
          <p className="text-[10px] font-mono text-ink-muted text-right">
            {state === 'validating' ? 'Checking structure...' : state === 'uploading' ? 'Streaming bytes...' : 'Running correlation rules...'}
          </p>
        </div>
      )}

      {state === 'completed' && metrics && (
        <div className="grid grid-cols-3 gap-2 pt-1 text-center font-mono">
          <div className="rounded-lg border border-border-subtle bg-panel p-2">
            <span className="text-[10px] text-ink-muted block uppercase">Parsed</span>
            <span className="text-xs font-bold text-ink-primary mt-0.5 block">{metrics.eventsParsed ?? 0}</span>
          </div>
          <div className="rounded-lg border border-border-subtle bg-panel p-2">
            <span className="text-[10px] text-ink-muted block uppercase">Flagged</span>
            <span className="text-xs font-bold text-severity-high mt-0.5 block">{metrics.eventsFlagged ?? 0}</span>
          </div>
          <div className="rounded-lg border border-border-subtle bg-panel p-2">
            <span className="text-[10px] text-ink-muted block uppercase">Incidents</span>
            <span className="text-xs font-bold text-accent-emerald mt-0.5 block">{metrics.incidentsCreated ?? 0}</span>
          </div>
        </div>
      )}

      {state === 'failed' && errorMessage && (
        <p className="text-xs text-severity-critical bg-panel/60 p-2.5 rounded-lg border border-severity-critical/20">
          {errorMessage}
        </p>
      )}
    </div>
  )
}
