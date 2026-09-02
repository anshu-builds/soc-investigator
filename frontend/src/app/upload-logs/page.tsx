'use client'

import React, { useRef, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  FileCode,
  FileSpreadsheet,
  FileText,
  HardDrive,
  Layers,
  Loader2,
  Lock,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Upload,
  UploadCloud,
  Wifi,
  X,
  Zap,
} from 'lucide-react'

import { uploadLogs } from '@/lib/api'
import type { LogUploadResponse } from '@/lib/types'
import { useToast } from '@/components/ui/Toast'

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB

export default function UploadLogsPage() {
  const { success, error: toastError } = useToast()

  const [file, setFile] = useState<File | null>(null)
  const [sourceName, setSourceName] = useState('')
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<LogUploadResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copiedJobId, setCopiedJobId] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const validateFile = (candidate: File): string | null => {
    const ext = candidate.name.toLowerCase().split('.').pop()
    if (ext !== 'csv' && ext !== 'json') {
      return 'Unsupported file format. The ingestion engine requires .csv (with headers) or .json array telemetry.'
    }
    if (candidate.size > MAX_FILE_SIZE_BYTES) {
      const sizeMB = (candidate.size / (1024 * 1024)).toFixed(1)
      return `File size (${sizeMB} MB) exceeds the 10 MB limit. Please chunk your telemetry batch.`
    }
    return null
  }

  const handleSelectFile = (selectedFile: File) => {
    setError(null)
    setResult(null)

    const validationErr = validateFile(selectedFile)
    if (validationErr) {
      setError(validationErr)
      setFile(null)
      setSourceName('')
      return
    }

    setFile(selectedFile)
    if (!sourceName) {
      setSourceName(selectedFile.name)
    }
  }

  const handleUpload = async () => {
    if (!file || uploading) return

    const validationErr = validateFile(file)
    if (validationErr) {
      setError(validationErr)
      return
    }

    setUploading(true)
    setError(null)
    setResult(null)

    try {
      const res = await uploadLogs(file, sourceName.trim() || file.name)
      setResult(res)
      success(
        'Ingestion Complete',
        `Parsed ${res.events_parsed} events, formed ${res.incidents_created} incidents`
      )
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Telemetry upload processing failed'
      setError(msg)
      toastError('Ingestion Failed', msg)
    } finally {
      setUploading(false)
    }
  }

  const resetUpload = () => {
    setFile(null)
    setSourceName('')
    setResult(null)
    setError(null)
    if (fileRef.current) {
      fileRef.current.value = ''
    }
  }

  const copyJobId = (id: string) => {
    navigator.clipboard.writeText(id)
    setCopiedJobId(true)
    success('Job ID Copied', 'Ingestion Job UUID copied to clipboard')
    setTimeout(() => setCopiedJobId(false), 2000)
  }

  const fileExt = file?.name.toLowerCase().split('.').pop()

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              Telemetry Ingestion Engine
            </h1>
            <span className="flex items-center gap-1.5 rounded-full border border-accent-emerald/30 bg-accent-emerald/10 px-2.5 py-0.5 font-mono text-[10px] font-bold text-accent-emerald uppercase">
              <Upload className="h-3 w-3" />
              <span>Synchronous Batch Pipeline</span>
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
            Ingest raw CSV or JSON security telemetry for automated schema normalization, in-memory deduplication, rule-based anomaly detection, and incident correlation.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Link href="/logs" className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Database className="h-3.5 w-3.5" />
            <span>SIEM Logs</span>
          </Link>
          <Link href="/incidents" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            <span>Incident Queue</span>
          </Link>
        </div>
      </div>

      {/* Telemetry Ingestion Pipeline Verification Strip */}
      <div className="card p-4 sm:p-5 border-border bg-panel space-y-3 shadow-sm">
        <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
          <span className="font-mono text-[10px] uppercase font-bold text-ink-muted tracking-wider flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5 text-accent-emerald" />
            <span>Synchronous Ingestion & Correlation Lifecycle</span>
          </span>
          <span className="font-mono text-[10px] text-accent-emerald font-semibold">
            Transactional Backend Pipeline
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 font-mono text-xs">
          <div className="p-2.5 rounded-lg bg-elevated/40 border border-border-subtle space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">1. Ingest</span>
            <span className="text-ink-primary font-bold block truncate">CSV / JSON Stream</span>
          </div>
          <div className="p-2.5 rounded-lg bg-elevated/40 border border-border-subtle space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">2. Normalize</span>
            <span className="text-accent-cyan font-bold block truncate">Alias Mapping</span>
          </div>
          <div className="p-2.5 rounded-lg bg-elevated/40 border border-border-subtle space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">3. Deduplicate</span>
            <span className="text-[#facc15] font-bold block truncate">LRU Hash Match</span>
          </div>
          <div className="p-2.5 rounded-lg bg-elevated/40 border border-border-subtle space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">4. Detect</span>
            <span className="text-severity-critical font-bold block truncate">Rule Evaluation</span>
          </div>
          <div className="p-2.5 rounded-lg bg-elevated/40 border border-border-subtle space-y-1">
            <span className="text-[10px] text-ink-muted uppercase block">5. Correlate</span>
            <span className="text-accent-emerald font-bold block truncate">Incident Synthesis</span>
          </div>
        </div>
      </div>

      {/* Main Upload Dropzone Workspace */}
      <div className="card p-6 sm:p-7 border-border bg-panel space-y-5 shadow-sm">
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.json"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) handleSelectFile(f)
          }}
        />

        <div
          role="button"
          tabIndex={0}
          aria-label="Click to browse security logs or drop files here"
          onClick={() => !uploading && fileRef.current?.click()}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !uploading) {
              e.preventDefault()
              fileRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
            if (!uploading) setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            if (uploading) return
            const f = e.dataTransfer.files?.[0]
            if (f) handleSelectFile(f)
          }}
          className={`cursor-pointer flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 sm:p-10 text-center transition outline-none ${
            dragging
              ? 'border-accent-emerald bg-accent-emerald/10 scale-[0.99]'
              : file
              ? 'border-accent-emerald/40 bg-elevated/30 hover:border-accent-emerald'
              : 'border-border bg-canvas/60 hover:border-border-active hover:bg-elevated/40'
          }`}
        >
          <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-border/80 bg-elevated text-accent-emerald mb-3">
            <UploadCloud className="h-5 w-5" />
          </div>

          {file ? (
            <div className="space-y-1.5">
              <div className="flex items-center justify-center gap-2">
                <span className="font-mono text-sm font-bold text-ink-primary">
                  {file.name}
                </span>
                <span className="rounded bg-elevated px-2 py-0.5 font-mono text-[10px] uppercase font-bold text-accent-cyan border border-border">
                  {fileExt}
                </span>
              </div>
              <span className="font-mono text-xs text-ink-muted block">
                {(file.size / 1024).toFixed(1)} KB · Validated format · Ready for ingestion
              </span>
            </div>
          ) : (
            <div className="space-y-1">
              <span className="text-sm font-bold text-ink-primary block">
                Click to browse or drop security telemetry files here
              </span>
              <p className="text-xs text-ink-secondary max-w-sm mx-auto leading-relaxed">
                Accepts <strong className="text-ink-primary font-mono font-semibold">.csv</strong> (with header row) or <strong className="text-ink-primary font-mono font-semibold">.json</strong> arrays up to 10 MB and 10,000 events.
              </p>
            </div>
          )}
        </div>

        {/* Selected File Details & Actions Strip */}
        {file && !result && (
          <div className="space-y-4 pt-3 border-t border-border-subtle animate-fade-in">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2 space-y-1">
                <label
                  htmlFor="source-name"
                  className="block text-xs font-mono font-semibold text-ink-secondary"
                >
                  Batch Source Identifier (Recorded as source_file)
                </label>
                <input
                  id="source-name"
                  type="text"
                  value={sourceName}
                  onChange={(e) => setSourceName(e.target.value)}
                  placeholder="e.g. edge-firewall-cluster-01.csv"
                  className="input w-full font-mono text-xs"
                />
              </div>

              <div className="space-y-1 font-mono text-xs">
                <span className="block text-ink-muted text-[11px]">Payload Size</span>
                <div className="p-2.5 rounded-lg bg-elevated/60 border border-border-subtle text-ink-primary font-semibold">
                  {(file.size / 1024).toFixed(1)} KB (
                  {((file.size / MAX_FILE_SIZE_BYTES) * 100).toFixed(1)}% of 10 MB limit)
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <span className="text-[11px] font-mono text-ink-muted">
                Validation passed: Ready to stream into backend ingestion pipeline
              </span>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={resetUpload}
                  disabled={uploading}
                  className="btn-ghost text-xs py-2 px-4"
                >
                  Clear Selection
                </button>
                <button
                  type="button"
                  onClick={handleUpload}
                  disabled={uploading}
                  className="btn-primary text-xs py-2 px-5 flex items-center gap-2"
                >
                  {uploading ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Parsing & Correlating…</span>
                    </>
                  ) : (
                    <>
                      <Zap className="h-3.5 w-3.5" />
                      <span>Ingest Telemetry Batch</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Uploading In-Progress Status Card */}
        {uploading && (
          <div className="rounded-xl border border-accent-emerald/30 bg-accent-emerald/10 p-5 text-center space-y-2 animate-pulse-subtle">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-accent-emerald" />
            <h3 className="text-sm font-bold text-ink-primary">
              Streaming & Processing Telemetry Payload
            </h3>
            <p className="text-xs text-ink-secondary max-w-md mx-auto leading-relaxed">
              Normalizing schema fields, deduplicating with database cache, evaluating detection rules, and synthesizing incident groups…
            </p>
          </div>
        )}
      </div>

      {/* Non-blocking Error Notice */}
      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4 text-xs text-severity-critical animate-fade-in">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <div className="space-y-0.5">
            <span className="font-bold block">Ingestion Pipeline Failed</span>
            <span className="text-ink-secondary">{error}</span>
          </div>
        </div>
      )}

      {/* Ingestion Receipt & Processing Summary */}
      {result && (
        <div className="card p-6 sm:p-7 border-accent-emerald/40 bg-panel space-y-5 animate-fade-in shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-4">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 className="h-5 w-5 text-accent-emerald" />
              <div>
                <h3 className="text-base font-bold text-ink-primary">
                  Telemetry Ingestion Receipt
                </h3>
                <div className="flex items-center gap-2 font-mono text-[11px] text-ink-muted mt-0.5">
                  <span>Job: {result.job_id}</span>
                  <button
                    type="button"
                    onClick={() => copyJobId(result.job_id)}
                    className="hover:text-ink-primary transition"
                    title="Copy Job ID"
                  >
                    {copiedJobId ? (
                      <Check className="h-3 w-3 text-accent-emerald" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={resetUpload}
              className="text-xs font-mono text-accent-emerald hover:underline"
            >
              Ingest Another Batch
            </button>
          </div>

          {/* 4 Ingestion Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 font-mono text-xs">
            <div className="rounded-lg border border-border/80 bg-elevated/40 p-3 space-y-1">
              <span className="text-ink-muted text-[10px] uppercase block">Events Parsed</span>
              <span className="text-2xl font-bold text-ink-primary block">
                {result.events_parsed.toLocaleString()}
              </span>
              <span className="text-[11px] text-ink-secondary block font-sans">
                Normalized into DB
              </span>
            </div>

            <div className="rounded-lg border border-border/80 bg-elevated/40 p-3 space-y-1">
              <span className="text-ink-muted text-[10px] uppercase block">Events Flagged</span>
              <span className="text-2xl font-bold text-severity-critical block">
                {result.events_flagged.toLocaleString()}
              </span>
              <span className="text-[11px] text-ink-secondary block font-sans">
                Rule Anomaly Triggers
              </span>
            </div>

            <div className="rounded-lg border border-border/80 bg-elevated/40 p-3 space-y-1">
              <span className="text-ink-muted text-[10px] uppercase block">Incidents Formed</span>
              <span className="text-2xl font-bold text-[#facc15] block">
                {result.incidents_created}
              </span>
              <span className="text-[11px] text-ink-secondary block font-sans">
                Attack Groups Synthesized
              </span>
            </div>

            <div className="rounded-lg border border-border/80 bg-elevated/40 p-3 space-y-1">
              <span className="text-ink-muted text-[10px] uppercase block">Pipeline Latency</span>
              <span className="text-2xl font-bold text-accent-cyan block">
                {result.processing_time_ms} ms
              </span>
              <span className="text-[11px] text-ink-secondary block font-sans">
                Total Execution Time
              </span>
            </div>
          </div>

          {/* Source File Meta Strip */}
          <div className="p-3 rounded-lg bg-canvas/70 border border-border-subtle flex flex-wrap items-center justify-between text-xs font-mono">
            <span className="text-ink-muted">
              Source File: <strong className="text-ink-primary">{result.source_file}</strong>
            </span>
            <span className="text-accent-emerald">
              All events indexed with transactional ACID persistence
            </span>
          </div>

          {/* Investigation Pivots */}
          <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
            <Link
              href="/logs"
              className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
              title="Explore all security events in the SIEM Explorer"
            >
              <Database className="h-3.5 w-3.5" />
              <span>Explore Ingested Logs</span>
            </Link>

            {result.events_flagged > 0 && (
              <Link
                href="/logs?is_flagged=true"
                className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5 text-severity-critical border-severity-critical/30"
                title="View only events flagged as anomalous by rules"
              >
                <ShieldAlert className="h-3.5 w-3.5 text-severity-critical" />
                <span>View Flagged Events ({result.events_flagged})</span>
              </Link>
            )}

            {result.incidents_created > 0 && (
              <Link
                href="/incidents"
                className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Triage incidents formed by this ingestion"
              >
                <Shield className="h-3.5 w-3.5" />
                <span>Triage Created Incidents ({result.incidents_created})</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            )}
          </div>
        </div>
      )}

      {/* Parser Specifications & Field Aliases Reference */}
      <div className="card p-5 sm:p-6 border-border bg-panel space-y-3.5 shadow-sm">
        <div className="space-y-0.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-ink-primary flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-accent-emerald" />
            <span>Supported Schema Normalization & Field Aliases</span>
          </h3>
          <p className="text-xs text-ink-secondary leading-relaxed">
            The normalizer automatically resolves disparate field names across Windows Event Logs, Syslog, Linux auth.log, and Wazuh HIDS telemetry into standard fields.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-[11px] pt-1">
          <div className="rounded-lg border border-border-subtle bg-elevated/40 p-2.5 space-y-1">
            <span className="text-ink-muted text-[10px] uppercase block">Timestamp</span>
            <span className="text-accent-cyan block">@timestamp, time, date, ts</span>
          </div>

          <div className="rounded-lg border border-border-subtle bg-elevated/40 p-2.5 space-y-1">
            <span className="text-ink-muted text-[10px] uppercase block">Source IP</span>
            <span className="text-accent-cyan block">src_ip, source_ip, ip, client_ip</span>
          </div>

          <div className="rounded-lg border border-border-subtle bg-elevated/40 p-2.5 space-y-1">
            <span className="text-ink-muted text-[10px] uppercase block">Username</span>
            <span className="text-[#facc15] block">user, username, account, target_user</span>
          </div>

          <div className="rounded-lg border border-border-subtle bg-elevated/40 p-2.5 space-y-1">
            <span className="text-ink-muted text-[10px] uppercase block">Event Type</span>
            <span className="text-accent-emerald block">event_type, action, rule, activity</span>
          </div>
        </div>
      </div>
    </div>
  )
}
