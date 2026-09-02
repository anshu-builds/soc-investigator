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
  Database,
  ExternalLink,
  FileText,
  Layers,
  Loader2,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Upload,
  UploadCloud,
  X,
  Zap,
} from 'lucide-react'

import { uploadLogs } from '@/lib/api'
import type { LogUploadResponse } from '@/lib/types'
import { useToast } from '@/components/ui/Toast'

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB
const SUPPORTED_EXTENSIONS = ['.csv', '.json']

export default function UploadLogsPage() {
  const { success, error: toastError } = useToast()

  const [file, setFile] = useState<File | null>(null)
  const [sourceName, setSourceName] = useState('')
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<LogUploadResponse | null>(null)

  const fileRef = useRef<HTMLInputElement>(null)

  const validateFile = (selectedFile: File): string | null => {
    const ext = '.' + selectedFile.name.split('.').pop()?.toLowerCase()
    if (!SUPPORTED_EXTENSIONS.includes(ext)) {
      return `Unsupported file format '${ext}'. Only .csv and .json logs are accepted.`
    }
    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      const sizeMb = (selectedFile.size / (1024 * 1024)).toFixed(2)
      return `File size (${sizeMb} MB) exceeds maximum permissible 10 MB threshold.`
    }
    if (selectedFile.size === 0) {
      return 'File is empty (0 bytes). Please provide valid telemetry data.'
    }
    return null
  }

  const handleSelectFile = (selectedFile: File) => {
    setError(null)
    setResult(null)
    const validationError = validateFile(selectedFile)
    if (validationError) {
      setError(validationError)
      toastError('Validation Failed', validationError)
      return
    }
    setFile(selectedFile)
    setSourceName(selectedFile.name)
  }

  const handleUpload = async () => {
    if (!file || uploading) return
    setUploading(true)
    setError(null)
    setProgress(15)

    const progressTimer = setInterval(() => {
      setProgress((p) => (p < 85 ? p + 15 : p))
    }, 180)

    try {
      const res = await uploadLogs(file, sourceName.trim() || undefined)
      clearInterval(progressTimer)
      setProgress(100)
      setResult(res)
      success(
        'Telemetry Batch Ingested',
        `Successfully ingested ${res.events_parsed} events (${res.incidents_created} new incidents created)`
      )
    } catch (e) {
      clearInterval(progressTimer)
      const msg = e instanceof Error ? e.message : 'Telemetry upload failed'
      setError(msg)
      toastError('Ingestion Failed', msg)
    } finally {
      setUploading(false)
    }
  }

  const resetUpload = () => {
    setFile(null)
    setSourceName('')
    setError(null)
    setResult(null)
    setProgress(0)
    if (fileRef.current) fileRef.current.value = ''
  }

  const fileExt = file?.name.split('.').pop()?.toUpperCase()

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* 1. HEADER (Open Canvas) */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              Telemetry Log Ingestion
            </h1>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-[11px] font-semibold text-accent-emerald border border-border">
              Batch Pipeline
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
            Upload CSV or JSON telemetry to stream events through deduplication, rule evaluation, and incident synthesis.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link href="/logs" className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5">
            <Database className="h-3.5 w-3.5" />
            <span>SIEM Logs</span>
          </Link>
          <Link href="/incidents" className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            <span>Incident Queue</span>
          </Link>
        </div>
      </div>

      {/* 2. PRIMARY DROPZONE (Main Focal Point) */}
      <div className="space-y-4">
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
              ? 'border-accent-emerald bg-accent-emerald/10'
              : file
              ? 'border-accent-emerald/60 bg-panel'
              : 'border-border/80 bg-panel/60 hover:border-border-active hover:bg-elevated/40'
          }`}
        >
          <div className="flex h-10 w-10 items-center justify-center rounded border border-border/80 bg-elevated text-accent-emerald mb-3">
            <UploadCloud className="h-5 w-5" />
          </div>

          {file ? (
            <div className="space-y-1">
              <div className="flex items-center justify-center gap-2">
                <span className="font-mono text-sm font-bold text-ink-primary">
                  {file.name}
                </span>
                <span className="rounded bg-elevated px-1.5 py-0.2 font-mono text-[10px] uppercase font-bold text-accent-cyan border border-border">
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
          <div className="p-4 rounded border border-border/80 bg-panel/70 space-y-3 animate-fade-in">
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
                  className="input w-full font-mono text-xs py-1.5"
                />
              </div>

              <div className="space-y-1 font-mono text-xs">
                <span className="block text-ink-muted text-[11px]">Payload Size</span>
                <div className="p-2 rounded bg-elevated border border-border text-ink-primary font-semibold">
                  {(file.size / 1024).toFixed(1)} KB (
                  {((file.size / MAX_FILE_SIZE_BYTES) * 100).toFixed(1)}% of 10 MB)
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border-subtle">
              <span className="text-[11px] font-mono text-ink-muted">
                Pre-flight check passed: Ready to stream into database
              </span>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={resetUpload}
                  disabled={uploading}
                  className="btn-ghost text-xs py-1 px-3"
                >
                  Clear
                </button>
                <button
                  type="button"
                  onClick={handleUpload}
                  disabled={uploading}
                  className="btn-primary text-xs py-1 px-4 flex items-center gap-1.5"
                >
                  {uploading ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Ingesting Telemetry…</span>
                    </>
                  ) : (
                    <>
                      <Upload className="h-3.5 w-3.5" />
                      <span>Execute Batch Ingestion</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Error Banner */}
        {error && (
          <div className="flex items-center gap-3 rounded border border-severity-critical/30 bg-severity-critical/10 p-3 text-xs text-severity-critical animate-fade-in">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* 3. TRANSACTIONAL INGESTION RECEIPT */}
      {result && (
        <div className="rounded-lg border border-accent-emerald/40 bg-panel/90 p-5 space-y-4 animate-fade-in shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-accent-emerald" />
              <h2 className="text-sm font-bold text-ink-primary font-mono">
                Telemetry Batch Ingestion Receipt
              </h2>
            </div>
            <span className="rounded bg-accent-emerald/10 px-2 py-0.5 font-mono text-[10px] text-accent-emerald font-semibold border border-accent-emerald/30">
              HTTP 200 OK · Committed
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
            <div className="p-3 rounded border border-border/80 bg-canvas/60 space-y-0.5">
              <span className="text-[10px] uppercase text-ink-muted block">Ingestion Job ID</span>
              <span className="text-ink-primary font-bold block truncate" title={result.job_id}>
                {result.job_id.slice(0, 10)}…
              </span>
            </div>

            <div className="p-3 rounded border border-border/80 bg-canvas/60 space-y-0.5">
              <span className="text-[10px] uppercase text-ink-muted block">Events Parsed</span>
              <span className="text-accent-emerald font-bold block text-base">
                {result.events_parsed.toLocaleString()}
              </span>
            </div>

            <div className="p-3 rounded border border-border/80 bg-canvas/60 space-y-0.5">
              <span className="text-[10px] uppercase text-ink-muted block">Flagged Anomalies</span>
              <span className="text-severity-critical font-bold block text-base">
                {result.events_flagged.toLocaleString()}
              </span>
            </div>

            <div className="p-3 rounded border border-border/80 bg-canvas/60 space-y-0.5">
              <span className="text-[10px] uppercase text-ink-muted block">Incidents Synthesized</span>
              <span className="text-severity-medium font-bold block text-base">
                {result.incidents_created.toLocaleString()}
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border-subtle/80">
            <span className="text-[11px] font-mono text-ink-muted">
              Execution latency: <strong className="text-ink-primary">{result.processing_time_ms.toFixed(1)} ms</strong>
            </span>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={resetUpload}
                className="btn-ghost text-xs py-1 px-3"
              >
                Upload Another Batch
              </button>
              <Link href="/logs" className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5">
                <Database className="h-3.5 w-3.5" />
                <span>Inspect in SIEM</span>
              </Link>
              <Link href="/incidents" className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5" />
                <span>View Incident Queue</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* 4. INGESTION PIPELINE LIFECYCLE STRIP */}
      <div className="space-y-2 pt-2">
        <span className="text-[10px] font-mono uppercase text-ink-muted tracking-wider block">
          Ingestion Architecture Flow
        </span>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-xs">
          <div className="p-2.5 rounded border border-border/80 bg-panel/50 space-y-0.5">
            <span className="text-[10px] text-ink-muted uppercase block">1. Stream</span>
            <span className="text-ink-primary font-semibold block text-[11px]">CSV / JSON Parse</span>
          </div>
          <div className="p-2.5 rounded border border-border/80 bg-panel/50 space-y-0.5">
            <span className="text-[10px] text-ink-muted uppercase block">2. Normalize</span>
            <span className="text-accent-cyan font-semibold block text-[11px]">Alias Mapping</span>
          </div>
          <div className="p-2.5 rounded border border-border/80 bg-panel/50 space-y-0.5">
            <span className="text-[10px] text-ink-muted uppercase block">3. Deduplicate</span>
            <span className="text-[#facc15] font-semibold block text-[11px]">LRU Hash Match</span>
          </div>
          <div className="p-2.5 rounded border border-border/80 bg-panel/50 space-y-0.5">
            <span className="text-[10px] text-ink-muted uppercase block">4. Detect</span>
            <span className="text-severity-critical font-semibold block text-[11px]">Rule Evaluation</span>
          </div>
          <div className="p-2.5 rounded border border-border/80 bg-panel/50 space-y-0.5">
            <span className="text-[10px] text-ink-muted uppercase block">5. Correlate</span>
            <span className="text-accent-emerald font-semibold block text-[11px]">Incident Synthesis</span>
          </div>
        </div>
      </div>
    </div>
  )
}
