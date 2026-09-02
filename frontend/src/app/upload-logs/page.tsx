'use client'

import React, { useRef, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Database,
  FileText,
  Loader2,
  Shield,
  Upload,
  Zap,
} from 'lucide-react'

import { uploadLogs } from '@/lib/api'
import type { LogUploadResponse } from '@/lib/types'

export default function UploadLogsPage() {
  const [file, setFile] = useState<File | null>(null)
  const [sourceName, setSourceName] = useState('')
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<LogUploadResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleSelectFile = (selectedFile: File) => {
    setFile(selectedFile)
    if (!sourceName) {
      setSourceName(selectedFile.name)
    }
    setResult(null)
    setError(null)
  }

  const handleUpload = async () => {
    if (!file || uploading) return
    setUploading(true)
    setError(null)
    setResult(null)

    try {
      const res = await uploadLogs(file, sourceName || file.name)
      setResult(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Telemetry upload processing failed')
    } finally {
      setUploading(false)
    }
  }

  const resetUpload = () => {
    setFile(null)
    setSourceName('')
    setResult(null)
    setError(null)
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      {/* Header */}
      <div className="border-b border-[#1f2937] pb-5">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
            Telemetry Ingestion Engine
          </h1>
          <span className="flex items-center gap-1 rounded border border-[#10b981]/30 bg-[#10b981]/10 px-2 py-0.5 font-mono text-[10px] font-medium text-[#34d399]">
            <Upload className="h-3 w-3" /> Batch Pipeline
          </span>
        </div>
        <p className="mt-1 text-xs text-[#9ca3af]">
          Upload structured security logs for automated entity extraction, rule detection, and incident correlation.
        </p>
      </div>

      {/* Upload Dropzone Card */}
      <div className="card p-6 sm:p-8 border-[#1f2937] bg-[#11161d] space-y-5">
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
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            const f = e.dataTransfer.files[0]
            if (f) handleSelectFile(f)
          }}
          className={`cursor-pointer flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-10 text-center transition ${
            dragging
              ? 'border-[#10b981] bg-[#10b981]/10'
              : 'border-[#1f2937] bg-[#0b0f14]/50 hover:border-[#374151] hover:bg-[#141b24]'
          }`}
        >
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981] mb-3">
            <Upload className="h-6 w-6" />
          </div>

          {file ? (
            <div className="space-y-1">
              <span className="font-mono text-sm font-semibold text-[#f3f4f6] block">
                {file.name}
              </span>
              <span className="font-mono text-xs text-[#9ca3af] block">
                {(file.size / 1024).toFixed(1)} KB · Ready for ingestion
              </span>
            </div>
          ) : (
            <div className="space-y-1">
              <span className="text-sm font-semibold text-[#f3f4f6] block">
                Click to browse or drop log files here
              </span>
              <span className="text-xs text-[#9ca3af] block">
                Supports CSV (with headers) or JSON arrays, up to 10 MB
              </span>
            </div>
          )}
        </div>

        {file && !result && (
          <div className="space-y-4 pt-2 border-t border-[#1f2937]">
            <div>
              <label className="block text-xs font-medium text-[#9ca3af] mb-1.5" htmlFor="source-name">
                Batch Source Identifier (Optional)
              </label>
              <input
                id="source-name"
                type="text"
                value={sourceName}
                onChange={(e) => setSourceName(e.target.value)}
                placeholder="e.g. fw-edge-cluster-01.csv"
                className="input w-full font-mono text-xs"
              />
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={resetUpload}
                disabled={uploading}
                className="btn-ghost text-xs py-2 px-4"
              >
                Clear
              </button>
              <button
                type="button"
                onClick={handleUpload}
                disabled={uploading}
                className="btn-primary text-xs py-2 px-5"
              >
                {uploading ? (
                  <>
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    Parsing & Correlating…
                  </>
                ) : (
                  <>
                    <Zap className="mr-1.5 h-3.5 w-3.5" />
                    Ingest Security Logs
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="flex gap-3 rounded-lg border border-[#7f1d1d] bg-[#450a0a]/50 p-4 text-xs text-[#fca5a5]">
          <AlertTriangle className="h-4 w-4 shrink-0 text-[#ef4444]" />
          <div>
            <span className="font-semibold block mb-0.5">Ingestion Pipeline Failed</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Ingestion Results Breakdown */}
      {result && (
        <div className="card p-6 border-[#10b981]/30 bg-[#11161d] space-y-5 animate-fade-in">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#34d399]">
              <CheckCircle2 className="h-5 w-5" />
              <span>Batch Ingestion Completed Successfully</span>
            </div>
            <button
              type="button"
              onClick={resetUpload}
              className="text-xs text-[#9ca3af] hover:text-[#f3f4f6] underline"
            >
              Upload Another Batch
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
            <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
              <span className="text-[#6b7280] text-[10px] uppercase block">Events Parsed</span>
              <span className="text-xl font-bold text-[#f3f4f6] block mt-1">
                {result.events_parsed.toLocaleString()}
              </span>
            </div>

            <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
              <span className="text-[#6b7280] text-[10px] uppercase block">Events Flagged</span>
              <span className="text-xl font-bold text-[#f87171] block mt-1">
                {result.events_flagged.toLocaleString()}
              </span>
            </div>

            <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
              <span className="text-[#6b7280] text-[10px] uppercase block">Incidents Formed</span>
              <span className="text-xl font-bold text-[#facc15] block mt-1">
                {result.incidents_created}
              </span>
            </div>

            <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3">
              <span className="text-[#6b7280] text-[10px] uppercase block">Pipeline Latency</span>
              <span className="text-xl font-bold text-[#38bdf8] block mt-1">
                {result.processing_time_ms} ms
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
            <Link href="/logs" className="btn-ghost text-xs py-1.5 px-3">
              <Database className="mr-1.5 h-3.5 w-3.5" /> Explore in SIEM Logs
            </Link>
            {result.incidents_created > 0 && (
              <Link
                href="/incidents"
                className="btn-primary text-xs py-1.5 px-3"
              >
                <Shield className="mr-1.5 h-3.5 w-3.5" />
                <span>Triage Created Incidents ({result.incidents_created})</span>
                <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </div>
      )}

      {/* Parser Specifications & Aliases */}
      <div className="card p-5 border-[#1f2937] bg-[#11161d] space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#9ca3af]">
          Supported Ingestion Schemas
        </h3>
        <p className="text-xs text-[#9ca3af] leading-relaxed">
          The ingestion engine automatically maps common field aliases across Windows Event Logs, Syslog,
          Linux auth.log, and Wazuh alerts.
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px] pt-1">
          <div className="rounded border border-[#1f2937] bg-[#0b0f14] p-2">
            <span className="text-[#6b7280] block text-[10px]">Timestamp</span>
            <span className="text-[#38bdf8]">@timestamp, time, date</span>
          </div>
          <div className="rounded border border-[#1f2937] bg-[#0b0f14] p-2">
            <span className="text-[#6b7280] block text-[10px]">Source IP</span>
            <span className="text-[#38bdf8]">src_ip, source_ip, ip</span>
          </div>
          <div className="rounded border border-[#1f2937] bg-[#0b0f14] p-2">
            <span className="text-[#6b7280] block text-[10px]">Username</span>
            <span className="text-[#facc15]">user, username, account</span>
          </div>
          <div className="rounded border border-[#1f2937] bg-[#0b0f14] p-2">
            <span className="text-[#6b7280] block text-[10px]">Event Type</span>
            <span className="text-[#10b981]">event_type, action, rule</span>
          </div>
        </div>
      </div>
    </div>
  )
}
