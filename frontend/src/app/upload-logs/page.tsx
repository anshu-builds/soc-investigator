'use client'

import { useState, useRef } from 'react'
import {
  Upload,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Clock,
  Shield,
} from 'lucide-react'
import { uploadLogs } from '@/lib/api'
import type { LogUploadResponse } from '@/lib/types'
import Link from 'next/link'
import { InvestigationBlocksBackground } from '@/components/ui/investigation-blocks-bg'
import { BorderBeam } from '@/components/ui/border-beam'

export default function UploadLogsPage() {
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<LogUploadResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) {
      setFile(f)
      setResult(null)
      setError(null)
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setUploading(true)
    setError(null)
    setResult(null)

    try {
      const res = await uploadLogs(file, file.name)
      setResult(res)
    } catch (e: any) {
      setError(e.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="relative p-6 max-w-3xl mx-auto animate-fade-in overflow-hidden">
      <InvestigationBlocksBackground />
      <div className="relative z-10">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-ink">Upload Security Logs</h1>
        <p className="text-slate-600 text-sm mt-1">
          Upload CSV or JSON log files. The system will automatically detect threats and create incidents.
        </p>
      </div>

      <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-xl">
        <div
          className={`card border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
            dragging ? 'border-jade bg-jade/10' : 'border-black/10 hover:border-jade/55'
          }`}
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) {
                setFile(f)
                setResult(null)
                setError(null)
              }
            }}
          />

          <div
            className={`mx-auto w-16 h-16 rounded-2xl flex items-center justify-center mb-4 transition-colors ${
              dragging ? 'bg-jade/20' : 'bg-white/60'
            }`}
          >
            <Upload className={`w-8 h-8 ${dragging ? 'text-jade' : 'text-slate-500'}`} />
          </div>

          {file ? (
            <div>
              <div className="flex items-center justify-center gap-2 text-slate-700">
                <FileText className="w-4 h-4 text-jade" />
                <span className="font-medium">{file.name}</span>
              </div>
              <div className="text-sm text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB</div>
            </div>
          ) : (
            <>
              <p className="text-slate-700 font-medium">Drop your log file here</p>
              <p className="text-sm text-slate-500 mt-1">or click to browse - CSV, JSON up to 10MB</p>
            </>
          )}
        </div>
      </BorderBeam>

      {file && !result && (
        <div className="mt-4 flex justify-end">
          <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-xl inline-flex">
            <button
              onClick={handleUpload}
              disabled={uploading}
              className="btn-primary flex items-center gap-2 px-6 py-2.5"
            >
              {uploading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Processing pipeline...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Run Detection Pipeline
                </>
              )}
            </button>
          </BorderBeam>
        </div>
      )}

      {error && (
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="mt-4 rounded-lg">
          <div className="p-4 rounded-lg bg-red-100 border border-red-300 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-red-700 font-medium text-sm">Upload failed</p>
              <p className="text-red-600/80 text-xs mt-1">{error}</p>
            </div>
          </div>
        </BorderBeam>
      )}

      {result && (
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="mt-4 rounded-2xl">
          <div className="card p-5 animate-slide-in">
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle2 className="w-5 h-5 text-green-600" />
              <span className="font-semibold text-green-700">Pipeline Complete</span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              {[
                {
                  label: 'Events Parsed',
                  value: result.events_parsed,
                  icon: FileText,
                  color: 'text-sky-600',
                },
                {
                  label: 'Events Flagged',
                  value: result.events_flagged,
                  icon: AlertTriangle,
                  color: 'text-amber-600',
                },
                {
                  label: 'Incidents Created',
                  value: result.incidents_created,
                  icon: Shield,
                  color: 'text-red-600',
                },
                {
                  label: 'Processing Time',
                  value: `${result.processing_time_ms}ms`,
                  icon: Clock,
                  color: 'text-slate-600',
                },
              ].map(({ label, value, icon: Icon, color }) => (
                <BorderBeam key={label} size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-lg">
                  <div className="bg-white/60 rounded-lg p-3 text-center border border-black/10">
                    <Icon className={`w-5 h-5 mx-auto mb-1 ${color}`} />
                    <div className="text-xl font-bold text-ink tabular-nums">{value}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{label}</div>
                  </div>
                </BorderBeam>
              ))}
            </div>

            {result.incidents_created > 0 && (
              <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-xl">
                <Link href="/incidents" className="btn-primary w-full flex items-center justify-center gap-2">
                  <Shield className="w-4 h-4" />
                  View {result.incidents_created} New Incident{result.incidents_created !== 1 ? 's' : ''}
                </Link>
              </BorderBeam>
            )}
          </div>
        </BorderBeam>
      )}

      <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="mt-6 rounded-2xl">
        <div className="card p-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Supported Formats</h3>
          <div className="space-y-2 text-sm text-slate-600">
            <div className="flex gap-2">
              <span className="font-mono text-xs bg-white/70 px-1.5 py-0.5 rounded text-slate-700 border border-black/10">
                CSV
              </span>
              Flat log files with headers (timestamp, event_type, source_ip, username, ...)
            </div>
            <div className="flex gap-2">
              <span className="font-mono text-xs bg-white/70 px-1.5 py-0.5 rounded text-slate-700 border border-black/10">
                JSON
              </span>
              Array of log objects or {`{"events": [...]}`}
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-black/10 text-xs text-slate-500">
            Field aliases supported: <code className="text-slate-700">@timestamp</code>,{' '}
            <code className="text-slate-700">src_ip</code>, <code className="text-slate-700">sourceIp</code>,{' '}
            <code className="text-slate-700">account</code>, etc.
          </div>
        </div>
      </BorderBeam>
      </div>
    </div>
  )
}
