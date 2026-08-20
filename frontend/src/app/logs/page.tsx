'use client'

import { useState, useRef } from 'react'
import { Upload, FileText, CheckCircle2, AlertTriangle, Zap, Clock, Shield } from 'lucide-react'
import { uploadLogs } from '@/lib/api'
import type { LogUploadResponse } from '@/lib/types'
import Link from 'next/link'

export default function LogsPage() {
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
    if (f) { setFile(f); setResult(null); setError(null) }
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
    <div className="p-6 max-w-3xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Upload Security Logs</h1>
        <p className="text-slate-400 text-sm mt-1">
          Upload CSV or JSON log files. The system will automatically detect threats and create incidents.
        </p>
      </div>

      {/* Drop zone */}
      <div
        className={`card border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
          dragging ? 'border-accent-cyan bg-accent-cyan/5' : 'border-border hover:border-border-bright'
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input
          ref={fileRef} type="file" accept=".csv,.json" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) { setFile(f); setResult(null); setError(null) } }}
        />
        <div className={`mx-auto w-16 h-16 rounded-2xl flex items-center justify-center mb-4 transition-colors ${
          dragging ? 'bg-accent-cyan/20' : 'bg-bg-tertiary'
        }`}>
          <Upload className={`w-8 h-8 ${dragging ? 'text-accent-cyan' : 'text-slate-500'}`} />
        </div>
        {file ? (
          <div>
            <div className="flex items-center justify-center gap-2 text-slate-300">
              <FileText className="w-4 h-4 text-accent-blue" />
              <span className="font-medium">{file.name}</span>
            </div>
            <div className="text-sm text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB</div>
          </div>
        ) : (
          <>
            <p className="text-slate-300 font-medium">Drop your log file here</p>
            <p className="text-sm text-slate-500 mt-1">or click to browse — CSV, JSON up to 10MB</p>
          </>
        )}
      </div>

      {/* Upload button */}
      {file && !result && (
        <div className="mt-4 flex justify-end">
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
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mt-4 p-4 rounded-lg bg-red-950/40 border border-red-800/50 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-400 font-medium text-sm">Upload failed</p>
            <p className="text-red-300/70 text-xs mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="mt-4 card p-5 animate-slide-in">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle2 className="w-5 h-5 text-green-400" />
            <span className="font-semibold text-green-400">Pipeline Complete</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            {[
              { label: 'Events Parsed', value: result.events_parsed, icon: FileText, color: 'text-blue-400' },
              { label: 'Events Flagged', value: result.events_flagged, icon: AlertTriangle, color: 'text-yellow-400' },
              { label: 'Incidents Created', value: result.incidents_created, icon: Shield, color: 'text-red-400' },
              { label: 'Processing Time', value: `${result.processing_time_ms}ms`, icon: Clock, color: 'text-slate-400' },
            ].map(({ label, value, icon: Icon, color }) => (
              <div key={label} className="bg-bg-tertiary rounded-lg p-3 text-center">
                <Icon className={`w-5 h-5 mx-auto mb-1 ${color}`} />
                <div className="text-xl font-bold text-white tabular-nums">{value}</div>
                <div className="text-xs text-slate-500 mt-0.5">{label}</div>
              </div>
            ))}
          </div>
          {result.incidents_created > 0 && (
            <Link href="/incidents" className="btn-primary w-full flex items-center justify-center gap-2">
              <Shield className="w-4 h-4" />
              View {result.incidents_created} New Incident{result.incidents_created !== 1 ? 's' : ''}
            </Link>
          )}
        </div>
      )}

      {/* Supported formats */}
      <div className="mt-6 card p-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Supported Formats</h3>
        <div className="space-y-2 text-sm text-slate-400">
          <div className="flex gap-2"><span className="font-mono text-xs bg-bg-tertiary px-1.5 py-0.5 rounded text-slate-300">CSV</span> Flat log files with headers (timestamp, event_type, source_ip, username, ...)</div>
          <div className="flex gap-2"><span className="font-mono text-xs bg-bg-tertiary px-1.5 py-0.5 rounded text-slate-300">JSON</span> Array of log objects or {`{"events": [...]}`}</div>
        </div>
        <div className="mt-3 pt-3 border-t border-border text-xs text-slate-500">
          Field aliases supported: <code className="text-slate-400">@timestamp</code>, <code className="text-slate-400">src_ip</code>, <code className="text-slate-400">sourceIp</code>, <code className="text-slate-400">account</code>, etc.
        </div>
      </div>
    </div>
  )
}
