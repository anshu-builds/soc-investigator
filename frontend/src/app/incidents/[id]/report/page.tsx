'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ChevronLeft, FileText, Download, Loader2, AlertTriangle } from 'lucide-react'
import { createReport, getReport, getReportDownloadUrl } from '@/lib/api'
import type { ReportOut } from '@/lib/types'
import { format } from 'date-fns'

export default function ReportPage({ params }: { params: { id: string } }) {
  const [report, setReport] = useState<ReportOut | null>(null)
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    setGenerating(true)
    setError(null)
    try {
      const { report_id } = await createReport(params.id, { format: 'MARKDOWN' })
      const rep = await getReport(report_id)
      setReport(rep)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setGenerating(false)
    }
  }

  // Simple markdown renderer with syntax highlighting for code blocks
  const renderMarkdown = (md: string) => {
    return md
      .split('\n')
      .map((line, i) => {
        if (line.startsWith('# '))  return <h1 key={i} className="text-2xl font-bold text-white mt-6 mb-3 border-b border-border pb-2">{line.slice(2)}</h1>
        if (line.startsWith('## ')) return <h2 key={i} className="text-lg font-semibold text-slate-200 mt-5 mb-2">{line.slice(3)}</h2>
        if (line.startsWith('### '))return <h3 key={i} className="text-sm font-semibold text-slate-300 mt-4 mb-1">{line.slice(4)}</h3>
        if (line.startsWith('| '))  return <div key={i} className="font-mono text-xs text-slate-400 border-b border-border/30 py-1 px-2">{line}</div>
        if (line.startsWith('- '))  return <li key={i} className="text-slate-400 text-sm ml-4 py-0.5 list-disc">{line.slice(2)}</li>
        if (line.startsWith('> '))  return <blockquote key={i} className="border-l-2 border-accent-blue pl-3 text-slate-400 text-sm italic my-1">{line.slice(2)}</blockquote>
        if (line.match(/^\d+\. /)) return <li key={i} className="text-slate-400 text-sm ml-4 py-0.5 list-decimal">{line.replace(/^\d+\. /, '')}</li>
        if (line === '---') return <hr key={i} className="border-border my-4" />
        if (line === '') return <div key={i} className="h-2" />
        return <p key={i} className="text-slate-400 text-sm leading-relaxed">{line}</p>
      })
  }

  return (
    <div className="p-6 max-w-4xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Link href={`/incidents/${params.id}`} className="text-slate-400 hover:text-slate-200 transition-colors">
            <ChevronLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-accent-cyan" />
              Incident Report
            </h1>
            {report && (
              <p className="text-xs text-slate-500 mt-0.5">
                Generated {format(new Date(report.generated_at), 'yyyy-MM-dd HH:mm')} UTC
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {report && (
            <a
              href={getReportDownloadUrl(report.id)}
              download
              className="btn-ghost flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download .md
            </a>
          )}
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="btn-primary flex items-center gap-2"
          >
            {generating ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>
            ) : (
              <><FileText className="w-4 h-4" /> {report ? 'Regenerate' : 'Generate Report'}</>
            )}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-800/50 flex items-center gap-3 mb-4">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <span className="text-red-400 text-sm">{error}</span>
        </div>
      )}

      {/* Report content */}
      {!report && !generating && (
        <div className="card p-16 text-center">
          <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className="text-slate-300 font-semibold mb-2">No report generated yet</h2>
          <p className="text-slate-500 text-sm mb-6">
            Generate a comprehensive incident report with evidence timeline, MITRE mappings, and recommended actions.
          </p>
          <button onClick={handleGenerate} className="btn-primary">
            Generate Report
          </button>
        </div>
      )}

      {generating && (
        <div className="card p-16 text-center">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Assembling incident data and generating report...</p>
        </div>
      )}

      {report && (
        <div className="card p-6">
          <div className="prose-sm">
            {renderMarkdown(report.content)}
          </div>
        </div>
      )}
    </div>
  )
}
