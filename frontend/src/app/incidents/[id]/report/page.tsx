'use client'

import React, { Fragment, useEffect, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  AlertTriangle,
  ChevronLeft,
  Download,
  FileDown,
  FileText,
  Loader2,
  Printer,
  Shield,
  Sparkles,
} from 'lucide-react'
import { format } from 'date-fns'

import { createReport, downloadReportFile, getReport } from '@/lib/api'
import type { ReportOut } from '@/lib/types'

function renderWithEvidence(children: ReactNode): ReactNode {
  if (typeof children === 'string') {
    const parts = children.split(/(\[EV-\d{3,}\])/g)
    if (parts.length === 1) return children
    return (
      <>
        {parts.map((part, i) =>
          /^\[EV-\d{3,}\]$/.test(part) ? (
            <span key={i} className="evidence-chip">
              {part}
            </span>
          ) : (
            <Fragment key={i}>{part}</Fragment>
          )
        )}
      </>
    )
  }
  if (Array.isArray(children)) {
    return children.map((child, i) => (
      <Fragment key={i}>{renderWithEvidence(child)}</Fragment>
    ))
  }
  return children
}

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const [report, setReport] = useState<ReportOut | null>(null)
  const [generating, setGenerating] = useState(false)
  const [downloadingPdf, setDownloadingPdf] = useState(false)
  const [downloadingMd, setDownloadingMd] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [incidentId, setIncidentId] = useState('')
  const reportRef = useRef<HTMLElement>(null)

  useEffect(() => {
    params.then(({ id }) => setIncidentId(id))
  }, [params])

  const generate = async () => {
    const { id } = await params
    setGenerating(true)
    setError(null)
    try {
      const created = await createReport(id, { format: 'MARKDOWN' })
      setReport(await getReport(created.report_id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to generate incident report')
    } finally {
      setGenerating(false)
    }
  }

  const downloadPdf = async () => {
    if (!reportRef.current || !report || downloadingPdf) return
    setDownloadingPdf(true)
    setError(null)

    try {
      const html2pdf = (await import('html2pdf.js')).default

      const footer = reportRef.current.querySelector('.ir-print-footer') as HTMLElement | null
      if (footer) footer.style.display = 'block'

      const filename = `SOC_Investigator_Incident_${report.incident_id}.pdf`

      await html2pdf()
        .set({
          margin: [12, 14, 12, 14],
          filename,
          image: { type: 'jpeg', quality: 0.98 },
          html2canvas: {
            scale: 2,
            useCORS: true,
            letterRendering: true,
            logging: false,
          },
          jsPDF: {
            unit: 'mm',
            format: 'a4',
            orientation: 'portrait',
          },
          pagebreak: {
            mode: ['css', 'legacy'],
            avoid: [
              '.ir-subsection-title',
              '.ir-blockquote',
              '.ir-code-block',
              '.ir-tr',
              '.ir-evidence-block',
            ],
          },
        })
        .from(reportRef.current)
        .save()

      if (footer) footer.style.display = ''
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to compile PDF document')
    } finally {
      setDownloadingPdf(false)
    }
  }

  const downloadMarkdown = async () => {
    if (!report || downloadingMd) return
    setDownloadingMd(true)
    setError(null)
    try {
      const blob = await downloadReportFile(report.id)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `Incident_${report.incident_id}_Report.md`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to download report markdown')
    } finally {
      setDownloadingMd(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Top Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-4 print:hidden">
        <div>
          <Link
            href={`/incidents/${incidentId}`}
            className="inline-flex items-center text-xs font-mono text-[#9ca3af] hover:text-[#f3f4f6] transition-colors"
          >
            <ChevronLeft className="mr-1 h-3.5 w-3.5" /> Back to Incident Workspace
          </Link>
          <div className="mt-1 flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-[#f3f4f6]">
              Executive Incident Report
            </h1>
            <span className="font-mono text-xs text-[#9ca3af]">({incidentId.slice(0, 8)})</span>
          </div>
          {report && (
            <p className="mt-0.5 font-mono text-[11px] text-[#6b7280]">
              Generated {format(new Date(report.generated_at), 'yyyy-MM-dd HH:mm')} UTC
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {report && (
            <>
              <button
                type="button"
                onClick={downloadPdf}
                disabled={downloadingPdf}
                className="btn-ghost text-xs py-1.5 px-3"
              >
                {downloadingPdf ? (
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin text-[#10b981]" />
                ) : (
                  <Download className="mr-1.5 h-3.5 w-3.5" />
                )}
                <span>{downloadingPdf ? 'Exporting PDF…' : 'Download PDF'}</span>
              </button>

              <button
                type="button"
                onClick={downloadMarkdown}
                disabled={downloadingMd}
                className="btn-ghost text-xs py-1.5 px-3"
                title="Download raw Markdown report"
              >
                {downloadingMd ? (
                  <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin text-[#10b981]" />
                ) : (
                  <FileDown className="mr-1.5 h-3.5 w-3.5" />
                )}
                <span>Markdown</span>
              </button>

              <button
                type="button"
                onClick={() => window.print()}
                className="btn-ghost text-xs py-1.5 px-3"
              >
                <Printer className="mr-1.5 h-3.5 w-3.5" />
                <span>Print</span>
              </button>
            </>
          )}

          <button
            type="button"
            onClick={generate}
            disabled={generating}
            className="btn-primary text-xs py-1.5 px-3"
          >
            {generating ? (
              <>
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                Synthesizing…
              </>
            ) : (
              <>
                <Sparkles className="mr-1.5 h-3.5 w-3.5" />
                {report ? 'Regenerate Report' : 'Compile Executive Report'}
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="flex gap-3 rounded-lg border border-[#7f1d1d] bg-[#450a0a]/50 p-4 text-xs text-[#fca5a5] print:hidden">
          <AlertTriangle className="h-4 w-4 shrink-0 text-[#ef4444]" />
          <span>{error}</span>
        </div>
      )}

      {/* Initial Empty State */}
      {!report && !generating && (
        <div className="card p-12 text-center border-[#1f2937] bg-[#11161d] print:hidden">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-[#1f2937] bg-[#171e28] text-[#9ca3af]">
            <FileText className="h-6 w-6 text-[#10b981]" />
          </div>
          <h2 className="mt-4 text-sm font-semibold text-[#f3f4f6]">
            No Executive Report Generated
          </h2>
          <p className="mt-1 max-w-md mx-auto text-xs text-[#9ca3af] leading-relaxed">
            Generate a standardized executive briefing combining chronological telemetry,
            verified MITRE ATT&CK tactics, and actionable containment recommendations.
          </p>
          <button
            type="button"
            onClick={generate}
            className="btn-primary mt-5 text-xs py-2 px-4 inline-flex items-center gap-1.5"
          >
            <Sparkles className="h-3.5 w-3.5" /> Compile Executive Report
          </button>
        </div>
      )}

      {/* Loading Progress State */}
      {generating && (
        <div className="card p-12 text-center border-[#1f2937] bg-[#11161d] print:hidden space-y-3">
          <Loader2 className="mx-auto h-7 w-7 animate-spin text-[#10b981]" />
          <h3 className="text-sm font-semibold text-[#f3f4f6]">
            Assembling Incident Artifacts & Telemetry
          </h3>
          <p className="text-xs text-[#9ca3af] max-w-sm mx-auto">
            Correlating evidence, mapping MITRE techniques, and structuring forensic findings…
          </p>
        </div>
      )}

      {/* Report Document Presentation */}
      {report && (
        <article
          ref={reportRef}
          className="incident-report card p-6 sm:p-8 border-[#1f2937] bg-[#11161d] print:border-none print:shadow-none print:p-0 print:bg-white text-xs leading-relaxed"
        >
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              h1: ({ children }) => (
                <h1 className="ir-report-title">{children}</h1>
              ),
              h2: ({ children }) => (
                <h2 className="ir-section-title">{children}</h2>
              ),
              h3: ({ children }) => (
                <h3 className="ir-subsection-title">{renderWithEvidence(children)}</h3>
              ),
              p: ({ children }) => (
                <p className="ir-body">{renderWithEvidence(children)}</p>
              ),
              ul: ({ children }) => <ul className="ir-ul">{children}</ul>,
              ol: ({ children }) => <ol className="ir-ol">{children}</ol>,
              li: ({ children }) => (
                <li className="ir-li">{renderWithEvidence(children)}</li>
              ),
              strong: ({ children }) => (
                <strong className="ir-strong">{renderWithEvidence(children)}</strong>
              ),
              em: ({ children }) => <em className="ir-em">{children}</em>,
              table: ({ children }) => (
                <div className="ir-table-wrap">
                  <table className="ir-table">{children}</table>
                </div>
              ),
              thead: ({ children }) => <thead className="ir-thead">{children}</thead>,
              tbody: ({ children }) => <tbody>{children}</tbody>,
              tr: ({ children }) => <tr className="ir-tr">{children}</tr>,
              th: ({ children }) => <th className="ir-th">{children}</th>,
              td: ({ children }) => <td className="ir-td">{renderWithEvidence(children)}</td>,
              blockquote: ({ children }) => (
                <blockquote className="ir-blockquote">{children}</blockquote>
              ),
              code: ({ children, className }) => {
                if (className) {
                  return (
                    <pre className="ir-code-block">
                      <code className={className}>{children}</code>
                    </pre>
                  )
                }
                return <code className="ir-inline-code">{children}</code>
              },
              pre: ({ children }) => <>{children}</>,
              hr: () => <hr className="ir-hr" />,
              a: ({ href, children }) => {
                const safeHref = href && /^(https?:|\/|#|mailto:)/i.test(href.trim()) ? href : '#'
                const isExternal = safeHref.startsWith('http')
                return (
                  <a
                    href={safeHref}
                    target={isExternal ? '_blank' : undefined}
                    rel={isExternal ? 'noopener noreferrer' : undefined}
                    className="text-[#10b981] underline hover:text-[#34d399]"
                  >
                    {children}
                  </a>
                )
              },
              img: ({ alt }) => (
                <span className="inline-block rounded bg-[#171e28] border border-[#1f2937] px-2 py-1 text-[10px] text-[#9ca3af] font-mono">
                  [{alt ? String(alt) : 'Image'} (external media blocked)]
                </span>
              ),
            }}
            urlTransform={(url: string) => {
              const trimmed = url.trim().toLowerCase()
              if (/^(https?:|\/|#|mailto:)/.test(trimmed)) {
                return url
              }
              return ''
            }}
          >
            {report.content
              .replace(/---\s*\n\*\s*Automatically generated by SOC Investigator[\s\S]*$/i, '')
              .replace(/---\s*\n\*Evidence citations are traceable[\s\S]*$/i, '')
              .trim()}
          </ReactMarkdown>

          <div className="ir-print-footer">
            <p>SOC Investigator · Incident ID: {report.incident_id}</p>
            <p>Confidential — Security Operations Forensics & Incident Response Report</p>
          </div>
        </article>
      )}
    </div>
  )
}
