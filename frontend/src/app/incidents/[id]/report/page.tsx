'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { AlertTriangle, ChevronLeft, Download, FileText, Loader2, Printer } from 'lucide-react'
import { format } from 'date-fns'
import { createReport, getReport } from '@/lib/api'
import type { ReportOut } from '@/lib/types'
import React, { Fragment, type ReactNode } from 'react'

function renderWithEvidence(children: ReactNode): ReactNode {
  if (typeof children === 'string') {
    const parts = children.split(/(\[EV-\d{3,}\])/g)
    if (parts.length === 1) return children
    return (
      <>
        {parts.map((part, i) =>
          /^\[EV-\d{3,}\]$/.test(part) ? (
            <span key={i} className="evidence-chip">{part}</span>
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
      setError(e instanceof Error ? e.message : 'Unable to generate report')
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
      setError(e instanceof Error ? e.message : 'Failed to generate PDF')
    } finally {
      setDownloadingPdf(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl p-5 sm:p-8">
      <div className="flex flex-wrap items-center justify-between gap-4 print:hidden">
        <div>
          <Link
            href={`/incidents/${incidentId}`}
            className="inline-flex items-center text-sm text-[#667085] hover:text-[#111827]"
          >
            <ChevronLeft className="mr-1 h-4 w-4" />Incident
          </Link>
          <h1 className="mt-2 text-2xl font-semibold tracking-[-.02em] text-[#111827]">
            Incident report
          </h1>
          {report && (
            <p className="mt-1 text-sm text-[#667085]">
              Generated {format(new Date(report.generated_at), 'yyyy-MM-dd HH:mm')} UTC
            </p>
          )}
        </div>
        <div className="flex gap-2">
          {report && (
            <>
              <button
                onClick={downloadPdf}
                disabled={downloadingPdf}
                className="btn-ghost"
              >
                {downloadingPdf ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Generating PDF…</>
                ) : (
                  <><Download className="mr-2 h-4 w-4" />Download PDF</>
                )}
              </button>
              <button onClick={() => window.print()} className="btn-ghost">
                <Printer className="mr-2 h-4 w-4" />Print / PDF
              </button>
            </>
          )}
          <button onClick={generate} disabled={generating} className="btn-primary">
            {generating ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Generating</>
            ) : (
              <><FileText className="mr-2 h-4 w-4" />{report ? 'Regenerate' : 'Generate report'}</>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-5 flex gap-3 rounded-xl border border-[#fecaca] bg-[#fef2f2] p-4 text-sm text-[#b42318] print:hidden">
          <AlertTriangle className="h-5 w-5 shrink-0" />{error}
        </div>
      )}

      {!report && !generating && (
        <div className="card mt-6 p-12 text-center print:hidden">
          <FileText className="mx-auto h-9 w-9 text-[#667085]" />
          <p className="mt-3 text-sm font-medium text-[#111827]">No report generated</p>
          <p className="mt-1 text-sm text-[#667085]">
            Create an evidence-based incident report when you are ready.
          </p>
        </div>
      )}

      {generating && (
        <div className="card mt-6 p-12 text-center text-sm text-[#667085] print:hidden">
          <Loader2 className="mx-auto mb-3 h-6 w-6 animate-spin text-[#168a52]" />
          Assembling incident data…
        </div>
      )}

      {report && (
        <article
          ref={reportRef}
          className="incident-report card mt-6 p-6 sm:p-8 print:mt-0 print:border-none print:shadow-none print:p-0"
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
                    className="text-[#168a52] underline hover:text-[#116e41]"
                  >
                    {children}
                  </a>
                )
              },
              img: ({ alt }) => (
                <span className="inline-block rounded bg-[#f3f4f6] px-2 py-1 text-xs text-[#667085] font-mono">
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
            <p>Confidential — Security Investigation Report</p>
          </div>
        </article>
      )}
    </div>
  )
}
