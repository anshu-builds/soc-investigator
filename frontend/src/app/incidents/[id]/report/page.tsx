'use client'

import React, { Fragment, useEffect, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronLeft,
  Clock,
  Database,
  Download,
  FileDown,
  FileText,
  Layers,
  ListOrdered,
  Loader2,
  Lock,
  Printer,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  User,
  Wifi,
  Zap,
} from 'lucide-react'
import { format, formatDistanceStrict } from 'date-fns'

import { createReport, downloadReportFile, getIncident, getReport } from '@/lib/api'
import type { AttackPhase, Evidence, Incident, ReportOut, SecurityEvent } from '@/lib/types'
import { AttackTypeLabel, MitreTechniqueChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { EventDrawer } from '@/components/ui/EventDrawer'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'

const PHASE_ICONS: Record<string, React.ElementType> = {
  INITIAL_ACCESS: Wifi,
  COMPROMISE: Lock,
  ESCALATION: Zap,
  IMPACT: Database,
}

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
  const { success, error: toastError } = useToast()

  const [incidentId, setIncidentId] = useState('')
  const [incident, setIncident] = useState<Incident | null>(null)
  const [report, setReport] = useState<ReportOut | null>(null)
  const [activeTab, setActiveTab] = useState<'executive' | 'technical' | 'document'>('executive')

  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [downloadingPdf, setDownloadingPdf] = useState(false)
  const [downloadingMd, setDownloadingMd] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)

  const reportRef = useRef<HTMLElement>(null)

  // Initialize incident and restore previous report from session if available
  useEffect(() => {
    let isMounted = true

    params
      .then(async ({ id }) => {
        setIncidentId(id)
        try {
          const inc = await getIncident(id)
          if (!isMounted) return
          setIncident(inc)

          // Check for existing report stored in sessionStorage
          const storageKey = `soc_incident_report_${id}`
          const savedReportId =
            typeof window !== 'undefined' ? sessionStorage.getItem(storageKey) : null

          if (savedReportId) {
            try {
              const rep = await getReport(savedReportId)
              if (isMounted) setReport(rep)
            } catch {
              // Saved report id is stale or not found; ignore
            }
          }
        } catch (e) {
          if (isMounted) {
            setError(e instanceof Error ? e.message : 'Unable to load incident data')
          }
        } finally {
          if (isMounted) setLoading(false)
        }
      })
      .catch((e) => {
        if (isMounted) {
          setError(e instanceof Error ? e.message : 'Failed to parse incident parameter')
          setLoading(false)
        }
      })

    return () => {
      isMounted = false
    }
  }, [params])

  const generate = async () => {
    if (!incidentId || generating) return
    setGenerating(true)
    setError(null)

    try {
      const created = await createReport(incidentId, {
        format: 'MARKDOWN',
        include_ai_summary: true,
      })
      const rep = await getReport(created.report_id)
      setReport(rep)

      if (typeof window !== 'undefined') {
        sessionStorage.setItem(`soc_incident_report_${incidentId}`, created.report_id)
      }
      success('Report Generated', 'Executive forensic report successfully synthesized')
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Unable to generate incident report'
      setError(msg)
      toastError('Generation Failed', msg)
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

      const filename = `SOC_Report_${incident?.id ? incident.id.slice(0, 8) : 'Incident'}.pdf`

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
      success('PDF Export Complete', `Report downloaded as ${filename}`)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to compile PDF document'
      setError(msg)
      toastError('PDF Export Failed', msg)
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
      a.download = `Incident_${report.incident_id.slice(0, 8)}_Report.md`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
      success('Markdown Exported', 'Raw forensic markdown file downloaded')
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to download report markdown'
      setError(msg)
      toastError('Download Failed', msg)
    } finally {
      setDownloadingMd(false)
    }
  }

  // Calculate temporal attack duration if dates are valid
  let durationStr = '—'
  if (incident?.first_seen && incident?.last_seen) {
    try {
      durationStr = formatDistanceStrict(new Date(incident.first_seen), new Date(incident.last_seen))
    } catch {
      durationStr = '—'
    }
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl space-y-6">
        <div className="h-5 w-36 bg-elevated rounded animate-pulse" />
        <SkeletonCard className="h-44" />
        <SkeletonCard className="h-96" />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Top Workstation Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4 print:hidden">
        <div>
          <Link
            href={`/incidents/${incidentId}`}
            className="inline-flex items-center text-xs font-mono text-ink-secondary hover:text-ink-primary transition-colors group"
          >
            <ChevronLeft className="mr-1 h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
            <span>Back to Incident Workspace</span>
          </Link>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-ink-primary">
              Executive Security Incident Report
            </h1>
            <span className="font-mono text-xs text-ink-secondary">
              ID: {incidentId.slice(0, 8)}
            </span>
          </div>
          {report && (
            <p className="mt-0.5 font-mono text-[11px] text-ink-muted">
              Compiled on {format(new Date(report.generated_at), 'yyyy-MM-dd HH:mm:ss')} UTC
            </p>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {report && (
            <>
              <button
                type="button"
                onClick={downloadPdf}
                disabled={downloadingPdf}
                className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Export report to PDF format"
              >
                {downloadingPdf ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-accent-emerald" />
                ) : (
                  <Download className="h-3.5 w-3.5" />
                )}
                <span>{downloadingPdf ? 'Exporting…' : 'Export PDF'}</span>
              </button>

              <button
                type="button"
                onClick={downloadMarkdown}
                disabled={downloadingMd}
                className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Download raw Markdown report"
              >
                {downloadingMd ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-accent-emerald" />
                ) : (
                  <FileDown className="h-3.5 w-3.5" />
                )}
                <span>Markdown</span>
              </button>

              <button
                type="button"
                onClick={() => window.print()}
                className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Print report or save via system dialog"
              >
                <Printer className="h-3.5 w-3.5" />
                <span>Print</span>
              </button>
            </>
          )}

          <button
            type="button"
            onClick={generate}
            disabled={generating}
            className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
          >
            {generating ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                <span>Synthesizing Report…</span>
              </>
            ) : (
              <>
                <Sparkles className="h-3.5 w-3.5" />
                <span>{report ? 'Regenerate Report' : 'Compile Executive Report'}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* View Tabs */}
      {report && (
        <div className="flex items-center gap-2 border-b border-border pb-2 text-xs font-mono print:hidden">
          <button
            type="button"
            onClick={() => setActiveTab('executive')}
            className={`px-3 py-1.5 rounded-lg font-medium transition ${
              activeTab === 'executive'
                ? 'bg-elevated border border-border text-ink-primary font-bold'
                : 'text-ink-secondary hover:text-ink-primary'
            }`}
          >
            Executive Briefing
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('technical')}
            className={`px-3 py-1.5 rounded-lg font-medium transition ${
              activeTab === 'technical'
                ? 'bg-elevated border border-border text-ink-primary font-bold'
                : 'text-ink-secondary hover:text-ink-primary'
            }`}
          >
            Technical Forensics
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('document')}
            className={`px-3 py-1.5 rounded-lg font-medium transition ${
              activeTab === 'document'
                ? 'bg-elevated border border-border text-ink-primary font-bold'
                : 'text-ink-secondary hover:text-ink-primary'
            }`}
          >
            Full Document (Print Preview)
          </button>
        </div>
      )}

      {/* Non-blocking Error Banner */}
      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4 text-xs text-severity-critical print:hidden animate-fade-in">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State when no report compiled yet */}
      {!report && !generating && (
        <div className="card p-12 text-center border-border bg-panel print:hidden space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald">
            <FileText className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <h2 className="text-base font-bold text-ink-primary">
              No Incident Report Compiled Yet
            </h2>
            <p className="max-w-md mx-auto text-xs text-ink-secondary leading-relaxed">
              Compile a formal security report synthesizing verified telemetry, MITRE ATT&CK
              technique mapping, tactical evidence records, and recommended remediation actions.
            </p>
          </div>
          <button
            type="button"
            onClick={generate}
            className="btn-primary mt-3 text-xs py-2 px-4 inline-flex items-center gap-2"
          >
            <Sparkles className="h-4 w-4" />
            <span>Compile Executive Report</span>
          </button>
        </div>
      )}

      {/* Generating Progress State */}
      {generating && (
        <div className="card p-12 text-center border-border bg-panel print:hidden space-y-3.5 animate-pulse-subtle">
          <Loader2 className="mx-auto h-8 w-8 animate-spin text-accent-emerald" />
          <h3 className="text-sm font-bold text-ink-primary">
            Synthesizing Forensic Telemetry & Analysis
          </h3>
          <p className="text-xs text-ink-secondary max-w-sm mx-auto leading-relaxed">
            Correlating security evidence, verifying attack trajectories, mapping MITRE techniques,
            and formatting containment actions…
          </p>
        </div>
      )}

      {/* REPORT CONTENT VIEWPORT */}
      {report && incident && (
        <div className="space-y-6">
          {/* TAB 1: EXECUTIVE BRIEFING VIEW */}
          {(activeTab === 'executive' || activeTab === 'document') && (
            <div className="space-y-6">
              {/* Executive Metadata Header Card */}
              <div className="card p-6 sm:p-7 space-y-5 border-border bg-panel shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-4">
                  <div className="space-y-1">
                    <span className="font-mono text-[10px] uppercase font-bold text-accent-emerald tracking-wider">
                      Forensic Artifact · Synthesized from Telemetry
                    </span>
                    <h2 className="text-xl font-bold text-ink-primary">
                      {incident.title}
                    </h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={incident.severity} />
                    <StatusBadge status={incident.status} />
                  </div>
                </div>

                {/* Scope & Impact Metric Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-2 rounded-lg bg-elevated/60 border border-border-subtle">
                    <span className="text-ink-muted block text-[10px] uppercase">Attack Vector</span>
                    <span className="text-ink-primary font-bold block mt-0.5 truncate">
                      {incident.attack_type.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div className="p-2 rounded-lg bg-elevated/60 border border-border-subtle">
                    <span className="text-ink-muted block text-[10px] uppercase">Target Entity</span>
                    <span className="text-[#facc15] font-bold block mt-0.5 truncate">
                      {incident.affected_username || incident.affected_host || '—'}
                    </span>
                  </div>

                  <div className="p-2 rounded-lg bg-elevated/60 border border-border-subtle">
                    <span className="text-ink-muted block text-[10px] uppercase">Adversary Source</span>
                    <span className="text-accent-cyan font-bold block mt-0.5 truncate">
                      {incident.source_ip || '—'}
                    </span>
                  </div>

                  <div className="p-2 rounded-lg bg-elevated/60 border border-border-subtle">
                    <span className="text-ink-muted block text-[10px] uppercase">Temporal Span</span>
                    <span className="text-accent-emerald font-bold block mt-0.5">
                      {durationStr}
                    </span>
                  </div>
                </div>

                {/* AI Executive Summary Block */}
                {report.ai_summary && (
                  <div className="rounded-xl border border-accent-emerald/30 bg-accent-emerald/10 p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <Sparkles className="h-4 w-4 text-accent-emerald" />
                      <span className="font-mono text-xs font-bold uppercase tracking-wider text-accent-emerald">
                        Executive Investigation Summary
                      </span>
                    </div>
                    <p className="text-xs text-ink-primary leading-relaxed">
                      {report.ai_summary}
                    </p>
                  </div>
                )}

                {/* Recommended Containment & Next Steps */}
                {report.recommended_actions && report.recommended_actions.length > 0 && (
                  <div className="rounded-xl border border-border-subtle bg-elevated/40 p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-accent-emerald" />
                      <span className="font-mono text-xs font-bold uppercase tracking-wider text-ink-primary">
                        Recommended Containment & Next Actions
                      </span>
                    </div>
                    <ul className="space-y-2 text-xs text-ink-secondary">
                      {report.recommended_actions.map((act, idx) => (
                        <li key={idx} className="flex items-start gap-2.5">
                          <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded bg-elevated border border-border text-[10px] font-mono text-ink-muted mt-0.5">
                            {idx + 1}
                          </span>
                          <span className="leading-relaxed">{act}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2 & 3: TECHNICAL FORENSICS & FULL DOCUMENT VIEW */}
          {(activeTab === 'technical' || activeTab === 'document') && (
            <div className="space-y-6">
              {/* Evidence Matrix Locker */}
              <div className="card p-6 space-y-4 border-border bg-panel">
                <div className="flex items-center justify-between border-b border-border-subtle pb-3">
                  <div className="space-y-0.5">
                    <h3 className="text-sm font-bold text-ink-primary flex items-center gap-2">
                      <Database className="h-4 w-4 text-accent-cyan" />
                      Correlated Forensic Evidence Annex
                    </h3>
                    <p className="text-xs text-ink-secondary">
                      Audited security telemetry entries establishing root cause and adversary progression
                    </p>
                  </div>
                  <span className="font-mono text-xs text-accent-cyan bg-accent-cyan/10 px-2.5 py-0.5 rounded border border-accent-cyan/20">
                    {incident.evidence.length} Evidence Records
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left font-sans text-xs">
                    <thead className="th-soc border-b border-border">
                      <tr>
                        <th className="py-2.5 px-3">Item</th>
                        <th className="py-2.5 px-3">Tactical Role</th>
                        <th className="py-2.5 px-3">Event Type</th>
                        <th className="py-2.5 px-3">Timestamp (UTC)</th>
                        <th className="py-2.5 px-3">Source Entity</th>
                        <th className="py-2.5 px-3 text-right">Payload</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle font-mono text-[11px]">
                      {incident.evidence.map((ev, index) => (
                        <tr key={ev.id} className="tr-soc">
                          <td className="td-soc whitespace-nowrap">
                            <span className="evidence-chip">
                              EV-{String(ev.sequence_order ?? index + 1).padStart(3, '0')}
                            </span>
                          </td>
                          <td className="td-soc whitespace-nowrap uppercase text-ink-secondary text-[10px]">
                            {ev.role.replace(/_/g, ' ')}
                          </td>
                          <td className="td-soc whitespace-nowrap text-ink-primary font-semibold">
                            {ev.event?.event_type || 'SECURITY_EVENT'}
                          </td>
                          <td className="td-soc whitespace-nowrap text-ink-muted">
                            {ev.event?.timestamp ? format(new Date(ev.event.timestamp), 'yyyy-MM-dd HH:mm:ss') : '—'}
                          </td>
                          <td className="td-soc whitespace-nowrap text-accent-cyan">
                            {ev.event?.source_ip || ev.event?.username || '—'}
                          </td>
                          <td className="td-soc whitespace-nowrap text-right">
                            {ev.event && (
                              <button
                                type="button"
                                onClick={() => setSelectedEvent(ev.event!)}
                                className="text-accent-cyan hover:underline inline-flex items-center gap-1 font-sans text-xs"
                              >
                                <span>Inspect</span>
                                <Terminal className="h-3 w-3" />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* MITRE ATT&CK Matrix Mapping Grid */}
              {incident.techniques.length > 0 && (
                <div className="card p-5 space-y-3 border-border bg-panel">
                  <h3 className="text-sm font-bold text-ink-primary flex items-center gap-2">
                    <Shield className="h-4 w-4 text-accent-emerald" />
                    MITRE ATT&CK Framework Mapping
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {incident.techniques.map((t) => (
                      <MitreTechniqueChip
                        key={t.id}
                        techniqueId={t.sub_technique_id || t.technique_id}
                        techniqueName={t.sub_technique_name || t.technique_name}
                        url={t.url}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Forensic Markdown Document */}
              <article
                ref={reportRef}
                className="incident-report card p-6 sm:p-8 border-border bg-panel print:border-none print:shadow-none print:p-0 print:bg-white text-xs leading-relaxed"
              >
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    h1: ({ children }) => <h1 className="ir-report-title">{children}</h1>,
                    h2: ({ children }) => <h2 className="ir-section-title">{children}</h2>,
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
                      const safeHref =
                        href && /^(https?:|\/|#|mailto:)/i.test(href.trim()) ? href : '#'
                      const isExternal = safeHref.startsWith('http')
                      return (
                        <a
                          href={safeHref}
                          target={isExternal ? '_blank' : undefined}
                          rel={isExternal ? 'noopener noreferrer' : undefined}
                          className="text-accent-emerald underline hover:text-accent-emerald/80"
                        >
                          {children}
                        </a>
                      )
                    },
                    img: ({ alt }) => (
                      <span className="inline-block rounded bg-elevated border border-border px-2 py-1 text-[10px] text-ink-muted font-mono">
                        [{alt ? String(alt) : 'Media'} (external media blocked)]
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
            </div>
          )}
        </div>
      )}

      {/* Raw Event Inspector Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}
