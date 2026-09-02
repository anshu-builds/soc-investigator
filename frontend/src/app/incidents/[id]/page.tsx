'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronLeft,
  Clock,
  Copy,
  Database,
  ExternalLink,
  FileText,
  Filter,
  Layers,
  Loader2,
  Lock,
  MessageSquare,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  Target,
  Terminal,
  User,
  Wifi,
  Zap,
} from 'lucide-react'
import { format, formatDistanceStrict, formatDistanceToNow } from 'date-fns'

import { getIncident, updateIncidentStatus } from '@/lib/api'
import type { AttackPhase, Evidence, Incident, SecurityEvent } from '@/lib/types'
import { AttackTypeLabel, MitreTechniqueChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { EventDrawer } from '@/components/ui/EventDrawer'
import { SkeletonCard, SkeletonTable } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'

const PHASE_ICONS: Record<string, React.ElementType> = {
  INITIAL_ACCESS: Wifi,
  COMPROMISE: Lock,
  ESCALATION: Zap,
  IMPACT: Database,
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { success, error: toastError } = useToast()

  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [copiedId, setCopiedId] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [evidenceSearch, setEvidenceSearch] = useState('')

  useEffect(() => {
    params
      .then(({ id }) => getIncident(id))
      .then(setIncident)
      .catch((e) => setError(e instanceof Error ? e.message : 'Unable to retrieve incident'))
      .finally(() => setLoading(false))
  }, [params])

  const handleStatusChange = async (nextStatus: string) => {
    if (!incident || updatingStatus) return
    setUpdatingStatus(true)
    try {
      const updated = await updateIncidentStatus(incident.id, nextStatus)
      setIncident({ ...incident, status: updated.status as any })
      success('Incident Status Updated', `Status changed to ${nextStatus.replace(/_/g, ' ')}`)
    } catch (e) {
      toastError('Status Update Failed', e instanceof Error ? e.message : 'Failed to modify incident status')
    } finally {
      setUpdatingStatus(false)
    }
  }

  const copyIncidentId = () => {
    if (!incident) return
    navigator.clipboard.writeText(incident.id)
    setCopiedId(true)
    success('Incident ID Copied', incident.id)
    setTimeout(() => setCopiedId(false), 2000)
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-5 w-36 bg-elevated rounded animate-pulse" />
        <SkeletonCard className="h-48" />
        <div className="grid gap-6 lg:grid-cols-2">
          <SkeletonCard className="h-80" />
          <SkeletonCard className="h-80" />
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="card p-10 text-center max-w-md mx-auto mt-12 border-severity-critical/30 bg-panel">
        <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
        <h2 className="mt-3 text-base font-semibold text-ink-primary">Incident Record Not Found</h2>
        <p className="text-xs text-ink-secondary mt-1">{error || 'Unable to locate the specified security incident.'}</p>
        <Link href="/incidents" className="btn-primary mt-5 inline-flex items-center gap-1.5 text-xs">
          <ChevronLeft className="h-3.5 w-3.5" /> Return to Triage Queue
        </Link>
      </div>
    )
  }

  const phases = incident.attack_hypothesis?.phases || []

  // Filter evidence events
  const filteredEvidence = incident.evidence.filter((ev) => {
    if (!evidenceSearch.trim()) return true
    const q = evidenceSearch.toLowerCase()
    return (
      (ev.role || '').toLowerCase().includes(q) ||
      (ev.description || '').toLowerCase().includes(q) ||
      (ev.event?.event_type || '').toLowerCase().includes(q) ||
      (ev.event?.source_ip || '').toLowerCase().includes(q) ||
      (ev.event?.username || '').toLowerCase().includes(q)
    )
  })

  // Calculate temporal attack duration if dates are valid
  let durationStr = '—'
  try {
    if (incident.first_seen && incident.last_seen) {
      durationStr = formatDistanceStrict(new Date(incident.first_seen), new Date(incident.last_seen))
    }
  } catch {
    durationStr = '—'
  }

  return (
    <div className="space-y-6">
      {/* Top Workstation Navigation & Quick Actions Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <Link
          href="/incidents"
          className="inline-flex items-center text-xs font-mono text-ink-secondary hover:text-ink-primary transition-colors group"
        >
          <ChevronLeft className="mr-1 h-4 w-4 transition-transform group-hover:-translate-x-0.5" />
          <span>Back to Triage Queue</span>
        </Link>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Status Mutation Dropdown with Non-Blocking Loading State */}
          <div className="flex items-center gap-1.5 rounded-lg border border-border bg-panel px-2.5 py-1">
            <span className="text-[11px] text-ink-muted font-mono uppercase tracking-wider">Status:</span>
            <select
              value={incident.status}
              disabled={updatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-transparent text-xs font-mono text-ink-primary focus:outline-none cursor-pointer disabled:opacity-50"
              aria-label="Change incident status"
            >
              <option value="OPEN" className="bg-elevated text-ink-primary">OPEN</option>
              <option value="INVESTIGATING" className="bg-elevated text-ink-primary">INVESTIGATING</option>
              <option value="CLOSED" className="bg-elevated text-ink-primary">CLOSED</option>
              <option value="FALSE_POSITIVE" className="bg-elevated text-ink-primary">FALSE POSITIVE</option>
            </select>
            {updatingStatus && <Loader2 className="h-3 w-3 animate-spin text-accent-emerald ml-1" />}
          </div>

          {/* Formal Report Link */}
          <Link
            href={`/incidents/${incident.id}/report`}
            className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Generate and view formal incident report"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Formal Report</span>
          </Link>

          {/* AI Copilot Primary Action */}
          <Link
            href={`/incidents/${incident.id}/chat`}
            className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
            title="Launch interactive AI Investigation Copilot"
          >
            <MessageSquare className="h-3.5 w-3.5" />
            <span>Consult Copilot</span>
          </Link>
        </div>
      </div>

      {/* Incident Header Workstation Card */}
      <div className="card p-5 sm:p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2 max-w-3xl">
            {/* Badges & ID Strip */}
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              <button
                type="button"
                onClick={copyIncidentId}
                className="inline-flex items-center gap-1.5 rounded border border-border bg-elevated px-2 py-0.5 font-mono text-[11px] text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95"
                title="Click to copy full incident UUID"
              >
                {copiedId ? <Check className="h-3 w-3 text-accent-emerald" /> : <Copy className="h-3 w-3 text-ink-muted" />}
                <span>ID: {incident.id.slice(0, 8)}...</span>
              </button>
            </div>

            {/* Title */}
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-ink-primary">
              {incident.title}
            </h1>

            {/* Description if present */}
            {incident.description && (
              <p className="text-xs text-ink-secondary leading-relaxed max-w-2xl">
                {incident.description}
              </p>
            )}

            {/* Attack Classification & AI Confidence */}
            <div className="flex items-center gap-2 pt-0.5">
              <AttackTypeLabel attackType={incident.attack_type} />
              <span className="font-mono text-xs text-ink-muted">·</span>
              <span className="font-mono text-xs text-ink-secondary bg-elevated px-2 py-0.5 rounded border border-border">
                Confidence: <span className="font-bold text-ink-primary">{Math.round(incident.confidence * 100)}%</span>
              </span>
              <span className="font-mono text-xs text-ink-muted">·</span>
              <span className="font-mono text-xs text-ink-muted">
                {incident.event_count} evidence events correlated
              </span>
            </div>
          </div>
        </div>

        {/* Entity / Scope Metadata Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 rounded-xl border border-border bg-canvas/70 p-3.5 font-mono text-xs">
          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">Affected User</span>
            <span className="text-[#facc15] font-semibold block mt-0.5 truncate" title={incident.affected_username || 'None'}>
              {incident.affected_username || '—'}
            </span>
          </div>

          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">Host</span>
            <span className="text-ink-primary font-semibold block mt-0.5 truncate" title={incident.affected_host || 'None'}>
              {incident.affected_host || '—'}
            </span>
          </div>

          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">Source IP</span>
            <span className="text-accent-cyan font-semibold block mt-0.5 truncate" title={incident.source_ip || 'None'}>
              {incident.source_ip || '—'}
            </span>
          </div>

          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">First Seen (UTC)</span>
            <span className="text-ink-secondary block mt-0.5">
              {incident.first_seen ? format(new Date(incident.first_seen), 'HH:mm:ss') : '—'}
            </span>
          </div>

          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">Last Seen (UTC)</span>
            <span className="text-ink-secondary block mt-0.5">
              {incident.last_seen ? format(new Date(incident.last_seen), 'HH:mm:ss') : '—'}
            </span>
          </div>

          <div className="p-1">
            <span className="text-ink-muted block text-[10px] uppercase tracking-wider">Temporal Span</span>
            <span className="text-accent-emerald font-semibold block mt-0.5">
              {durationStr}
            </span>
          </div>
        </div>

        {/* Attack Narrative & Hypothesis */}
        {incident.attack_hypothesis?.narrative && (
          <div className="rounded-xl border border-border-subtle bg-elevated/40 p-4 text-xs text-ink-primary leading-relaxed">
            <span className="font-mono text-[10px] uppercase font-semibold text-accent-emerald block mb-1">
              Attack Hypothesis & Behavioral Narrative
            </span>
            <p className="text-ink-secondary leading-relaxed">{incident.attack_hypothesis.narrative}</p>
          </div>
        )}

        {/* MITRE ATT&CK Matrix Mapping */}
        {incident.techniques.length > 0 && (
          <div className="border-t border-border-subtle pt-4">
            <span className="font-mono text-[10px] uppercase font-semibold text-ink-muted block mb-2.5">
              Mapped MITRE ATT&CK Techniques ({incident.techniques.length})
            </span>
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
      </div>

      {/* Two-Column Investigation Workbench: Attack Progression & Evidence Locker */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left: Chronological Attack Progression */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <Clock className="h-4 w-4 text-accent-emerald" />
                Chronological Attack Progression
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Sequential attacker execution phases derived from evidence timestamps
              </p>
            </div>
            <span className="font-mono text-[11px] text-ink-muted">
              {phases.length} Phase{phases.length === 1 ? '' : 's'}
            </span>
          </div>

          {phases.length === 0 ? (
            <p className="text-xs text-ink-muted py-8 text-center">
              No sequential attack phases mapped for this incident.
            </p>
          ) : (
            <div className="space-y-4 pt-1">
              {phases.map((phase, idx) => {
                const Icon = PHASE_ICONS[phase.phase] || Target
                return (
                  <div
                    key={`${phase.phase}-${idx}`}
                    className="relative pl-6 border-l border-border pb-4 last:pb-0"
                  >
                    <span className="absolute -left-2 top-0 flex h-4 w-4 items-center justify-center rounded-full border border-accent-emerald bg-panel">
                      <Icon className="h-2.5 w-2.5 text-accent-emerald" />
                    </span>
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold uppercase tracking-wider text-ink-primary">
                          {phase.phase.replace(/_/g, ' ')}
                        </span>
                        {phase.technique && <MitreTechniqueChip techniqueId={phase.technique} />}
                      </div>
                      <p className="text-xs text-ink-secondary leading-relaxed">{phase.description}</p>
                      <p className="font-mono text-[10px] text-ink-muted">
                        {format(new Date(phase.timestamp_start), 'HH:mm:ss')} UTC · {phase.event_count} event{phase.event_count === 1 ? '' : 's'}
                      </p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right: Evidence Locker & Event Inspector */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div>
              <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
                <Database className="h-4 w-4 text-accent-cyan" />
                Evidence Locker
              </h2>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Underlying security telemetry events correlated into this incident
              </p>
            </div>
            <span className="font-mono text-[11px] text-accent-cyan bg-accent-cyan/10 px-2 py-0.5 rounded border border-accent-cyan/20">
              {incident.evidence.length} Record{incident.evidence.length === 1 ? '' : 's'}
            </span>
          </div>

          {/* Evidence Search Filter */}
          {incident.evidence.length > 3 && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
              <input
                type="text"
                placeholder="Filter evidence by event type, IP, or role..."
                value={evidenceSearch}
                onChange={(e) => setEvidenceSearch(e.target.value)}
                className="input w-full pl-8 py-1.5 text-xs font-mono"
              />
            </div>
          )}

          {incident.evidence.length === 0 ? (
            <p className="text-xs text-ink-muted py-8 text-center">
              No correlated security evidence mapped to this incident.
            </p>
          ) : filteredEvidence.length === 0 ? (
            <p className="text-xs text-ink-muted py-6 text-center">
              No evidence matching &ldquo;{evidenceSearch}&rdquo;.
            </p>
          ) : (
            <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
              {filteredEvidence.map((ev, index) => (
                <div
                  key={ev.id}
                  className="rounded-xl border border-border-subtle bg-canvas/50 p-3.5 hover:border-border transition"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="evidence-chip font-bold shrink-0">
                        EV-{String(ev.sequence_order ?? index + 1).padStart(3, '0')}
                      </span>
                      <span className="font-mono text-xs font-medium text-ink-primary truncate">
                        {ev.event?.event_type || 'SECURITY_EVENT'}
                      </span>
                    </div>
                    <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary uppercase shrink-0">
                      {ev.role.replace(/_/g, ' ')}
                    </span>
                  </div>

                  {ev.description && (
                    <p className="mt-1.5 text-xs text-ink-secondary leading-relaxed">
                      {ev.description}
                    </p>
                  )}

                  <div className="mt-2.5 flex items-center justify-between font-mono text-[10px] text-ink-muted border-t border-border-subtle pt-2">
                    <span className="truncate">
                      {ev.event?.timestamp ? format(new Date(ev.event.timestamp), 'yyyy-MM-dd HH:mm:ss') : '—'} UTC · {ev.event?.source_ip || '—'}
                    </span>
                    {ev.event && (
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(ev.event!)}
                        className="text-accent-cyan hover:underline flex items-center gap-1 shrink-0 ml-2"
                      >
                        <span>Inspect Raw</span>
                        <Terminal className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* AI Copilot Accelerated Investigation Bar */}
      <div className="card p-5 flex flex-wrap items-center justify-between gap-4 border-accent-emerald/30 bg-panel">
        <div className="flex items-center gap-3.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald shrink-0">
            <MessageSquare className="h-4.5 w-4.5" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-ink-primary">
              AI Security Copilot Investigation
            </h3>
            <p className="text-[11px] text-ink-secondary mt-0.5">
              Interact with the Copilot to formulate hypotheses, isolate root cause, and synthesize containment actions.
            </p>
          </div>
        </div>

        <Link
          href={`/incidents/${incident.id}/chat`}
          className="btn-primary text-xs py-2 px-4 flex items-center gap-1.5"
        >
          <span>Open AI Investigation</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {/* Raw Event Inspector Modal Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}
