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
        <div className="h-32 bg-elevated/40 rounded border border-border/60 animate-pulse" />
        <div className="grid gap-6 lg:grid-cols-2">
          <SkeletonCard className="h-80" />
          <SkeletonCard className="h-80" />
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="max-w-md mx-auto mt-12 p-8 text-center border border-severity-critical/30 rounded-lg bg-panel">
        <AlertTriangle className="mx-auto h-8 w-8 text-severity-critical" />
        <h2 className="mt-3 text-base font-semibold text-ink-primary">Incident Record Not Found</h2>
        <p className="text-xs text-ink-secondary mt-1">{error || 'Unable to locate the specified security incident.'}</p>
        <Link href="/incidents" className="btn-primary mt-5 inline-flex items-center gap-1.5 text-xs">
          <ChevronLeft className="h-3.5 w-3.5" /> Return to Queue
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
      {/* 1. TOP ACTION BAR */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-3">
        <Link
          href="/incidents"
          className="inline-flex items-center text-xs font-mono text-ink-secondary hover:text-ink-primary transition-colors group"
        >
          <ChevronLeft className="mr-1 h-4 w-4 transition-transform group-hover:-translate-x-0.5" />
          <span>Incident Queue</span>
        </Link>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status Mutation Select */}
          <div className="flex items-center gap-1.5 rounded border border-border/80 bg-panel px-2.5 py-1">
            <span className="text-[11px] text-ink-muted font-mono uppercase">Status:</span>
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

          <Link
            href={`/incidents/${incident.id}/report`}
            className="btn-ghost text-xs py-1 px-3 flex items-center gap-1.5"
            title="Generate executive report"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Formal Report</span>
          </Link>

          <Link
            href={`/incidents/${incident.id}/chat`}
            className="btn-primary text-xs py-1 px-3 flex items-center gap-1.5"
            title="Launch interactive AI Investigation Copilot"
          >
            <MessageSquare className="h-3.5 w-3.5" />
            <span>Consult Copilot</span>
          </Link>
        </div>
      </div>

      {/* 2. INCIDENT DOSSIER IDENTITY SECTION (Open Canvas) */}
      <div className="space-y-4">
        {/* Severity, Status, Attack Vector, Confidence */}
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />

          <button
            type="button"
            onClick={copyIncidentId}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-elevated px-2 py-0.5 font-mono text-[11px] text-ink-secondary hover:text-ink-primary hover:border-border-active transition-colors active:scale-95"
            title="Click to copy UUID"
          >
            {copiedId ? <Check className="h-3 w-3 text-accent-emerald" /> : <Copy className="h-3 w-3 text-ink-muted" />}
            <span>INC-{incident.id.slice(0, 8)}</span>
          </button>

          <span className="text-xs font-mono text-ink-muted">·</span>
          <AttackTypeLabel attackType={incident.attack_type} />

          <span className="text-xs font-mono text-ink-muted">·</span>
          <span className="font-mono text-xs text-ink-secondary">
            Confidence: <strong className="text-ink-primary">{Math.round(incident.confidence * 100)}%</strong>
          </span>

          <span className="text-xs font-mono text-ink-muted">·</span>
          <span className="font-mono text-xs text-ink-muted">
            {incident.event_count} evidence events
          </span>
        </div>

        {/* Title */}
        <h1 className="text-2xl font-bold tracking-tight text-ink-primary">
          {incident.title}
        </h1>

        {/* Narrative */}
        {incident.attack_hypothesis?.narrative && (
          <p className="text-xs text-ink-secondary leading-relaxed max-w-4xl border-l-2 border-accent-emerald/60 pl-3 py-0.5">
            {incident.attack_hypothesis.narrative}
          </p>
        )}

        {/* Unified Entity / Scope Horizontal Strip */}
        <div className="rounded border border-border/80 bg-panel/60 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 divide-y sm:divide-y-0 sm:divide-x divide-border/60 text-xs font-mono">
          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">Target User</span>
            <span className="font-semibold text-[#facc15] block truncate mt-0.5" title={incident.affected_username || 'None'}>
              {incident.affected_username || '—'}
            </span>
          </div>

          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">Host</span>
            <span className="font-semibold text-ink-primary block truncate mt-0.5" title={incident.affected_host || 'None'}>
              {incident.affected_host || '—'}
            </span>
          </div>

          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">Source IP</span>
            <span className="font-semibold text-accent-cyan block truncate mt-0.5" title={incident.source_ip || 'None'}>
              {incident.source_ip || '—'}
            </span>
          </div>

          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">First Seen (UTC)</span>
            <span className="text-ink-secondary block mt-0.5">
              {incident.first_seen ? format(new Date(incident.first_seen), 'HH:mm:ss') : '—'}
            </span>
          </div>

          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">Last Seen (UTC)</span>
            <span className="text-ink-secondary block mt-0.5">
              {incident.last_seen ? format(new Date(incident.last_seen), 'HH:mm:ss') : '—'}
            </span>
          </div>

          <div className="p-2.5">
            <span className="text-[10px] uppercase text-ink-muted block">Duration</span>
            <span className="font-semibold text-accent-emerald block mt-0.5">
              {durationStr}
            </span>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Chips */}
        {incident.techniques.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="font-mono text-[10px] uppercase text-ink-muted">MITRE Techniques:</span>
            {incident.techniques.map((t) => (
              <MitreTechniqueChip
                key={t.id}
                techniqueId={t.sub_technique_id || t.technique_id}
                techniqueName={t.sub_technique_name || t.technique_name}
                url={t.url}
              />
            ))}
          </div>
        )}
      </div>

      {/* 3. TWO-COLUMN INVESTIGATION WORKBENCH (Timeline + Evidence Table) */}
      <div className="grid gap-6 lg:grid-cols-2 pt-2">
        {/* Left: Sequential Attack Timeline */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-2">
              <Clock className="h-3.5 w-3.5 text-accent-emerald" />
              <span>Chronological Attack Progression</span>
            </h2>
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
                    className="relative pl-6 border-l border-border/80 pb-4 last:pb-0"
                  >
                    <span className="absolute -left-2 top-0 flex h-4 w-4 items-center justify-center rounded-full border border-accent-emerald bg-panel">
                      <Icon className="h-2.5 w-2.5 text-accent-emerald" />
                    </span>
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold uppercase tracking-wider text-ink-primary">
                          {phase.phase.replace(/_/g, ' ')}
                        </span>
                        {phase.technique_name && (
                          <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-accent-cyan border border-border">
                            {phase.technique_name}
                          </span>
                        )}
                        {phase.timestamp_start && (
                          <span className="font-mono text-[10px] text-ink-muted ml-auto">
                            {format(new Date(phase.timestamp_start), 'HH:mm:ss')} UTC
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-ink-secondary leading-relaxed">
                        {phase.description}
                      </p>
                      {phase.technique && (
                        <div className="pt-1">
                          <span className="inline-flex items-center rounded border border-[#581c87]/70 bg-[#3b0764]/40 px-1.5 py-0.5 font-mono text-[10px] text-[#c084fc]">
                            {phase.technique}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right: Correlated Evidence Locker */}
        <div className="space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-2">
              <Database className="h-3.5 w-3.5 text-accent-cyan" />
              <span>Correlated Evidence Records</span>
            </h2>
            <span className="font-mono text-[11px] text-ink-muted">
              {incident.evidence.length} Events
            </span>
          </div>

          {/* Evidence Quick Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Filter evidence events…"
              value={evidenceSearch}
              onChange={(e) => setEvidenceSearch(e.target.value)}
              className="input w-full pl-8 text-xs py-1.5 bg-panel/60"
            />
          </div>

          {filteredEvidence.length === 0 ? (
            <p className="text-xs text-ink-muted py-6 text-center">
              No matching evidence events found.
            </p>
          ) : (
            <div className="border border-border/80 rounded overflow-hidden">
              <div className="max-h-[380px] overflow-y-auto divide-y divide-border-subtle/80">
                {filteredEvidence.map((ev, i) => (
                  <div
                    key={ev.id || i}
                    onClick={() => ev.event && setSelectedEvent(ev.event)}
                    className={`p-2.5 transition-colors cursor-pointer hover:bg-elevated/50 ${
                      selectedEvent?.id === ev.event_id ? 'bg-elevated' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-xs font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="rounded px-1.5 py-0.2 bg-elevated border border-border text-[10px] text-accent-cyan font-bold">
                          EV-{String(i + 1).padStart(3, '0')}
                        </span>
                        <span className="text-ink-primary font-semibold truncate max-w-[180px]">
                          {ev.event?.event_type || ev.role || 'EVENT'}
                        </span>
                      </div>
                      <span className="text-[10px] text-ink-muted">
                        {ev.event?.timestamp ? format(new Date(ev.event.timestamp), 'HH:mm:ss') : '—'}
                      </span>
                    </div>

                    <p className="text-[11px] text-ink-secondary mt-1 leading-snug line-clamp-2">
                      {ev.description || 'Contributing event telemetry'}
                    </p>

                    <div className="flex items-center justify-between text-[10px] font-mono text-ink-muted mt-1.5">
                      <span>IP: {ev.event?.source_ip || '—'}</span>
                      <span className="text-accent-emerald hover:underline">Inspect Raw &gt;</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Raw Event Detail Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}
