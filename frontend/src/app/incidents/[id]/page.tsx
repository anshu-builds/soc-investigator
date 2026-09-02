'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronLeft,
  Clock,
  Copy,
  Database,
  ExternalLink,
  FileText,
  Lock,
  MessageSquare,
  Radio,
  RefreshCw,
  Send,
  Shield,
  Target,
  Terminal,
  User,
  Wifi,
  Zap,
} from 'lucide-react'
import { format } from 'date-fns'

import { getIncident, updateIncidentStatus } from '@/lib/api'
import type { AttackPhase, Evidence, Incident, SecurityEvent } from '@/lib/types'
import { AttackTypeLabel, MitreTechniqueChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { EventDrawer } from '@/components/ui/EventDrawer'
import { SkeletonCard, SkeletonTable, SkeletonText } from '@/components/ui/Skeleton'

const PHASE_ICONS: Record<string, React.ElementType> = {
  INITIAL_ACCESS: Wifi,
  COMPROMISE: Lock,
  ESCALATION: Zap,
  IMPACT: Database,
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [copiedId, setCopiedId] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [quickPrompt, setQuickPrompt] = useState('')

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
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Status update failed')
    } finally {
      setUpdatingStatus(false)
    }
  }

  const copyIncidentId = () => {
    if (!incident) return
    navigator.clipboard.writeText(incident.id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-5 w-32 bg-[#1e293b] rounded animate-pulse" />
        <SkeletonCard className="h-44" />
        <div className="grid gap-6 lg:grid-cols-2">
          <SkeletonCard className="h-80" />
          <SkeletonCard className="h-80" />
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="card p-8 text-center max-w-md mx-auto mt-12 border-[#7f1d1d] bg-[#11161d]">
        <AlertTriangle className="mx-auto h-8 w-8 text-[#ef4444]" />
        <h2 className="mt-2 text-base font-semibold text-[#f3f4f6]">Incident Not Found</h2>
        <p className="text-xs text-[#9ca3af] mt-1">{error || 'Unable to locate the specified incident.'}</p>
        <Link href="/incidents" className="btn-ghost mt-4 inline-flex text-xs">
          Return to Incidents
        </Link>
      </div>
    )
  }

  const phases = incident.attack_hypothesis?.phases || []

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-4">
        <Link
          href="/incidents"
          className="inline-flex items-center text-xs font-mono text-[#9ca3af] hover:text-[#f3f4f6] transition-colors"
        >
          <ChevronLeft className="mr-1 h-4 w-4" /> Back to Triage Queue
        </Link>

        <div className="flex items-center gap-3">
          {/* Status Dropdown */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[#9ca3af] font-mono">Status:</span>
            <select
              value={incident.status}
              disabled={updatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="input text-xs py-1 px-2.5 font-mono"
            >
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CLOSED">CLOSED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>

          <Link href={`/incidents/${incident.id}/report`} className="btn-ghost text-xs py-1.5 px-3">
            <FileText className="mr-1.5 h-3.5 w-3.5" />
            Report
          </Link>

          <Link href={`/incidents/${incident.id}/chat`} className="btn-primary text-xs py-1.5 px-3">
            <MessageSquare className="mr-1.5 h-3.5 w-3.5" />
            Launch Copilot
          </Link>
        </div>
      </div>

      {/* Incident Header Card */}
      <div className="card p-5 sm:p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              <button
                type="button"
                onClick={copyIncidentId}
                className="inline-flex items-center gap-1 rounded border border-[#1f2937] bg-[#171e28] px-2 py-0.5 font-mono text-[11px] text-[#9ca3af] hover:text-[#f3f4f6] transition"
              >
                {copiedId ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
                <span>{incident.id.slice(0, 13)}...</span>
              </button>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
              {incident.title}
            </h1>
            <div className="flex items-center gap-2">
              <AttackTypeLabel attackType={incident.attack_type} />
              <span className="font-mono text-xs text-[#6b7280]">·</span>
              <span className="font-mono text-xs text-[#9ca3af] bg-[#171e28] px-2 py-0.5 rounded border border-[#1f2937]">
                Confidence: {Math.round(incident.confidence * 100)}%
              </span>
            </div>
          </div>
        </div>

        {/* Entity / Scope Metadata Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3.5 font-mono text-xs">
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Affected User</span>
            <span className="text-[#facc15] font-medium block mt-0.5 truncate">
              {incident.affected_username || '—'}
            </span>
          </div>
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Host</span>
            <span className="text-[#f3f4f6] font-medium block mt-0.5 truncate">
              {incident.affected_host || '—'}
            </span>
          </div>
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Source IP</span>
            <span className="text-[#38bdf8] font-medium block mt-0.5">
              {incident.source_ip || '—'}
            </span>
          </div>
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">First Seen (UTC)</span>
            <span className="text-[#9ca3af] block mt-0.5">
              {format(new Date(incident.first_seen), 'HH:mm:ss')}
            </span>
          </div>
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Last Seen (UTC)</span>
            <span className="text-[#9ca3af] block mt-0.5">
              {format(new Date(incident.last_seen), 'HH:mm:ss')}
            </span>
          </div>
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Correlated Events</span>
            <span className="text-[#10b981] font-semibold block mt-0.5">
              {incident.event_count}
            </span>
          </div>
        </div>

        {/* Attack Narrative */}
        {incident.attack_hypothesis?.narrative && (
          <div className="rounded-lg border border-[#1f2937] bg-[#141b24] p-4 text-xs text-[#d1d5db] leading-relaxed">
            <span className="font-mono text-[10px] uppercase font-semibold text-[#10b981] block mb-1">
              Attack Hypothesis & Narrative
            </span>
            {incident.attack_hypothesis.narrative}
          </div>
        )}

        {/* MITRE ATT&CK Techniques */}
        {incident.techniques.length > 0 && (
          <div className="border-t border-[#1f2937] pt-4">
            <span className="font-mono text-[10px] uppercase font-semibold text-[#9ca3af] block mb-2">
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

      {/* Two-Column Split Workbench: Timeline & Evidence */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left: Chronological Attack Timeline */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
            <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
              <Clock className="h-4 w-4 text-[#10b981]" />
              Chronological Attack Progression
            </h2>
            <span className="font-mono text-[11px] text-[#9ca3af]">
              {phases.length} Phase{phases.length === 1 ? '' : 's'}
            </span>
          </div>

          {phases.length === 0 ? (
            <p className="text-xs text-[#6b7280] py-8 text-center">No timeline phases recorded for this incident.</p>
          ) : (
            <div className="space-y-4 pt-1">
              {phases.map((phase, idx) => {
                const Icon = PHASE_ICONS[phase.phase] || Target
                return (
                  <div key={`${phase.phase}-${idx}`} className="relative pl-6 border-l border-[#1f2937] pb-4 last:pb-0">
                    <span className="absolute -left-2 top-0 flex h-4 w-4 items-center justify-center rounded-full border border-[#10b981] bg-[#11161d]">
                      <Icon className="h-2.5 w-2.5 text-[#10b981]" />
                    </span>
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#f3f4f6]">
                          {phase.phase.replace(/_/g, ' ')}
                        </span>
                        {phase.technique && <MitreTechniqueChip techniqueId={phase.technique} />}
                      </div>
                      <p className="text-xs text-[#9ca3af] leading-relaxed">{phase.description}</p>
                      <p className="font-mono text-[10px] text-[#6b7280]">
                        {format(new Date(phase.timestamp_start), 'HH:mm:ss')} UTC · {phase.event_count} event{phase.event_count === 1 ? '' : 's'}
                      </p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right: Evidence Locker */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
            <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
              <Database className="h-4 w-4 text-[#10b981]" />
              Evidence Matrix
            </h2>
            <span className="font-mono text-[11px] text-[#10b981] bg-[#10b981]/10 px-2 py-0.5 rounded border border-[#10b981]/20">
              {incident.evidence.length} Item{incident.evidence.length === 1 ? '' : 's'}
            </span>
          </div>

          {incident.evidence.length === 0 ? (
            <p className="text-xs text-[#6b7280] py-8 text-center">No evidence events mapped yet.</p>
          ) : (
            <div className="space-y-3 max-h-[520px] overflow-y-auto pr-1">
              {incident.evidence.map((ev, index) => (
                <div
                  key={ev.id}
                  className="rounded-lg border border-[#1f2937] bg-[#141b24] p-3 hover:border-[#374151] transition"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="evidence-chip font-bold">
                        EV-{String(index + 1).padStart(3, '0')}
                      </span>
                      <span className="font-mono text-xs font-medium text-[#f3f4f6]">
                        {ev.event?.event_type || 'SECURITY_EVENT'}
                      </span>
                    </div>
                    <span className="rounded bg-[#171e28] px-1.5 py-0.5 font-mono text-[10px] text-[#9ca3af] uppercase">
                      {ev.role.replace(/_/g, ' ')}
                    </span>
                  </div>

                  {ev.description && (
                    <p className="mt-1.5 text-xs text-[#9ca3af] leading-relaxed">
                      {ev.description}
                    </p>
                  )}

                  <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-[#6b7280]">
                    <span>
                      {ev.event?.timestamp ? format(new Date(ev.event.timestamp), 'HH:mm:ss') : '—'} UTC · {ev.event?.source_ip || '—'}
                    </span>
                    {ev.event && (
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(ev.event!)}
                        className="text-[#38bdf8] hover:underline flex items-center gap-1"
                      >
                        Inspect Raw <Terminal className="h-2.5 w-2.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Quick Copilot Jump Bar */}
      <div className="card p-4 flex flex-wrap items-center justify-between gap-3 border-[#10b981]/30 bg-[#11161d]">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 text-[#10b981]">
            <MessageSquare className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-[#f3f4f6]">
              Accelerate with SOC AI Copilot
            </h3>
            <p className="text-[11px] text-[#9ca3af]">
              Ask questions grounded directly in this incident&apos;s evidence and MITRE techniques.
            </p>
          </div>
        </div>
        <Link href={`/incidents/${incident.id}/chat`} className="btn-primary text-xs py-1.5 px-3">
          Open Investigation Session <ArrowRight className="ml-1 h-3 w-3" />
        </Link>
      </div>

      {/* Raw Event Inspector Drawer */}
      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  )
}
