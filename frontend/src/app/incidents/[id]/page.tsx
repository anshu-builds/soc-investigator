'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { getIncident, updateIncidentStatus } from '@/lib/api'
import type { Incident, Evidence, AttackPhase, AttackTechnique } from '@/lib/types'
import { SeverityBadge, StatusBadge, MitreTechniqueChip } from '@/components/ui/badges'
import {
  MessageSquare, FileText, ChevronLeft, Clock, User, Wifi,
  Shield, AlertTriangle, Zap, Lock, Target, Database
} from 'lucide-react'
import { format } from 'date-fns'

const PHASE_ICONS: Record<string, React.ElementType> = {
  INITIAL_ACCESS: Wifi,
  COMPROMISE:     Lock,
  ESCALATION:     Zap,
  IMPACT:         Database,
}

const PHASE_COLORS: Record<string, string> = {
  INITIAL_ACCESS: 'text-indigo-400 bg-indigo-950/40 border-indigo-700/40',
  COMPROMISE:     'text-red-400 bg-red-950/40 border-red-700/40',
  ESCALATION:     'text-orange-400 bg-orange-950/40 border-orange-700/40',
  IMPACT:         'text-rose-400 bg-rose-950/40 border-rose-700/40',
  UNKNOWN:        'text-slate-400 bg-slate-800/40 border-slate-700/40',
}

function TimelineEntry({ phase, entry, index }: { phase: AttackPhase; entry: string; index: number }) {
  const PhaseIcon = PHASE_ICONS[phase.phase] || Target
  const colorClass = PHASE_COLORS[phase.phase] || PHASE_COLORS.UNKNOWN

  return (
    <div className="flex gap-4 relative">
      {/* Connector line */}
      {index > 0 && <div className="absolute left-4 -top-6 h-6 w-px bg-gradient-to-b from-border-bright to-border" />}

      {/* Phase icon */}
      <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 border ${colorClass} z-10 mt-0.5`}>
        <PhaseIcon className="w-3.5 h-3.5" />
      </div>

      {/* Content */}
      <div className={`flex-1 rounded-lg border p-3 mb-6 ${colorClass}`}>
        <div className="flex items-start justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider opacity-80">{phase.phase.replace('_', ' ')}</span>
              <MitreTechniqueChip techniqueId={phase.technique} />
            </div>
            <p className="text-sm mt-1 opacity-90">{phase.description}</p>
          </div>
          <div className="text-xs opacity-60 font-mono whitespace-nowrap">
            {format(new Date(phase.timestamp_start), 'HH:mm:ss')} UTC
          </div>
        </div>
        <div className="text-xs opacity-50 mt-1">{phase.event_count} event{phase.event_count !== 1 ? 's' : ''}</div>
      </div>
    </div>
  )
}

function EvidenceCard({ evidence, index }: { evidence: Evidence; index: number }) {
  const [expanded, setExpanded] = useState(false)
  const ROLE_COLORS: Record<string, string> = {
    TRIGGER_EVENT:       'text-red-400 bg-red-950/30',
    COMPROMISE_INDICATOR:'text-rose-400 bg-rose-950/30',
    ANOMALOUS_BEHAVIOR:  'text-orange-400 bg-orange-950/30',
    SUPPORTING_EVENT:    'text-slate-400 bg-slate-800/30',
  }
  const roleClass = ROLE_COLORS[evidence.role] || 'text-slate-400 bg-slate-800/30'

  return (
    <div className="rounded-lg bg-bg-tertiary border border-border p-3 text-sm">
      <div className="flex items-start gap-3">
        <span className="font-mono text-xs text-cyan-400 bg-cyan-950/40 border border-cyan-800/40 px-1.5 py-0.5 rounded flex-shrink-0">
          EV-{String(index).padStart(3, '0')}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="font-mono text-xs font-bold text-slate-300">
              {evidence.event?.event_type}
            </span>
            <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${roleClass}`}>{evidence.role}</span>
          </div>
          <p className="text-slate-400 text-xs">{evidence.description}</p>
          <div className="flex items-center gap-3 mt-1 text-xs text-slate-500 font-mono">
            <span>{evidence.event?.timestamp ? format(new Date(evidence.event.timestamp), 'HH:mm:ss') : ''} UTC</span>
            <span>src: {evidence.event?.source_ip}</span>
            {evidence.event?.username && <span>user: {evidence.event.username}</span>}
          </div>
          {expanded && evidence.event?.raw_log && (
            <div className="mt-2 p-2 rounded bg-bg-primary border border-border font-mono text-xs text-slate-400 break-all">
              {evidence.event.raw_log}
            </div>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-slate-600 hover:text-slate-400 transition-colors mt-1"
          >
            {expanded ? '▲ Hide raw log' : '▼ Show raw log'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function IncidentDetailPage({ params }: { params: { id: string } }) {
  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getIncident(params.id).then(setIncident).finally(() => setLoading(false))
  }, [params.id])

  const handleStatusChange = async (newStatus: string) => {
    if (!incident) return
    const updated = await updateIncidentStatus(params.id, newStatus)
    setIncident({ ...incident, status: updated.status })
  }

  if (loading) return (
    <div className="flex items-center justify-center h-screen">
      <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
    </div>
  )

  if (!incident) return (
    <div className="p-6 text-center text-slate-400">Incident not found</div>
  )

  const phases = incident.attack_hypothesis?.phases || []

  return (
    <div className="p-6 max-w-6xl mx-auto animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 mb-5">
        <Link href="/incidents" className="hover:text-slate-300 transition-colors flex items-center gap-1">
          <ChevronLeft className="w-4 h-4" /> Incidents
        </Link>
        <span>/</span>
        <span className="text-slate-300 truncate max-w-md">{incident.title}</span>
      </div>

      {/* Header */}
      <div className="card p-5 mb-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              <span className="text-xs text-slate-500 font-mono">{incident.id.slice(0, 8)}...</span>
            </div>
            <h1 className="text-xl font-bold text-white">{incident.title}</h1>
            {incident.attack_hypothesis?.narrative && (
              <p className="text-sm text-slate-400 mt-2 leading-relaxed max-w-2xl">
                {incident.attack_hypothesis.narrative}
              </p>
            )}
          </div>
          {/* Quick actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <Link href={`/incidents/${params.id}/chat`} className="btn-primary flex items-center gap-2">
              <MessageSquare className="w-4 h-4" />
              AI Investigate
            </Link>
            <Link href={`/incidents/${params.id}/report`} className="btn-ghost flex items-center gap-2">
              <FileText className="w-4 h-4" />
              Report
            </Link>
            <select
              className="input text-sm"
              value={incident.status}
              onChange={(e) => handleStatusChange(e.target.value)}
            >
              {['OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Meta stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pt-5 border-t border-border text-sm">
          <div>
            <div className="text-xs text-slate-500 mb-1 flex items-center gap-1"><User className="w-3 h-3" /> Target User</div>
            <div className="text-slate-200 font-mono text-sm">{incident.affected_username || '—'}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500 mb-1 flex items-center gap-1"><Wifi className="w-3 h-3" /> Attacker IP</div>
            <div className="text-slate-200 font-mono text-sm">{incident.source_ip || '—'}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500 mb-1 flex items-center gap-1"><Clock className="w-3 h-3" /> First Seen</div>
            <div className="text-slate-200 text-sm">{format(new Date(incident.first_seen), 'HH:mm:ss')} UTC</div>
          </div>
          <div>
            <div className="text-xs text-slate-500 mb-1 flex items-center gap-1"><Target className="w-3 h-3" /> Confidence</div>
            <div className="text-slate-200 text-sm">{Math.round(incident.confidence * 100)}%</div>
          </div>
        </div>
      </div>

      {/* MITRE Techniques */}
      {incident.techniques.length > 0 && (
        <div className="card p-4 mb-5">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-purple-400" /> MITRE ATT&CK Techniques
          </h2>
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Attack Timeline */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-5 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-accent-cyan" /> Attack Timeline
          </h2>
          {phases.length > 0 ? (
            <div className="relative">
              {phases.map((phase, i) => (
                <TimelineEntry key={i} phase={phase} entry="" index={i} />
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No timeline phases available</p>
          )}
        </div>

        {/* Evidence Panel */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Database className="w-4 h-4 text-accent-cyan" />
            Evidence ({incident.evidence.length} items)
          </h2>
          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
            {incident.evidence.length > 0 ? (
              incident.evidence.map((ev, i) => (
                <EvidenceCard key={ev.id} evidence={ev} index={i + 1} />
              ))
            ) : (
              <p className="text-slate-500 text-sm">No evidence items linked yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
