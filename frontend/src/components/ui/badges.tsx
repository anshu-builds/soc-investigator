import React from 'react'
import type { Severity, IncidentStatus } from '@/lib/types'

interface SeverityBadgeProps {
  severity: Severity | string
  showDot?: boolean
  className?: string
}

const SEVERITY_CONFIG: Record<string, { label: string; className: string; dot: string }> = {
  CRITICAL: { label: 'CRITICAL', className: 'badge-critical', dot: 'bg-[#ef4444]' },
  HIGH:     { label: 'HIGH',     className: 'badge-high',     dot: 'bg-[#f97316]' },
  MEDIUM:   { label: 'MEDIUM',   className: 'badge-medium',   dot: 'bg-[#eab308]' },
  LOW:      { label: 'LOW',      className: 'badge-low',      dot: 'bg-[#64748b]' },
}

export function SeverityBadge({ severity, showDot = true, className = '' }: SeverityBadgeProps) {
  const norm = (severity || 'LOW').toUpperCase()
  const cfg = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.LOW
  return (
    <span className={`${cfg.className} ${className}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />}
      {cfg.label}
    </span>
  )
}

interface StatusBadgeProps {
  status: IncidentStatus | string
  className?: string
}

const STATUS_CONFIG: Record<string, { label: string; className: string; dot: string }> = {
  OPEN:           { label: 'OPEN',           className: 'status-open',           dot: 'bg-[#eab308]' },
  INVESTIGATING:  { label: 'INVESTIGATING',  className: 'status-investigating',  dot: 'bg-[#3b82f6]' },
  CLOSED:         { label: 'CLOSED',         className: 'status-closed',         dot: 'bg-[#10b981]' },
  FALSE_POSITIVE: { label: 'FALSE POSITIVE', className: 'status-false_positive', dot: 'bg-[#64748b]' },
}

export function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const norm = (status || 'OPEN').toUpperCase()
  const cfg = STATUS_CONFIG[norm] || STATUS_CONFIG.OPEN
  return (
    <span className={`inline-flex items-center gap-1.5 ${cfg.className} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

interface MitreTechniqueChipProps {
  techniqueId: string
  techniqueName?: string
  url?: string
}

export function MitreTechniqueChip({ techniqueId, techniqueName, url }: MitreTechniqueChipProps) {
  const content = (
    <span className="mitre-chip gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-[#c084fc]" />
      <span className="font-bold">{techniqueId}</span>
      {techniqueName && <span className="text-[#d8b4fe]">· {techniqueName}</span>}
    </span>
  )

  if (url) {
    return (
      <a href={url} target="_blank" rel="noopener noreferrer" className="hover:opacity-80 transition-opacity">
        {content}
      </a>
    )
  }
  return content
}

interface AttackTypeLabelProps {
  attackType: string
  className?: string
}

const ATTACK_LABELS: Record<string, { label: string; color: string }> = {
  BRUTE_FORCE:                        { label: 'Brute Force', color: 'text-[#fca5a5]' },
  ACCOUNT_COMPROMISE:                 { label: 'Account Compromise', color: 'text-[#fdba74]' },
  ACCOUNT_COMPROMISE_WITH_ESCALATION: { label: 'Compromise + Escalation', color: 'text-[#f472b6]' },
  PRIVILEGE_ESCALATION:               { label: 'Privilege Escalation', color: 'text-[#facc15]' },
}

export function AttackTypeLabel({ attackType, className = '' }: AttackTypeLabelProps) {
  const cfg = ATTACK_LABELS[attackType] || { label: attackType.replace(/_/g, ' '), color: 'text-[#9ca3af]' }
  return <span className={`text-xs font-medium ${cfg.color} ${className}`}>{cfg.label}</span>
}

export function RoleBadge({ role }: { role?: string }) {
  const r = (role || 'analyst').toUpperCase()
  if (r === 'ADMIN') {
    return (
      <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider border border-[#7f1d1d] bg-[#450a0a] text-[#f87171]">
        ADMIN
      </span>
    )
  }
  if (r === 'LEAD_ANALYST') {
    return (
      <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider border border-[#1e3a8a] bg-[#172554] text-[#60a5fa]">
        LEAD
      </span>
    )
  }
  return (
    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider border border-[#374151] bg-[#171e28] text-[#9ca3af]">
      ANALYST
    </span>
  )
}

export function EvidenceChip({ id, onClick }: { id: string; onClick?: () => void }) {
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="evidence-chip hover:opacity-80 transition cursor-pointer"
      >
        {id}
      </button>
    )
  }
  return <span className="evidence-chip">{id}</span>
}
