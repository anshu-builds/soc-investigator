import type { Severity, IncidentStatus } from '@/lib/types'

interface SeverityBadgeProps {
  severity: Severity
  showDot?: boolean
}

const SEVERITY_CONFIG: Record<Severity, { label: string; className: string; dot: string }> = {
  CRITICAL: { label: 'CRITICAL', className: 'badge-critical', dot: 'bg-[#dc2626]' },
  HIGH:     { label: 'HIGH',     className: 'badge-high',     dot: 'bg-[#ea580c]' },
  MEDIUM:   { label: 'MEDIUM',   className: 'badge-medium',   dot: 'bg-[#d97706]' },
  LOW:      { label: 'LOW',      className: 'badge-low',      dot: 'bg-[#64748b]' },
}

export function SeverityBadge({ severity, showDot = true }: SeverityBadgeProps) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.LOW
  return (
    <span className={cfg.className}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />}
      {cfg.label}
    </span>
  )
}

interface StatusBadgeProps {
  status: IncidentStatus
}

const STATUS_CONFIG: Record<IncidentStatus, { label: string; className: string }> = {
  OPEN:          { label: 'OPEN',          className: 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border status-open' },
  INVESTIGATING: { label: 'INVESTIGATING', className: 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border status-investigating' },
  CLOSED:        { label: 'CLOSED',        className: 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border status-closed' },
  FALSE_POSITIVE:{ label: 'FALSE POSITIVE', className: 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border status-false_positive' },
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.OPEN
  return <span className={cfg.className}>{cfg.label}</span>
}

interface MitreTechniqueChipProps {
  techniqueId: string
  techniqueName?: string
  url?: string
}

export function MitreTechniqueChip({ techniqueId, techniqueName, url }: MitreTechniqueChipProps) {
  const content = (
    <span className="mitre-chip gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-[#7c3aed]" />
      <span className="font-bold">{techniqueId}</span>
      {techniqueName && <span className="text-[#6d5a9e]">· {techniqueName}</span>}
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
}

const ATTACK_LABELS: Record<string, { label: string; color: string }> = {
  BRUTE_FORCE:                           { label: 'Brute Force', color: 'text-[#475467]' },
  ACCOUNT_COMPROMISE:                    { label: 'Account Compromise', color: 'text-[#475467]' },
  ACCOUNT_COMPROMISE_WITH_ESCALATION:    { label: 'Compromise + Escalation', color: 'text-[#475467]' },
  PRIVILEGE_ESCALATION:                  { label: 'Privilege Escalation', color: 'text-[#475467]' },
}

export function AttackTypeLabel({ attackType }: AttackTypeLabelProps) {
  const cfg = ATTACK_LABELS[attackType] || { label: attackType, color: 'text-[#667085]' }
  return <span className={`text-xs ${cfg.color}`}>{cfg.label}</span>
}
