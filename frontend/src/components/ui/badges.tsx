import type { Severity, IncidentStatus } from '@/lib/types'

interface SeverityBadgeProps {
  severity: Severity
  showDot?: boolean
}

const SEVERITY_CONFIG: Record<Severity, { label: string; className: string; dot: string }> = {
  CRITICAL: { label: 'CRITICAL', className: 'badge-critical', dot: 'bg-red-500' },
  HIGH:     { label: 'HIGH',     className: 'badge-high',     dot: 'bg-orange-500' },
  MEDIUM:   { label: 'MEDIUM',   className: 'badge-medium',   dot: 'bg-yellow-500' },
  LOW:      { label: 'LOW',      className: 'badge-low',      dot: 'bg-green-500' },
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
      <span className="w-1.5 h-1.5 rounded-full bg-purple-500" />
      <span className="font-bold">{techniqueId}</span>
      {techniqueName && <span className="text-purple-300/70">· {techniqueName}</span>}
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
  BRUTE_FORCE:                           { label: 'Brute Force', color: 'text-indigo-400' },
  ACCOUNT_COMPROMISE:                    { label: 'Account Compromise', color: 'text-red-400' },
  ACCOUNT_COMPROMISE_WITH_ESCALATION:    { label: 'Compromise + Escalation', color: 'text-rose-400' },
  PRIVILEGE_ESCALATION:                  { label: 'Privilege Escalation', color: 'text-orange-400' },
}

export function AttackTypeLabel({ attackType }: AttackTypeLabelProps) {
  const cfg = ATTACK_LABELS[attackType] || { label: attackType, color: 'text-slate-400' }
  return <span className={`text-sm font-medium ${cfg.color}`}>{cfg.label}</span>
}
