'use client'

import React from 'react'

/**
 * Enterprise SOC design-system primitives.
 *
 * Restrained, compact, information-dense building blocks styled after
 * Splunk ES / Microsoft Sentinel / Elastic Security. Severity color is used
 * only on indicators, never on whole rows or containers.
 */

/* -------------------------------------------------------------------------- */
/* Severity                                                                    */
/* -------------------------------------------------------------------------- */

const SEV = {
  CRITICAL: { label: 'Critical', color: '#ef4444', rank: 4 },
  HIGH: { label: 'High', color: '#f97316', rank: 3 },
  MEDIUM: { label: 'Medium', color: '#eab308', rank: 2 },
  LOW: { label: 'Low', color: '#38bdf8', rank: 1 },
  INFO: { label: 'Info', color: '#64748b', rank: 0 },
} as const

export type SevKey = keyof typeof SEV

export function sevKey(s: string | undefined): SevKey {
  const k = (s || 'INFO').toUpperCase()
  return (k in SEV ? k : 'INFO') as SevKey
}

export function severityColor(s: string | undefined): string {
  return SEV[sevKey(s)].color
}

export function severityRank(s: string | undefined): number {
  return SEV[sevKey(s)].rank
}

/**
 * Compact severity indicator: a small colored bar + uppercase label.
 * The vertical bar reads as a severity "rail" like enterprise consoles use.
 */
export function SeverityIndicator({
  severity,
  size = 'sm',
}: {
  severity: string
  size?: 'sm' | 'xs'
}) {
  const cfg = SEV[sevKey(severity)]
  return (
    <span className="inline-flex items-center gap-2">
      <span
        aria-hidden
        className="inline-block rounded-[1px]"
        style={{
          width: 3,
          height: size === 'xs' ? 12 : 14,
          background: cfg.color,
          boxShadow: `0 0 6px -1px ${cfg.color}80`,
        }}
      />
      <span
        className={`font-mono font-semibold uppercase tracking-wide ${
          size === 'xs' ? 'text-[10px]' : 'text-[11px]'
        }`}
        style={{ color: cfg.color }}
      >
        {cfg.label}
      </span>
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Status                                                                      */
/* -------------------------------------------------------------------------- */

const STATUS = {
  OPEN: { label: 'Open', color: '#eab308' },
  INVESTIGATING: { label: 'Investigating', color: '#60a5fa' },
  CLOSED: { label: 'Closed', color: '#34d399' },
  FALSE_POSITIVE: { label: 'False Positive', color: '#94a3b8' },
} as const

export function StatusIndicator({ status }: { status: string }) {
  const key = (status || 'OPEN').toUpperCase() as keyof typeof STATUS
  const cfg = STATUS[key] || STATUS.OPEN
  const pulse = key === 'OPEN' || key === 'INVESTIGATING'
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-medium text-ink-secondary">
      <span className="relative flex h-1.5 w-1.5">
        {pulse && (
          <span
            className="absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping"
            style={{ background: cfg.color }}
          />
        )}
        <span
          className="relative inline-flex h-1.5 w-1.5 rounded-full"
          style={{ background: cfg.color }}
        />
      </span>
      <span style={{ color: cfg.color }}>{cfg.label}</span>
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Confidence meter                                                            */
/* -------------------------------------------------------------------------- */

export function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round((value || 0) * 100)
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : pct >= 40 ? '#eab308' : '#64748b'
  return (
    <span className="inline-flex items-center gap-2" title={`${pct}% confidence`}>
      <span className="relative h-1 w-12 overflow-hidden rounded-full bg-[#0b0f14] ring-1 ring-inset ring-border/70">
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct}%`, background: color }} />
      </span>
      <span className="font-mono text-[11px] tabular-nums text-ink-secondary">{pct}%</span>
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Entity token (user / host / ip)                                             */
/* -------------------------------------------------------------------------- */

export function EntityToken({
  icon,
  value,
  tone = 'default',
  title,
}: {
  icon: React.ReactNode
  value: string
  tone?: 'user' | 'ip' | 'host' | 'default'
  title?: string
}) {
  const tones: Record<string, string> = {
    user: 'text-[#fcd34d]',
    ip: 'text-accent-cyan',
    host: 'text-ink-secondary',
    default: 'text-ink-secondary',
  }
  return (
    <span
      title={title || value}
      className={`inline-flex max-w-[160px] items-center gap-1.5 font-mono text-[11px] ${tones[tone]}`}
    >
      <span className="shrink-0 opacity-80">{icon}</span>
      <span className="truncate">{value}</span>
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Section header — open-workspace separator (not a card)                      */
/* -------------------------------------------------------------------------- */

export function SectionHeader({
  title,
  icon,
  count,
  hint,
  action,
}: {
  title: string
  icon?: React.ReactNode
  count?: React.ReactNode
  hint?: string
  action?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border pb-2">
      <div className="flex items-center gap-2">
        {icon && <span className="text-ink-muted">{icon}</span>}
        <h2 className="text-[13px] font-semibold tracking-tight text-ink-primary">{title}</h2>
        {count !== undefined && (
          <span className="rounded-sm border border-border bg-elevated px-1.5 py-px font-mono text-[10px] font-medium text-ink-secondary tabular-nums">
            {count}
          </span>
        )}
        {hint && <span className="font-mono text-[10px] text-ink-muted">{hint}</span>}
      </div>
      {action}
    </div>
  )
}
