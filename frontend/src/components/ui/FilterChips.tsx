'use client'

import React from 'react'
import { Filter, X } from 'lucide-react'

export interface ActiveFilterItem {
  id: string
  label: string
  value: string
  onRemove: () => void
}

interface ActiveFiltersProps {
  filters: ActiveFilterItem[]
  onClearAll?: () => void
  className?: string
}

export function FilterChip({
  label,
  value,
  onRemove,
}: {
  label: string
  value: string
  onRemove: () => void
}) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-elevated pl-2 pr-1 py-0.5 text-[11px] font-mono text-ink-secondary animate-scale-in">
      <span className="text-ink-muted">{label}:</span>
      <span className="font-semibold text-ink-primary">{value}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove filter for ${label}`}
        className="rounded p-0.5 text-ink-muted hover:bg-highlight hover:text-ink-primary transition focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-emerald"
      >
        <X className="h-3 w-3" />
      </button>
    </span>
  )
}

export function ActiveFilters({ filters, onClearAll, className = '' }: ActiveFiltersProps) {
  if (filters.length === 0) return null

  return (
    <div className={`flex flex-wrap items-center gap-2 pt-2 animate-fade-in ${className}`}>
      <span className="flex items-center gap-1 text-[11px] font-mono text-ink-muted uppercase tracking-wider">
        <Filter className="h-3 w-3" /> Active Filters:
      </span>
      {filters.map((f) => (
        <FilterChip key={f.id} label={f.label} value={f.value} onRemove={f.onRemove} />
      ))}
      {onClearAll && filters.length > 1 && (
        <button
          type="button"
          onClick={onClearAll}
          className="text-[11px] font-mono text-accent-emerald hover:underline hover:text-accent-dark ml-1 transition"
        >
          Clear all
        </button>
      )}
    </div>
  )
}
