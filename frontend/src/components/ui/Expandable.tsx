'use client'

import React, { useState } from 'react'
import { ChevronDown } from 'lucide-react'

interface ExpandableProps {
  title: React.ReactNode
  subtitle?: React.ReactNode
  badge?: React.ReactNode
  defaultOpen?: boolean
  children: React.ReactNode
  className?: string
  headerClassName?: string
}

export function Expandable({
  title,
  subtitle,
  badge,
  defaultOpen = false,
  children,
  className = '',
  headerClassName = '',
}: ExpandableProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className={`card overflow-hidden transition-colors ${className}`}>
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between p-4 text-left hover:bg-elevated/40 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-emerald/40 ${headerClassName}`}
      >
        <div className="flex items-center gap-3 min-w-0 pr-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-ink-primary truncate">{title}</span>
              {badge}
            </div>
            {subtitle && (
              <p className="mt-0.5 text-[11px] text-ink-secondary truncate">{subtitle}</p>
            )}
          </div>
        </div>
        <ChevronDown
          className={`h-4 w-4 text-ink-muted shrink-0 transition-transform duration-200 ${
            isOpen ? 'rotate-180 text-ink-primary' : ''
          }`}
        />
      </button>

      {isOpen && (
        <div role="region" className="border-t border-border-subtle p-4 bg-canvas/30 animate-fade-in">
          {children}
        </div>
      )}
    </div>
  )
}
