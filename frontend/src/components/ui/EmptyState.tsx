import React from 'react'
import Link from 'next/link'
import { AlertCircle } from 'lucide-react'

interface EmptyStateProps {
  icon?: React.ElementType
  title: string
  description: string
  actionLabel?: string
  actionHref?: string
  onAction?: () => void
  className?: string
}

export function EmptyState({
  icon: Icon = AlertCircle,
  title,
  description,
  actionLabel,
  actionHref,
  onAction,
  className = '',
}: EmptyStateProps) {
  return (
    <div className={`card flex flex-col items-center justify-center p-12 text-center ${className}`}>
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-[#1f2937] bg-[#171e28] text-[#9ca3af]">
        <Icon className="h-6 w-6 text-[#9ca3af]" />
      </div>
      <h3 className="mt-4 text-base font-semibold text-[#f3f4f6]">{title}</h3>
      <p className="mt-1.5 max-w-sm text-sm text-[#9ca3af]">{description}</p>
      {actionLabel && actionHref && (
        <Link href={actionHref} className="btn-primary mt-5">
          {actionLabel}
        </Link>
      )}
      {actionLabel && onAction && !actionHref && (
        <button type="button" onClick={onAction} className="btn-primary mt-5">
          {actionLabel}
        </button>
      )}
    </div>
  )
}
