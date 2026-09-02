'use client'

import React from 'react'
import { AlertCircle, Bot, Check, Loader2, RefreshCw, Sparkles } from 'lucide-react'

export type AiState = 'idle' | 'thinking' | 'generating' | 'completed' | 'error' | 'retrying'

interface AiStatusIndicatorProps {
  state: AiState
  label?: string
  className?: string
}

export function AiStatusIndicator({ state, label, className = '' }: AiStatusIndicatorProps) {
  if (state === 'idle') return null

  if (state === 'thinking') {
    return (
      <div
        role="status"
        aria-label="AI Copilot is analyzing evidence"
        className={`inline-flex items-center gap-2 rounded-full border border-accent-cyan/30 bg-accent-cyan/10 px-2.5 py-1 text-xs font-mono text-accent-cyan animate-fade-in ${className}`}
      >
        <Sparkles className="h-3.5 w-3.5 animate-pulse" />
        <span>{label || 'Analyzing evidence'}</span>
        <span className="flex gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-accent-cyan typing-dot" style={{ animationDelay: '0ms' }} />
          <span className="h-1.5 w-1.5 rounded-full bg-accent-cyan typing-dot" style={{ animationDelay: '200ms' }} />
          <span className="h-1.5 w-1.5 rounded-full bg-accent-cyan typing-dot" style={{ animationDelay: '400ms' }} />
        </span>
      </div>
    )
  }

  if (state === 'generating') {
    return (
      <div
        role="status"
        aria-label="AI Copilot is generating response"
        className={`inline-flex items-center gap-2 rounded-full border border-accent-emerald/30 bg-accent-emerald/10 px-2.5 py-1 text-xs font-mono text-accent-emerald animate-fade-in ${className}`}
      >
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        <span>{label || 'Synthesizing investigation findings…'}</span>
      </div>
    )
  }

  if (state === 'retrying') {
    return (
      <div
        role="status"
        className={`inline-flex items-center gap-2 rounded-full border border-severity-medium/30 bg-severity-medium/10 px-2.5 py-1 text-xs font-mono text-severity-medium animate-fade-in ${className}`}
      >
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
        <span>{label || 'Retrying query…'}</span>
      </div>
    )
  }

  if (state === 'error') {
    return (
      <div
        role="alert"
        className={`inline-flex items-center gap-1.5 rounded-full border border-severity-critical/30 bg-severity-critical/10 px-2.5 py-1 text-xs font-mono text-severity-critical animate-fade-in ${className}`}
      >
        <AlertCircle className="h-3.5 w-3.5" />
        <span>{label || 'Investigation error'}</span>
      </div>
    )
  }

  if (state === 'completed') {
    return (
      <div
        role="status"
        className={`inline-flex items-center gap-1.5 rounded-full border border-border bg-elevated px-2 py-0.5 text-[11px] font-mono text-ink-muted animate-fade-in ${className}`}
      >
        <Check className="h-3 w-3 text-accent-emerald" />
        <span>{label || 'Analysis complete'}</span>
      </div>
    )
  }

  return null
}
