'use client'

import React, { createContext, useCallback, useContext, useId, useState } from 'react'
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from 'lucide-react'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastItem {
  id: string
  title: string
  description?: string
  type: ToastType
  duration?: number
}

interface ToastContextValue {
  toast: (options: { title: string; description?: string; type?: ToastType; duration?: number }) => void
  success: (title: string, description?: string) => void
  error: (title: string, description?: string) => void
  warning: (title: string, description?: string) => void
  info: (title: string, description?: string) => void
  dismiss: (id: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

const TOAST_ICONS: Record<ToastType, React.ElementType> = {
  success: CheckCircle2,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
}

const TOAST_STYLES: Record<ToastType, { border: string; bg: string; icon: string }> = {
  success: {
    border: 'border-[#064e3b]',
    bg: 'bg-[#022c22]/95',
    icon: 'text-[#34d399]',
  },
  error: {
    border: 'border-[#7f1d1d]',
    bg: 'bg-[#450a0a]/95',
    icon: 'text-[#f87171]',
  },
  warning: {
    border: 'border-[#713f12]',
    bg: 'bg-[#422006]/95',
    icon: 'text-[#facc15]',
  },
  info: {
    border: 'border-border',
    bg: 'bg-elevated/95',
    icon: 'text-[#38bdf8]',
  },
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = useCallback(
    ({
      title,
      description,
      type = 'info',
      duration = 4000,
    }: {
      title: string
      description?: string
      type?: ToastType
      duration?: number
    }) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const item: ToastItem = { id, title, description, type, duration }

      setToasts((prev) => [...prev.slice(-4), item]) // keep max 5 visible toasts

      if (duration > 0) {
        setTimeout(() => {
          dismiss(id)
        }, duration)
      }
    },
    [dismiss]
  )

  const success = useCallback(
    (title: string, description?: string) => toast({ title, description, type: 'success' }),
    [toast]
  )
  const error = useCallback(
    (title: string, description?: string) => toast({ title, description, type: 'error' }),
    [toast]
  )
  const warning = useCallback(
    (title: string, description?: string) => toast({ title, description, type: 'warning' }),
    [toast]
  )
  const info = useCallback(
    (title: string, description?: string) => toast({ title, description, type: 'info' }),
    [toast]
  )

  return (
    <ToastContext.Provider value={{ toast, success, error, warning, info, dismiss }}>
      {children}

      {/* Floating Toast Viewport */}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex max-w-sm w-full flex-col gap-2"
      >
        {toasts.map((t) => {
          const Icon = TOAST_ICONS[t.type]
          const style = TOAST_STYLES[t.type]

          return (
            <div
              key={t.id}
              role={t.type === 'error' ? 'alert' : 'status'}
              className={`pointer-events-auto flex items-start gap-3 rounded-xl border ${style.border} ${style.bg} p-3.5 shadow-2xl backdrop-blur-md animate-slide-in transition-all duration-150`}
            >
              <Icon className={`h-4 w-4 shrink-0 mt-0.5 ${style.icon}`} />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-ink-primary leading-snug">{t.title}</p>
                {t.description && (
                  <p className="mt-0.5 text-[11px] text-ink-secondary leading-relaxed break-words">
                    {t.description}
                  </p>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
                className="text-ink-muted hover:text-ink-primary transition p-0.5 rounded"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return ctx
}
