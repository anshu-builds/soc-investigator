'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  ChevronRight,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  Search,
  Shield,
  User,
} from 'lucide-react'

import { getCurrentUser, getWazuhStatus, logout } from '@/lib/api'
import type { UserSession } from '@/lib/types'
import { RoleBadge } from '@/components/ui/badges'

interface HeaderProps {
  collapsed?: boolean
  onToggleSidebar?: () => void
  onOpenMobile?: () => void
}

export function Header({
  collapsed = false,
  onToggleSidebar,
  onOpenMobile,
}: HeaderProps) {
  const pathname = usePathname()
  const router = useRouter()
  const [user, setUser] = useState<UserSession | null>(null)
  const [telemetryReady, setTelemetryReady] = useState<boolean | null>(null)

  useEffect(() => {
    setUser(getCurrentUser())

    // Check telemetry status
    getWazuhStatus()
      .then((res) => setTelemetryReady(res.status === 'ready'))
      .catch(() => setTelemetryReady(false))
  }, [pathname])

  // Global Ctrl+K / Cmd+K shortcut to open NLU Query Studio
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        router.push('/query')
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [router])

  const handleLogout = () => {
    logout()
    setUser(null)
    router.push('/login')
  }

  // Generate contextual SOC breadcrumbs
  const getBreadcrumbs = () => {
    if (pathname.startsWith('/dashboard')) {
      return [{ label: 'Command Center' }, { label: 'Overview' }]
    }
    if (pathname.startsWith('/incidents')) {
      const parts = pathname.split('/').filter(Boolean)
      const crumbs = [{ label: 'Command Center' }, { label: 'Incident Queue', href: '/incidents' }]
      if (parts.length >= 2) {
        crumbs.push({ label: `Incident #${parts[1].slice(0, 8)}`, href: `/incidents/${parts[1]}` })
      }
      if (parts.includes('chat')) {
        crumbs.push({ label: 'AI Copilot' })
      } else if (parts.includes('report')) {
        crumbs.push({ label: 'Formal Report' })
      }
      return crumbs
    }
    if (pathname.startsWith('/logs')) {
      return [{ label: 'Security Telemetry' }, { label: 'SIEM Event Explorer' }]
    }
    if (pathname.startsWith('/query')) {
      return [{ label: 'Security Telemetry' }, { label: 'Query Studio' }]
    }
    if (pathname.startsWith('/upload-logs')) {
      return [{ label: 'Security Telemetry' }, { label: 'Log Ingestion' }]
    }
    if (pathname.startsWith('/playbooks')) {
      return [{ label: 'Investigation & Intel' }, { label: 'Response Playbooks' }]
    }
    if (pathname.startsWith('/integrations')) {
      return [{ label: 'System & Integrations' }, { label: 'Wazuh Telemetry' }]
    }
    return [{ label: 'SOC' }, { label: 'Console' }]
  }

  const breadcrumbs = getBreadcrumbs()

  return (
    <header className="sticky top-0 z-20 flex h-14 w-full items-center justify-between border-b border-border bg-canvas/90 px-4 md:px-6 backdrop-blur-md transition-colors">
      {/* Left: Sidebar Toggle + Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Desktop Sidebar Collapse Button */}
        <button
          type="button"
          onClick={onToggleSidebar}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="hidden md:flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-elevated text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95 shrink-0"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </button>

        {/* Mobile Sidebar Hamburger Button */}
        <button
          type="button"
          onClick={onOpenMobile}
          aria-label="Open navigation drawer"
          className="md:hidden flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-elevated text-ink-secondary hover:text-ink-primary hover:border-border-active transition active:scale-95 shrink-0"
        >
          <Menu className="h-4 w-4" />
        </button>

        {/* Contextual Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-ink-secondary truncate">
          {breadcrumbs.map((crumb, idx) => {
            const isLast = idx === breadcrumbs.length - 1
            return (
              <React.Fragment key={crumb.label}>
                {idx > 0 && <ChevronRight className="h-3 w-3 text-ink-muted shrink-0" />}
                {crumb.href && !isLast ? (
                  <Link href={crumb.href} className="hover:text-ink-primary transition-colors truncate">
                    {crumb.label}
                  </Link>
                ) : (
                  <span className={isLast ? 'font-semibold text-ink-primary truncate' : 'truncate text-ink-muted'}>
                    {crumb.label}
                  </span>
                )}
              </React.Fragment>
            )
          })}
        </nav>
      </div>

      {/* Center: Global NLU Search Entry Point (desktop only) */}
      <div className="hidden lg:flex items-center">
        <button
          type="button"
          onClick={() => router.push('/query')}
          className="flex items-center gap-2 rounded-md border border-border/80 bg-panel px-3 py-1.5 text-xs text-ink-secondary hover:border-border-active hover:text-ink-primary transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-emerald"
        >
          <Search className="h-3.5 w-3.5 text-ink-muted" />
          <span>Ask SOC NLU (e.g. &ldquo;failed logins from IP&rdquo;)</span>
          <kbd className="ml-2 rounded border border-border bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
            Ctrl+K
          </kbd>
        </button>
      </div>

      {/* Right: Telemetry Status + User Session + Logout */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Live Telemetry Health Indicator */}
        <Link
          href="/integrations/wazuh"
          title="Telemetry Integration Posture"
          className="flex items-center gap-1.5 rounded border border-border/80 bg-panel/60 px-2 py-1 text-[11px] font-sans text-ink-muted hover:text-ink-secondary hover:border-border-active transition-colors"
        >
          <span
            className={`h-1.5 w-1.5 rounded-full shrink-0 ${
              telemetryReady === true
                ? 'bg-accent-emerald'
                : telemetryReady === false
                ? 'bg-severity-critical'
                : 'bg-severity-medium'
            }`}
          />
          <span className="hidden sm:inline text-[11px]">
            {telemetryReady === true
              ? 'Wazuh Online'
              : telemetryReady === false
              ? 'Wazuh Alert'
              : 'Wazuh…'}
          </span>
        </Link>

        {/* User Identity & Logout */}
        {user ? (
          <div className="flex items-center gap-1.5">
            <div className="flex items-center gap-2 rounded border border-border/80 bg-panel/60 px-2 py-1 text-xs">
              <User className="h-3.5 w-3.5 text-ink-muted" />
              <span className="hidden sm:inline font-mono text-[11px] text-ink-secondary max-w-[140px] truncate">
                {user.email}
              </span>
              <RoleBadge role={user.role} />
            </div>
            <button
              onClick={handleLogout}
              title="Sign out of SOC console"
              aria-label="Sign out"
              className="flex h-7 w-7 items-center justify-center rounded border border-border/80 bg-panel/60 text-ink-muted hover:border-severity-critical/40 hover:bg-[#450a0a]/20 hover:text-severity-critical transition-colors active:scale-95"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <Link href="/login" className="btn-primary text-xs py-1 px-3">
            Sign In
          </Link>
        )}
      </div>
    </header>
  )
}
