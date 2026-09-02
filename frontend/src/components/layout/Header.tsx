'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  LogOut,
  Radio,
  Search,
  Shield,
  User,
} from 'lucide-react'

import { getCurrentUser, getWazuhStatus, logout } from '@/lib/api'
import type { UserSession } from '@/lib/types'
import { RoleBadge } from '@/components/ui/badges'

export function Header() {
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

  const handleLogout = () => {
    logout()
    setUser(null)
    router.push('/login')
  }

  // Generate breadcrumbs
  const getBreadcrumbs = () => {
    if (pathname.startsWith('/dashboard')) {
      return [{ label: 'Operations' }, { label: 'Overview' }]
    }
    if (pathname.startsWith('/incidents')) {
      const parts = pathname.split('/').filter(Boolean)
      const crumbs = [{ label: 'Operations' }, { label: 'Incidents', href: '/incidents' }]
      if (parts.length >= 2) {
        crumbs.push({ label: parts[1].slice(0, 8), href: `/incidents/${parts[1]}` })
      }
      if (parts.includes('chat')) {
        crumbs.push({ label: 'AI Copilot' })
      } else if (parts.includes('report')) {
        crumbs.push({ label: 'Report' })
      }
      return crumbs
    }
    if (pathname.startsWith('/logs')) {
      return [{ label: 'Operations' }, { label: 'Events & Logs' }]
    }
    if (pathname.startsWith('/query')) {
      return [{ label: 'Intelligence' }, { label: 'AI Query' }]
    }
    if (pathname.startsWith('/playbooks')) {
      return [{ label: 'Intelligence' }, { label: 'Playbooks' }]
    }
    if (pathname.startsWith('/integrations')) {
      return [{ label: 'System' }, { label: 'Telemetry & Integrations' }]
    }
    if (pathname.startsWith('/upload-logs')) {
      return [{ label: 'System' }, { label: 'Upload Logs' }]
    }
    return [{ label: 'SOC' }, { label: 'Console' }]
  }

  const breadcrumbs = getBreadcrumbs()

  return (
    <header className="sticky top-0 z-10 flex h-14 w-full items-center justify-between border-b border-[#1f2937] bg-[#0b0f14]/90 px-6 backdrop-blur-md">
      {/* Left: Breadcrumbs */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-[#9ca3af]">
        {breadcrumbs.map((crumb, idx) => {
          const isLast = idx === breadcrumbs.length - 1
          return (
            <React.Fragment key={crumb.label}>
              {idx > 0 && <ChevronRight className="h-3.5 w-3.5 text-[#4b5563] shrink-0" />}
              {crumb.href && !isLast ? (
                <Link href={crumb.href} className="hover:text-[#f3f4f6] transition-colors">
                  {crumb.label}
                </Link>
              ) : (
                <span className={isLast ? 'font-medium text-[#f3f4f6]' : ''}>
                  {crumb.label}
                </span>
              )}
            </React.Fragment>
          )
        })}
      </nav>

      {/* Center: Global NLU Search Entry Point */}
      <div className="hidden md:flex items-center">
        <button
          type="button"
          onClick={() => router.push('/query')}
          className="flex items-center gap-2 rounded-lg border border-[#1f2937] bg-[#11161d] px-3 py-1.5 text-xs text-[#9ca3af] hover:border-[#374151] hover:text-[#f3f4f6] transition-colors"
        >
          <Search className="h-3.5 w-3.5 text-[#6b7280]" />
          <span>Ask SOC NLU (e.g. &ldquo;failed logins from IP&rdquo;)</span>
          <kbd className="ml-2 rounded border border-[#374151] bg-[#171e28] px-1.5 py-0.5 font-mono text-[10px] text-[#9ca3af]">
            Ctrl+K
          </kbd>
        </button>
      </div>

      {/* Right: Telemetry + User Session + Logout */}
      <div className="flex items-center gap-4">
        {/* Telemetry Indicator */}
        <Link
          href="/integrations/wazuh"
          title="Telemetry Integration Status"
          className="flex items-center gap-1.5 rounded-full border border-[#1f2937] bg-[#11161d] px-2.5 py-1 text-[11px] font-medium text-[#9ca3af] hover:border-[#374151] transition"
        >
          <span
            className={`h-2 w-2 rounded-full ${
              telemetryReady === true
                ? 'bg-[#10b981] animate-pulse'
                : telemetryReady === false
                ? 'bg-[#ef4444]'
                : 'bg-[#eab308]'
            }`}
          />
          <span>
            {telemetryReady === true
              ? 'Telemetry: OK'
              : telemetryReady === false
              ? 'Telemetry: Alert'
              : 'Telemetry: ...'}
          </span>
        </Link>

        {/* User Identity */}
        {user ? (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-lg border border-[#1f2937] bg-[#11161d] px-2.5 py-1 text-xs">
              <User className="h-3.5 w-3.5 text-[#9ca3af]" />
              <span className="font-mono text-[11px] text-[#f3f4f6]">{user.email}</span>
              <RoleBadge role={user.role} />
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              className="flex h-7 w-7 items-center justify-center rounded-lg border border-[#1f2937] bg-[#11161d] text-[#9ca3af] hover:border-[#ef4444]/40 hover:bg-[#450a0a]/30 hover:text-[#f87171] transition"
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
