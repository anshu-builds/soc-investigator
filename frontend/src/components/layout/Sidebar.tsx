'use client'

import React from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Activity,
  AlertTriangle,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Database,
  LayoutDashboard,
  Lock,
  Shield,
  Terminal,
  Upload,
  X,
} from 'lucide-react'

interface NavSection {
  title: string
  items: {
    href: string
    label: string
    icon: React.ElementType
  }[]
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Command Center',
    items: [
      { href: '/dashboard', label: 'Overview', icon: LayoutDashboard },
      { href: '/incidents', label: 'Incident Queue', icon: AlertTriangle },
    ],
  },
  {
    title: 'Security Telemetry',
    items: [
      { href: '/logs', label: 'SIEM Event Explorer', icon: Database },
      { href: '/query', label: 'Query Studio', icon: Terminal },
      { href: '/upload-logs', label: 'Log Ingestion', icon: Upload },
    ],
  },
  {
    title: 'Investigation & Intel',
    items: [
      { href: '/playbooks', label: 'Response Playbooks', icon: BookOpen },
    ],
  },
  {
    title: 'System & Integrations',
    items: [
      { href: '/integrations/wazuh', label: 'Wazuh Telemetry', icon: Activity },
    ],
  },
]

interface SidebarProps {
  collapsed?: boolean
  onToggle?: () => void
  mobileOpen?: boolean
  onCloseMobile?: () => void
}

export function Sidebar({
  collapsed = false,
  onToggle,
  mobileOpen = false,
  onCloseMobile,
}: SidebarProps) {
  const pathname = usePathname()

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {mobileOpen && (
        <div
          role="presentation"
          onClick={onCloseMobile}
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden animate-fade-in"
        />
      )}

      {/* Main Sidebar Aside */}
      <aside
        aria-label="Enterprise Navigation"
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border bg-panel transition-all duration-200 ease-in-out ${
          collapsed ? 'w-16' : 'w-64'
        } ${
          mobileOpen
            ? 'translate-x-0 shadow-2xl'
            : '-translate-x-full md:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="flex h-14 items-center justify-between px-3.5 border-b border-border">
          <Link
            href="/dashboard"
            className="flex items-center gap-2.5 min-w-0 group"
            title="SOC Investigator"
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald transition-transform group-hover:scale-105">
              <Shield className="h-4 w-4" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <span className="text-xs font-bold tracking-tight text-ink-primary block leading-tight truncate">
                  SOC Investigator
                </span>
                <span className="text-[10px] font-mono uppercase tracking-wider text-ink-muted block truncate">
                  Enterprise SIEM
                </span>
              </div>
            )}
          </Link>

          {/* Mobile Close Button */}
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Close mobile navigation"
            className="md:hidden flex h-7 w-7 items-center justify-center rounded-lg text-ink-muted hover:text-ink-primary hover:bg-elevated transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Navigation Sections */}
        <nav
          className="flex-1 overflow-y-auto overflow-x-hidden p-2.5 space-y-5"
          aria-label="Primary navigation"
        >
          {NAV_SECTIONS.map((section) => (
            <div key={section.title} className="space-y-1">
              {!collapsed ? (
                <p className="px-2.5 text-[10px] font-sans font-medium uppercase tracking-wider text-ink-muted/60">
                  {section.title}
                </p>
              ) : (
                <div className="h-px w-6 mx-auto my-2 bg-border-subtle" />
              )}

              <div className="space-y-0.5">
                {section.items.map(({ href, label, icon: Icon }) => {
                  const active =
                    pathname === href ||
                    (href !== '/dashboard' && pathname.startsWith(`${href}/`))

                  return (
                    <Link
                      key={href}
                      href={href}
                      title={collapsed ? label : undefined}
                      aria-current={active ? 'page' : undefined}
                      onClick={() => onCloseMobile?.()}
                      className={`group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-xs transition-colors ${
                        active
                          ? 'bg-elevated text-ink-primary font-medium'
                          : 'text-ink-secondary hover:bg-elevated/40 hover:text-ink-primary font-normal'
                      } ${collapsed ? 'justify-center' : ''}`}
                    >
                      {active && (
                        <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-r bg-accent-emerald" />
                      )}
                      <Icon
                        className={`h-4 w-4 shrink-0 transition-colors ${
                          active
                            ? 'text-accent-emerald'
                            : 'text-ink-muted group-hover:text-ink-secondary'
                        }`}
                      />
                      {!collapsed && <span className="truncate">{label}</span>}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer Security Badge & Collapse Toggle */}
        <div className="p-2.5 border-t border-border bg-canvas/40 flex items-center justify-between">
          {!collapsed ? (
            <div className="flex items-center justify-between w-full px-1 text-[10px] font-mono text-ink-muted">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3 w-3 text-accent-emerald" />
                RBAC Enforced
              </span>
              <span>v1.0-prod</span>
            </div>
          ) : (
            <div
              className="mx-auto flex h-6 w-6 items-center justify-center text-accent-emerald"
              title="RBAC Enforced"
            >
              <Lock className="h-3 w-3" />
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
