'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Database,
  LayoutDashboard,
  Lock,
  Shield,
  Terminal,
  Upload,
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
    title: 'Operations',
    items: [
      { href: '/dashboard', label: 'Overview', icon: LayoutDashboard },
      { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
      { href: '/logs', label: 'Events & Logs', icon: Database },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { href: '/query', label: 'AI Query', icon: Terminal },
      { href: '/playbooks', label: 'Playbooks', icon: BookOpen },
    ],
  },
  {
    title: 'System',
    items: [
      { href: '/integrations/wazuh', label: 'Telemetry & Wazuh', icon: Activity },
      { href: '/upload-logs', label: 'Upload Logs', icon: Upload },
    ],
  },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="fixed inset-y-0 left-0 z-20 flex w-64 flex-col border-r border-[#1f2937] bg-[#11161d]">
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1f2937]">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#10b981]/30 bg-[#10b981]/10 shrink-0">
          <Shield className="h-5 w-5 text-[#10b981]" />
        </div>
        <div>
          <span className="text-sm font-semibold tracking-tight text-[#f3f4f6] block leading-snug">
            SOC Investigator
          </span>
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#9ca3af] block">
            Enterprise SIEM
          </span>
        </div>
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6" aria-label="Primary navigation">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title}>
            <p className="px-3 text-[10px] font-mono font-semibold uppercase tracking-wider text-[#6b7280]">
              {section.title}
            </p>
            <div className="mt-1.5 space-y-1">
              {section.items.map(({ href, label, icon: Icon }) => {
                const active =
                  pathname === href ||
                  (href !== '/dashboard' && pathname.startsWith(`${href}/`))

                return (
                  <Link
                    key={href}
                    href={href}
                    className={`relative flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                      active
                        ? 'bg-[#171e28] text-[#10b981] font-semibold'
                        : 'text-[#9ca3af] hover:bg-[#171e28]/70 hover:text-[#f3f4f6]'
                    }`}
                  >
                    {active && (
                      <span className="absolute inset-y-1.5 left-0 w-1 rounded-r bg-[#10b981]" />
                    )}
                    <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-[#10b981]' : 'text-[#6b7280]'}`} />
                    <span>{label}</span>
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer Security Badge */}
      <div className="p-3 border-t border-[#1f2937] bg-[#0b0f14]/50">
        <div className="flex items-center justify-between px-2 py-1 text-[11px] font-mono text-[#6b7280]">
          <span className="flex items-center gap-1.5">
            <Lock className="h-3 w-3 text-[#10b981]" />
            RBAC Enforced
          </span>
          <span>v1.0-prod</span>
        </div>
      </div>
    </aside>
  )
}
