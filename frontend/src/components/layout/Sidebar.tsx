'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { AlertTriangle, LayoutDashboard, Shield, Upload } from 'lucide-react'

const NAV_ITEMS = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/upload-logs', label: 'Upload Logs', icon: Upload },
]

export function Sidebar() {
  const pathname = usePathname()
  return (
    <aside className="fixed inset-y-0 left-0 z-20 flex w-64 flex-col border-r border-[#e6e8eb] bg-[#fafbfc]">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-[#e6e8eb]">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#cfe6d9] bg-[#f0f8f4] shrink-0">
          <Shield className="h-5 w-5 text-[#168a52]" />
        </div>
        <div>
          <span className="text-[15px] font-semibold tracking-tight text-[#111827] block leading-snug">SOC Investigator</span>
          <span className="text-[11px] font-medium text-[#667085] block">Security Operations</span>
        </div>
      </div>
      <nav className="px-3 pt-4" aria-label="Primary navigation">
        <div className="space-y-1">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(`${href}/`))
            return (
              <Link
                key={href}
                href={href}
                className={`relative flex items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-colors ${
                  active
                    ? 'bg-[#f0f8f4] text-[#168a52]'
                    : 'text-[#475467] hover:bg-white hover:text-[#111827]'
                }`}
              >
                {active && <span className="absolute inset-y-2 left-0 w-0.5 rounded-r bg-[#168a52]" />}
                <Icon className="h-4.5 w-4.5 shrink-0" />
                {label}
              </Link>
            )
          })}
        </div>
      </nav>
    </aside>
  )
}
