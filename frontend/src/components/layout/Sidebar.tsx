'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  Shield, LayoutDashboard, AlertTriangle, Upload,
  MessageSquare, LogOut, ChevronRight, Zap
} from 'lucide-react'

const NAV_ITEMS = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/logs', label: 'Upload Logs', icon: Upload },
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const [currentTime, setCurrentTime] = useState('')

  useEffect(() => {
    const tick = () => setCurrentTime(new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC')
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('soc_token')
    router.push('/login')
  }

  return (
    <aside className="w-64 min-h-screen bg-bg-secondary border-r border-border flex flex-col">
      {/* Header */}
      <div className="p-5 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-glow-sm">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-white text-glow-cyan">SOC Investigator</div>
            <div className="text-xs text-slate-500">PS 114</div>
          </div>
        </div>
        {/* Live clock */}
        <div className="mt-3 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse-slow" />
          <span className="text-xs font-mono text-slate-500">{currentTime}</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const isActive = pathname.startsWith(href)
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group ${
                isActive
                  ? 'bg-accent-blue/15 text-accent-cyan border border-accent-blue/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-bg-hover'
              }`}
            >
              <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-accent-cyan' : 'text-slate-500 group-hover:text-slate-300'}`} />
              {label}
              {isActive && <ChevronRight className="ml-auto w-3 h-3 text-accent-cyan" />}
            </Link>
          )
        })}
      </nav>

      {/* Threat Level Indicator */}
      <div className="mx-3 mb-3 p-3 rounded-lg bg-bg-tertiary border border-border">
        <div className="flex items-center gap-2 mb-2">
          <Zap className="w-3 h-3 text-yellow-400" />
          <span className="text-xs text-slate-400 font-medium">System Status</span>
        </div>
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-500">Detection Engine</span>
          <span className="text-green-400 font-medium">ACTIVE</span>
        </div>
        <div className="flex items-center justify-between text-xs mt-1">
          <span className="text-slate-500">AI Layer</span>
          <span className="text-green-400 font-medium">ONLINE</span>
        </div>
      </div>

      {/* Logout */}
      <div className="p-3 border-t border-border">
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-400 hover:text-red-400 hover:bg-red-950/20 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  )
}
