'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  Shield,
  Sun,
  Moon,
  LayoutDashboard,
  AlertTriangle,
  Upload,
  LogOut,
  ChevronRight,
  Zap,
  Activity,
  User
} from 'lucide-react'

const NAV_ITEMS = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/upload-logs', label: 'Upload Logs', icon: Upload },
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const [currentTime, setCurrentTime] = useState('')
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  useEffect(() => {
    const tick = () => {
      setCurrentTime(
        new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
      )
    }

    tick()
    const id = setInterval(tick, 1000)

    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const savedTheme = localStorage.getItem('soc_theme')
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    const initialTheme = savedTheme === 'light' || savedTheme === 'dark'
      ? savedTheme
      : (prefersDark ? 'dark' : 'light')

    setTheme(initialTheme)
  }, [])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('soc_theme', theme)
  }, [theme])

  const handleLogout = () => {
    localStorage.removeItem('soc_token')
    router.push('/login')
  }

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

  return (
    <aside className="fixed left-0 top-0 z-20 flex h-screen w-[280px] flex-col border-r border-black/10 bg-white/55 text-ink shadow-[12px_0_40px_rgba(65,105,83,0.12)] backdrop-blur-2xl dark:border-white/10 dark:bg-[#111b18]/80 dark:text-white dark:shadow-[12px_0_40px_rgba(0,0,0,0.35)]">

      {/* ================= HEADER ================= */}
      <div className="border-b border-black/10 px-5 pb-5 pt-6 dark:border-white/10">

        <div className="mb-4 flex items-center justify-end">
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex items-center gap-2 rounded-lg border border-black/10 bg-white/70 px-2.5 py-1.5 text-[11px] font-medium text-slate-600 transition-colors hover:border-jade hover:text-ink dark:border-white/15 dark:bg-black/20 dark:text-slate-300 dark:hover:text-white"
            aria-label="Toggle theme"
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
            <span>{theme === 'dark' ? 'Light' : 'Dark'} Mode</span>
          </button>
        </div>

        <div className="flex items-center gap-3">

          {/* Logo */}
          <div className="relative">
            <div className="absolute inset-0 rounded-xl bg-jade/35 blur-lg" />

            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-jade/50 bg-gradient-to-br from-jade to-sage shadow-[0_0_25px_rgba(127,191,154,0.28)]">
              <Shield className="h-6 w-6 text-ink" />
            </div>
          </div>

          {/* Brand */}
          <div>
            <div className="text-[15px] font-bold tracking-wide text-ink">
              SOC Investigator
            </div>

            <div className="flex items-center gap-1.5 mt-1">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-jade">
                PS 114
              </span>

              <span className="h-1 w-1 rounded-full bg-jade" />

              <span className="text-[10px] uppercase tracking-wider text-slate-500">
                Security
              </span>
            </div>
          </div>
        </div>

        {/* Live Clock */}
        <div className="mt-5 flex items-center justify-between rounded-xl border border-black/10 bg-white/55 px-3 py-2.5 shadow-sm dark:border-white/10 dark:bg-white/5">

          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full rounded-full bg-green-500 opacity-50 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500" />
            </span>

            <span className="text-[10px] uppercase tracking-wider text-slate-500">
              Live
            </span>
          </div>

          <span className="font-mono text-[10px] text-slate-600">
            {currentTime}
          </span>
        </div>
      </div>

      {/* ================= NAVIGATION ================= */}
      <nav className="flex-1 px-3 py-6">

        <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">
          Operations
        </div>

        <div className="space-y-1.5">

          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {

            const isActive = pathname.startsWith(href)

            return (
              <Link
                key={href}
                href={href}
                className={`
                  group relative flex items-center gap-3
                  px-3.5 py-3 rounded-lg
                  text-sm font-medium
                  transition-all duration-200
                  overflow-hidden

                  ${
                    isActive
                      ? `
                        bg-jade/20
                        text-ink
                        border border-jade/45
                        shadow-[0_0_20px_rgba(127,191,154,0.14)]
                      `
                      : `
                        text-slate-600
                        border border-transparent
                        hover:text-ink
                        hover:bg-white/55
                        hover:border-black/10
                      `
                  }
                `}
              >

                {/* Active red line */}
                {isActive && (
                  <span className="absolute bottom-2 left-0 top-2 w-[3px] rounded-r-full bg-jade shadow-[0_0_10px_rgba(127,191,154,0.8)]" />
                )}

                {/* Icon */}
                <Icon
                  className={`
                    w-[18px] h-[18px] flex-shrink-0
                    transition-all duration-200

                    ${
                      isActive
                        ? 'text-jade'
                        : 'text-slate-500 group-hover:text-ink'
                    }
                  `}
                />

                {/* Label */}
                <span>{label}</span>

                {/* Active Arrow */}
                {isActive && (
                  <ChevronRight className="ml-auto h-4 w-4 text-jade" />
                )}
              </Link>
            )
          })}

        </div>
      </nav>

      {/* ================= SYSTEM STATUS ================= */}
      <div className="px-3 pb-4">

        <div className="relative overflow-hidden rounded-2xl border border-black/10 bg-white/50 p-4 shadow-sm dark:border-white/10 dark:bg-white/5">

          {/* Red glow */}
          <div className="absolute -right-10 -top-10 h-24 w-24 rounded-full bg-jade/20 blur-3xl" />

          <div className="relative">

            <div className="flex items-center gap-2 mb-4">

              <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-jade/40 bg-jade/20">
                <Activity className="h-3.5 w-3.5 text-jade" />
              </div>

              <div>
                  <div className="text-xs font-semibold text-ink">
                  System Status
                </div>

                  <div className="mt-0.5 text-[9px] uppercase tracking-wider text-slate-500">
                  Real-time monitoring
                </div>
              </div>

            </div>

            {/* Detection Engine */}
            <div className="flex items-center justify-between py-2 border-t border-[#181818] dark:border-white/10">

              <span className="text-[11px] text-slate-600">
                Detection Engine
              </span>

              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.8)]" />

                <span className="text-[10px] font-semibold text-green-400">
                  ACTIVE
                </span>
              </div>

            </div>

            {/* AI Layer */}
            <div className="flex items-center justify-between pt-2">

              <span className="text-[11px] text-slate-600">
                AI Layer
              </span>

              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.8)]" />

                <span className="text-[10px] font-semibold text-green-400">
                  ONLINE
                </span>
              </div>

            </div>

          </div>
        </div>
      </div>

      {/* ================= USER / LOGOUT ================= */}
      <div className="border-t border-black/10 p-3 dark:border-white/10">

        <div className="mb-2 flex items-center gap-3 rounded-xl border border-black/10 bg-white/55 px-3 py-3 dark:border-white/10 dark:bg-white/5">

          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-black/10 bg-cream">
            <User className="h-4 w-4 text-slate-600" />
          </div>

          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-ink">
              Security Analyst
            </div>

            <div className="truncate text-[10px] text-slate-500">
              SOC Operator
            </div>
          </div>

          <Zap className="h-3.5 w-3.5 text-jade" />
        </div>

        <button
          onClick={handleLogout}
          className="
            group w-full flex items-center gap-3
            px-3 py-2.5 rounded-lg
            text-sm text-slate-600
            border border-transparent
            hover:text-ink
            hover:bg-jade/15
            hover:border-jade/30
            transition-all duration-200
          "
        >
          <LogOut className="w-4 h-4 transition-transform duration-200 group-hover:-translate-x-0.5" />

          <span>Sign Out</span>
        </button>

      </div>

    </aside>
  )
}