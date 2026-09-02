'use client'

import React, { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { getCurrentUser } from '@/lib/api'

import { ToastProvider } from '@/components/ui/Toast'

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking')
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const isLoginPage = pathname === '/login'

  useEffect(() => {
    const user = getCurrentUser()
    if (user) {
      setAuthState('authenticated')
      if (isLoginPage) {
        router.replace('/dashboard')
      }
    } else {
      setAuthState('unauthenticated')
      if (!isLoginPage) {
        router.replace('/login')
      }
    }
  }, [pathname, isLoginPage, router])

  // Public /login page renders immediately without the application shell
  if (isLoginPage) {
    if (authState === 'authenticated') {
      return (
        <div className="min-h-screen bg-canvas flex items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent-emerald border-t-transparent" />
            <span className="font-mono text-xs text-ink-muted">Redirecting to console…</span>
          </div>
        </div>
      )
    }
    return (
      <ToastProvider>
        <main className="min-h-screen bg-canvas">{children}</main>
      </ToastProvider>
    )
  }

  // Protected route in 'checking' or 'unauthenticated' state:
  // Render neutral loading indicator — NEVER mount protected children or trigger unauthenticated API calls.
  if (authState !== 'authenticated') {
    return (
      <div className="min-h-screen bg-canvas flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent-emerald border-t-transparent" />
          <span className="font-mono text-xs text-ink-muted">Verifying SOC Session…</span>
        </div>
      </div>
    )
  }

  // Authenticated state: render full console layout with toast provider, responsive sidebar, and smooth transition
  return (
    <ToastProvider>
      <div className="min-h-screen bg-canvas text-ink-primary">
        <Sidebar
          collapsed={collapsed}
          onToggle={() => setCollapsed(!collapsed)}
          mobileOpen={mobileOpen}
          onCloseMobile={() => setMobileOpen(false)}
        />
        <div
          className={`flex min-h-screen flex-col transition-[padding] duration-200 ease-in-out ${
            collapsed ? 'md:pl-16' : 'md:pl-64'
          }`}
        >
          <Header
            collapsed={collapsed}
            onToggleSidebar={() => setCollapsed(!collapsed)}
            onOpenMobile={() => setMobileOpen(true)}
          />
          <main key={pathname} className="flex-1 p-4 md:p-6 lg:p-8 overflow-x-hidden animate-fade-in">
            {children}
          </main>
        </div>
      </div>
    </ToastProvider>
  )
}
