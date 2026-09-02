'use client'

import React, { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { getCurrentUser } from '@/lib/api'

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking')

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
        <div className="min-h-screen bg-[#0b0f14] flex items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-[#10b981] border-t-transparent" />
            <span className="font-mono text-xs text-[#6b7280]">Redirecting to console…</span>
          </div>
        </div>
      )
    }
    return <main className="min-h-screen bg-[#0b0f14]">{children}</main>
  }

  // Protected route in 'checking' or 'unauthenticated' state:
  // Render neutral loading indicator — NEVER mount protected children or trigger unauthenticated API calls.
  if (authState !== 'authenticated') {
    return (
      <div className="min-h-screen bg-[#0b0f14] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-[#10b981] border-t-transparent" />
          <span className="font-mono text-xs text-[#6b7280]">Verifying SOC Session…</span>
        </div>
      </div>
    )
  }

  // Authenticated state: render full console layout
  return (
    <div className="min-h-screen bg-[#0b0f14] text-[#f3f4f6]">
      <Sidebar />
      <div className="flex min-h-screen flex-col pl-64">
        <Header />
        <main className="flex-1 p-6 md:p-8 overflow-x-hidden">
          {children}
        </main>
      </div>
    </div>
  )
}
