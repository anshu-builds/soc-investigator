'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import { AlertTriangle, KeyRound, Lock, Mail, Shield } from 'lucide-react'
import { login } from '@/lib/api'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password) {
      setError('Email and password are required.')
      return
    }

    setLoading(true)
    setError(null)

    try {
      await login(email, password)
      router.push('/dashboard')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0b0f14] p-4">
      <div className="w-full max-w-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-[#10b981]/30 bg-[#10b981]/10 shadow-sm">
            <Shield className="h-6 w-6 text-[#10b981]" />
          </div>
          <h1 className="mt-4 text-xl font-bold tracking-tight text-[#f3f4f6]">
            SOC Investigator
          </h1>
          <p className="mt-1 text-xs font-mono uppercase tracking-wider text-[#9ca3af]">
            Enterprise Security Operations Portal
          </p>
        </div>

        {/* Login Card */}
        <div className="card p-6 sm:p-8 bg-[#11161d] border-[#1f2937]">
          <div className="mb-6 border-b border-[#1f2937] pb-4">
            <h2 className="text-sm font-semibold text-[#f3f4f6] flex items-center gap-2">
              <Lock className="h-4 w-4 text-[#10b981]" />
              Secure Analyst Authentication
            </h2>
            <p className="mt-1 text-xs text-[#9ca3af]">
              Enter authorized credentials to access SOC telemetry and investigations.
            </p>
          </div>

          {error && (
            <div className="mb-5 flex gap-3 rounded-lg border border-[#7f1d1d] bg-[#450a0a]/50 p-3.5 text-xs text-[#fca5a5]">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#ef4444]" />
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[#9ca3af] mb-1.5" htmlFor="email">
                Analyst Email
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6b7280]" />
                <input
                  id="email"
                  type="email"
                  required
                  placeholder="analyst@domain.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input w-full pl-9 font-mono text-xs"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#9ca3af] mb-1.5" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#6b7280]" />
                <input
                  id="password"
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input w-full pl-9 font-mono text-xs"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full mt-2 font-medium"
            >
              {loading ? 'Authenticating...' : 'Sign In to Console'}
            </button>
          </form>
        </div>

        {/* Security Notice */}
        <p className="mt-6 text-center text-[11px] font-mono text-[#6b7280]">
          Audit logged · TLS encrypted · Access restricted to authorized personnel
        </p>
      </div>
    </div>
  )
}
