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
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-accent-emerald/30 bg-accent-emerald/10 shadow-sm text-accent-emerald">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="mt-4 text-xl font-bold tracking-tight text-ink-primary">
            SOC Investigator
          </h1>
          <p className="mt-1 text-xs font-mono uppercase tracking-wider text-ink-secondary">
            Enterprise Security Operations Portal
          </p>
        </div>

        {/* Login Card */}
        <div className="card p-6 sm:p-8 bg-panel border-border shadow-sm">
          <div className="mb-6 border-b border-border-subtle pb-4">
            <h2 className="text-sm font-semibold text-ink-primary flex items-center gap-2">
              <Lock className="h-4 w-4 text-accent-emerald" />
              <span>Secure Analyst Authentication</span>
            </h2>
            <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
              Enter authorized credentials to access SOC telemetry, queue triage, and investigation workspaces.
            </p>
          </div>

          {error && (
            <div className="mb-5 flex items-center gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-3.5 text-xs text-severity-critical animate-fade-in">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono font-medium text-ink-secondary mb-1.5" htmlFor="email">
                Analyst Email
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
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
              <label className="block text-xs font-mono font-medium text-ink-secondary mb-1.5" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
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
              className="btn-primary w-full mt-2 font-medium py-2.5 flex items-center justify-center gap-2"
            >
              <span>{loading ? 'Authenticating…' : 'Sign In to Console'}</span>
            </button>
          </form>
        </div>

        {/* Security Notice */}
        <p className="mt-6 text-center text-[11px] font-mono text-ink-muted">
          Audit logged · TLS encrypted · Access restricted to authorized personnel
        </p>
      </div>
    </div>
  )
}
