'use client'

import { useState } from 'react'
import { Shield, Eye, EyeOff, Lock, Loader2 } from 'lucide-react'
import { login } from '@/lib/api'
import { useRouter } from 'next/navigation'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('analyst@demo.com')
  const [password, setPassword] = useState('demo1234')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await login(email, password)
      localStorage.setItem('soc_token', res.access_token)
      router.push('/dashboard')
    } catch (e: any) {
      setError(e.message || 'Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary">
      {/* Background glow */}
      <div className="absolute inset-0 bg-glow-cyan opacity-30 pointer-events-none" />

      <div className="relative w-full max-w-md px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center mx-auto mb-4 shadow-glow-lg">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white text-glow-cyan">SOC Investigator</h1>
          <p className="text-slate-400 text-sm mt-1">Evidence-Grounded AI Security Platform</p>
          <p className="text-xs text-slate-600 mt-1">PS 114 · SIH 2026</p>
        </div>

        {/* Card */}
        <div className="card p-7">
          <h2 className="text-lg font-semibold text-white mb-5 flex items-center gap-2">
            <Lock className="w-4 h-4 text-slate-400" /> Analyst Sign In
          </h2>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="text-xs text-slate-400 block mb-1.5">Email Address</label>
              <input
                className="input w-full"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1.5">Password</label>
              <div className="relative">
                <input
                  className="input w-full pr-10"
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/50 text-red-400 text-sm">
                {error}
              </div>
            )}

            <button type="submit" disabled={loading} className="btn-primary w-full py-3 flex items-center justify-center gap-2">
              {loading ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Authenticating...</>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <div className="mt-4 pt-4 border-t border-border text-center">
            <p className="text-xs text-slate-500">Demo credentials pre-filled above</p>
          </div>
        </div>
      </div>
    </div>
  )
}
