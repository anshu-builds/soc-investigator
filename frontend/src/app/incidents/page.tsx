'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Shield,
  Filter,
  Search,
  ChevronRight,
  Clock,
  User,
  Wifi,
} from 'lucide-react'
import { getIncidents } from '@/lib/api'
import type { IncidentSummary } from '@/lib/types'
import { SeverityBadge, StatusBadge, AttackTypeLabel } from '@/components/ui/badges'
import { formatDistanceToNow } from 'date-fns'
import { InvestigationBlocksBackground } from '@/components/ui/investigation-blocks-bg'
import { BorderBeam } from '@/components/ui/border-beam'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')

  useEffect(() => {
    setLoading(true)
    getIncidents({
      severity: severity || undefined,
      status: status || undefined,
      limit: 100,
    })
      .then((res) => {
        setIncidents(res.items)
        setTotal(res.total)
      })
      .finally(() => setLoading(false))
  }, [severity, status])

  const filtered = incidents.filter(
    (inc) =>
      !search ||
      inc.title.toLowerCase().includes(search.toLowerCase()) ||
      (inc.affected_username || '').toLowerCase().includes(search.toLowerCase()) ||
      (inc.source_ip || '').includes(search)
  )

  return (
    <div className="relative p-6 animate-fade-in overflow-hidden">
      <InvestigationBlocksBackground />
      <div className="relative z-10">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-ink">Security Incidents</h1>
          <p className="text-slate-600 text-sm mt-1">{total} total incidents detected</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-9 w-56"
            placeholder="Search incidents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="w-4 h-4 text-slate-500" />
          <select className="input text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select className="input text-sm" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All Statuses</option>
            {['OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE'].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
          <div className="card p-12 text-center text-slate-500">
            <div className="w-6 h-6 border-2 border-jade border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            Loading incidents...
          </div>
        </BorderBeam>
      ) : filtered.length === 0 ? (
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
          <div className="card p-12 text-center">
            <Shield className="w-10 h-10 text-slate-500 mx-auto mb-3" />
            <p className="text-slate-700 font-medium">No incidents found</p>
            <p className="text-slate-500 text-sm mt-1">Upload log files to start detection</p>
            <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-xl inline-flex mt-4">
              <Link href="/upload-logs" className="btn-primary inline-flex">
                Upload Logs
              </Link>
            </BorderBeam>
          </div>
        </BorderBeam>
      ) : (
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-black/10 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    <th className="text-left px-4 py-3">Severity</th>
                    <th className="text-left px-4 py-3">Incident</th>
                    <th className="text-left px-4 py-3">Type</th>
                    <th className="text-left px-4 py-3">Target</th>
                    <th className="text-left px-4 py-3">Source IP</th>
                    <th className="text-left px-4 py-3">Confidence</th>
                    <th className="text-left px-4 py-3">Status</th>
                    <th className="text-left px-4 py-3">Detected</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((inc) => (
                    <tr
                      key={inc.id}
                      className="border-b border-black/5 hover:bg-white/45 transition-colors cursor-pointer group"
                      onClick={() => (window.location.href = `/incidents/${inc.id}`)}
                    >
                      <td className="px-4 py-3">
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-slate-700 group-hover:text-ink transition-colors max-w-xs truncate">
                          {inc.title}
                        </div>
                        <div className="text-xs text-slate-500 mt-0.5">{inc.event_count} events</div>
                      </td>
                      <td className="px-4 py-3">
                        <AttackTypeLabel attackType={inc.attack_type} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-slate-600 text-xs">
                          <User className="w-3 h-3" />
                          {inc.affected_username || '-'}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-slate-600 text-xs font-mono">
                          <Wifi className="w-3 h-3" />
                          {inc.source_ip || '-'}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 bg-sky/50 rounded-full h-1.5">
                            <div
                              className="h-1.5 rounded-full bg-jade"
                              style={{ width: `${Math.round(inc.confidence * 100)}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-500">{Math.round(inc.confidence * 100)}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={inc.status} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-xs text-slate-500">
                          <Clock className="w-3 h-3" />
                          {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-slate-700 transition-colors" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </BorderBeam>
      )}
      </div>
    </div>
  )
}
