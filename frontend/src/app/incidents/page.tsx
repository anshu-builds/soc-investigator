'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, ChevronRight, Filter, Search, User, Wifi } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { getIncidents } from '@/lib/api'
import type { IncidentSummary } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  useEffect(() => { setLoading(true); getIncidents({ severity: severity || undefined, status: status || undefined, limit: 100 }).then((res) => { setIncidents(res.items); setTotal(res.total) }).finally(() => setLoading(false)) }, [severity, status])
  const filtered = incidents.filter((inc) => !search || inc.title.toLowerCase().includes(search.toLowerCase()) || (inc.affected_username || '').toLowerCase().includes(search.toLowerCase()) || (inc.source_ip || '').includes(search))

  return <div className="mx-auto max-w-7xl p-5 sm:p-8"><header className="mb-7"><h1 className="text-2xl font-semibold tracking-[-.02em] text-[#111827]">Incidents</h1><p className="mt-1 text-sm text-[#667085]">{total} detected security incidents</p></header><div className="mb-5 flex flex-wrap items-center gap-3"><label className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#667085]" /><input className="input w-64 pl-9" placeholder="Search incidents" value={search} onChange={(e) => setSearch(e.target.value)} /></label><div className="flex items-center gap-2"><Filter className="h-4 w-4 text-[#667085]" /><select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => <option key={value} value={value}>{value}</option>)}</select><select className="input" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option>{['OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE'].map((value) => <option key={value} value={value}>{value}</option>)}</select></div></div>
    <section className="card overflow-hidden">{loading ? <div className="p-12 text-center text-sm text-[#667085]">Loading incidents…</div> : filtered.length === 0 ? <div className="p-12 text-center"><AlertTriangle className="mx-auto h-7 w-7 text-[#667085]" /><p className="mt-3 text-sm font-medium text-[#111827]">No incidents found</p><p className="mt-1 text-sm text-[#667085]">Adjust filters or upload security logs.</p><Link className="btn-ghost mt-4" href="/upload-logs">Upload logs</Link></div> : <div className="overflow-x-auto"><table className="w-full min-w-[950px] text-left"><thead className="border-b border-[#e6e8eb] bg-[#fafbfc] text-xs font-medium uppercase tracking-wide text-[#667085]"><tr><th className="px-5 py-3">Severity</th><th className="px-5 py-3">Incident</th><th className="px-5 py-3">Type</th><th className="px-5 py-3">Affected entity</th><th className="px-5 py-3">Source IP</th><th className="px-5 py-3">Confidence</th><th className="px-5 py-3">Status</th><th className="px-5 py-3">Detected</th><th /></tr></thead><tbody>{filtered.map((inc) => <tr key={inc.id} className="cursor-pointer border-b border-[#eef0f2] last:border-0 hover:bg-[#fafbfc]" onClick={() => { window.location.href = `/incidents/${inc.id}` }}><td className="px-5 py-3"><SeverityBadge severity={inc.severity} /></td><td className="px-5 py-3"><div className="max-w-xs truncate text-sm font-medium text-[#111827]">{inc.title}</div><div className="mt-0.5 text-xs text-[#667085]">{inc.event_count} events</div></td><td className="px-5 py-3"><AttackTypeLabel attackType={inc.attack_type} /></td><td className="px-5 py-3"><span className="flex items-center gap-1.5 text-sm text-[#475467]"><User className="h-3.5 w-3.5 text-[#667085]" />{inc.affected_username || '—'}</span></td><td className="px-5 py-3"><span className="flex items-center gap-1.5 font-mono text-xs text-[#475467]"><Wifi className="h-3.5 w-3.5 text-[#667085]" />{inc.source_ip || '—'}</span></td><td className="px-5 py-3"><span className="text-sm text-[#475467]">{Math.round(inc.confidence * 100)}%</span></td><td className="px-5 py-3"><StatusBadge status={inc.status} /></td><td className="px-5 py-3 text-sm text-[#667085]">{formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}</td><td className="px-5 py-3"><ChevronRight className="h-4 w-4 text-[#98a2b3]" /></td></tr>)}</tbody></table></div>}</section>
  </div>
}
