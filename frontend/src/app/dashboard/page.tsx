'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  Shield,
  Activity,
  Zap,
  TrendingUp,
  Eye,
  ChevronRight,
  Upload,
} from 'lucide-react'
import { getDashboardSummary } from '@/lib/api'
import type { DashboardSummary, IncidentSummary } from '@/lib/types'
import { SeverityBadge, StatusBadge, AttackTypeLabel } from '@/components/ui/badges'
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatDistanceToNow } from 'date-fns'
import { InvestigationBlocksBackground } from '@/components/ui/investigation-blocks-bg'
import { BorderBeam } from '@/components/ui/border-beam'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
}

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  subtitle,
}: {
  title: string
  value: number | string
  icon: React.ElementType
  color: string
  subtitle?: string
}) {
  return (
    <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
      <div className="card p-5 flex items-start gap-4 relative overflow-hidden group hover:border-black/20 transition-colors">
        <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center flex-shrink-0`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="text-2xl font-bold text-ink tabular-nums">{value}</div>
          <div className="text-sm text-slate-600 mt-0.5">{title}</div>
          {subtitle && <div className="text-xs text-slate-500 mt-1">{subtitle}</div>}
        </div>
        <div className="absolute inset-0 opacity-0 group-hover:opacity-100 bg-gradient-to-r from-transparent to-jade/10 transition-opacity pointer-events-none" />
      </div>
    </BorderBeam>
  )
}

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  return (
    <Link href={`/incidents/${incident.id}`} className="block">
      <div className="flex items-center gap-3 px-4 py-3 hover:bg-white/45 transition-colors rounded-lg cursor-pointer group">
        <SeverityBadge severity={incident.severity} />
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-slate-700 truncate group-hover:text-ink transition-colors">
            {incident.title}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <AttackTypeLabel attackType={incident.attack_type} />
            <span className="text-slate-400">.</span>
            <span className="text-xs text-slate-500">
              {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}
            </span>
          </div>
        </div>
        <StatusBadge status={incident.status} />
        <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-slate-600 flex-shrink-0 transition-colors" />
      </div>
    </Link>
  )
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getDashboardSummary()
      .then(setSummary)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="flex items-center gap-3 text-slate-500">
          <div className="w-5 h-5 border-2 border-jade border-t-transparent rounded-full animate-spin" />
          Loading SOC dashboard...
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <AlertTriangle className="w-10 h-10 text-red-500 mx-auto mb-3" />
          <p className="text-red-600 font-medium">{error}</p>
          <p className="text-slate-500 text-sm mt-2">Check if the backend is running</p>
        </div>
      </div>
    )
  }

  const severityData = summary
    ? Object.entries(summary.severity_distribution).map(([name, value]) => ({
        name,
        value,
        fill: SEVERITY_COLORS[name] || '#64748b',
      }))
    : []

  const typeData = summary
    ? Object.entries(summary.incidents_by_type).map(([name, value]) => ({
        name: name
          .replace(/_/g, ' ')
          .split(' ')
          .map((w) => w[0])
          .join(''),
        fullName: name.replace(/_/g, ' '),
        value,
      }))
    : []

  return (
    <div className="relative p-6 space-y-6 animate-fade-in overflow-hidden">
      <InvestigationBlocksBackground />
      <div className="relative z-10 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink">SOC Dashboard</h1>
          <p className="text-slate-600 text-sm mt-1">Real-time security incident monitoring</p>
        </div>
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-xl inline-flex">
          <Link href="/upload-logs" className="btn-primary flex items-center gap-2">
            <Upload className="w-4 h-4" />
            Upload Logs
          </Link>
        </BorderBeam>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Incidents"
          value={summary?.total_incidents ?? 0}
          icon={AlertTriangle}
          color="bg-gradient-to-br from-red-500 to-red-600"
        />
        <StatCard
          title="Open Incidents"
          value={summary?.open_incidents ?? 0}
          icon={Eye}
          color="bg-gradient-to-br from-orange-500 to-orange-600"
        />
        <StatCard
          title="Critical"
          value={summary?.critical_count ?? 0}
          icon={Zap}
          color="bg-gradient-to-br from-red-700 to-red-800"
          subtitle="Highest priority"
        />
        <StatCard
          title="Events Processed"
          value={(summary?.events_processed_total ?? 0).toLocaleString()}
          icon={Activity}
          color="bg-gradient-to-br from-sky-500 to-sky-600"
          subtitle={`${summary?.events_flagged_total ?? 0} flagged`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-jade" />
              Severity Distribution
            </h2>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#ffffff',
                    border: '1px solid rgba(24,34,31,0.18)',
                    borderRadius: '8px',
                    color: '#18221f',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </BorderBeam>

        <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4 text-jade" />
              Incidents by Attack Type
            </h2>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={typeData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                <XAxis dataKey="name" tick={{ fill: '#475569', fontSize: 11 }} />
                <YAxis tick={{ fill: '#475569', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    background: '#ffffff',
                    border: '1px solid rgba(24,34,31,0.18)',
                    borderRadius: '8px',
                    color: '#18221f',
                  }}
                  formatter={(value: number, _name, props) => [value, props.payload?.fullName || '']}
                />
                <Bar dataKey="value" fill="#7FBF9A" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </BorderBeam>
      </div>

      <BorderBeam size="pulse-inner" colorVariant="colorful" theme="dark" strength={1} className="rounded-2xl">
        <div className="card">
          <div className="flex items-center justify-between px-5 pt-5 pb-3 border-b border-black/10">
            <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-jade" />
              Recent Incidents
            </h2>
            <Link href="/incidents" className="text-xs text-slate-600 hover:text-ink transition-colors">
              View all {`->`}
            </Link>
          </div>
          <div className="p-2">
            {summary?.recent_incidents.length ? (
              summary.recent_incidents.map((inc) => <IncidentRow key={inc.id} incident={inc} />)
            ) : (
              <div className="text-center py-12 text-slate-500">
                <Shield className="w-8 h-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm">No incidents yet.</p>
                <p className="text-xs mt-1">Upload log files to start detection.</p>
              </div>
            )}
          </div>
        </div>
      </BorderBeam>
      </div>
    </div>
  )
}
