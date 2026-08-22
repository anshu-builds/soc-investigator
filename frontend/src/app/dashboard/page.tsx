'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  RefreshCw,
  ShieldAlert,
  Upload,
} from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatDistanceToNow } from 'date-fns'
import { getDashboardSummary } from '@/lib/api'
import type { DashboardSummary, IncidentSummary } from '@/lib/types'
import { AttackTypeLabel, SeverityBadge, StatusBadge } from '@/components/ui/badges'

const ALL_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#64748b',
}

interface MetricCardProps {
  label: string
  value: string | number
  icon: React.ElementType
  detail?: string
  accentColor?: string
}

function MetricCard({ label, value, icon: Icon, detail, accentColor }: MetricCardProps) {
  return (
    <div className="card group flex flex-col justify-between p-5 transition-all duration-150 hover:border-[#c8d1cb] hover:shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#667085]">
            {label}
          </p>
          <p className="mt-2 text-3xl font-bold tracking-tight text-[#111827] tabular-nums">
            {value}
          </p>
        </div>
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#e6e8eb] bg-[#f8fafc] text-[#475467] transition-colors group-hover:border-[#d0d5dd] group-hover:bg-[#f1f5f9]">
          <Icon className="h-4.5 w-4.5 text-[#475467]" style={accentColor ? { color: accentColor } : undefined} />
        </div>
      </div>
      {detail ? (
        <p className="mt-3 text-xs font-medium text-[#667085] border-t border-[#f0f1f3] pt-2.5">
          {detail}
        </p>
      ) : (
        <div className="mt-3" />
      )}
    </div>
  )
}

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  return (
    <tr className="transition-colors hover:bg-[#f8fafc]">
      <td className="px-6 py-3.5">
        <Link
          href={`/incidents/${incident.id}`}
          className="font-mono text-xs font-medium text-[#2563eb] hover:underline"
        >
          {incident.id.slice(0, 8)}
        </Link>
      </td>
      <td className="px-6 py-3.5 max-w-[280px]">
        <Link
          href={`/incidents/${incident.id}`}
          className="block truncate text-sm font-medium text-[#111827] hover:text-[#168a52] transition-colors"
          title={incident.title}
        >
          {incident.title}
        </Link>
        <div className="mt-0.5">
          <AttackTypeLabel attackType={incident.attack_type} />
        </div>
      </td>
      <td className="px-6 py-3.5 whitespace-nowrap">
        <SeverityBadge severity={incident.severity} />
      </td>
      <td className="px-6 py-3.5 text-sm text-[#475467] whitespace-nowrap">
        {incident.affected_username || incident.source_ip || '—'}
      </td>
      <td className="px-6 py-3.5 text-sm text-[#667085] whitespace-nowrap">
        {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}
      </td>
      <td className="px-6 py-3.5 whitespace-nowrap">
        <StatusBadge status={incident.status} />
      </td>
    </tr>
  )
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setSummary(await getDashboardSummary())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-sm text-[#667085]">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin text-[#168a52]" />
        Loading dashboard…
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center p-6">
        <div className="card max-w-sm p-6 text-center">
          <AlertTriangle className="mx-auto h-7 w-7 text-[#dc2626]" />
          <p className="mt-3 font-semibold text-[#111827]">Dashboard unavailable</p>
          <p className="mt-1 text-sm text-[#667085]">{error}</p>
          <button onClick={load} className="btn-ghost mt-4 w-full justify-center">
            Try again
          </button>
        </div>
      </div>
    )
  }

  const severityDistribution = summary?.severity_distribution || {}
  const severityData = ALL_SEVERITIES.map((name) => ({
    name,
    value: severityDistribution[name] ?? 0,
    fill: SEVERITY_COLORS[name] || '#64748b',
  }))

  const maxVal = Math.max(...severityData.map((d) => d.value), 4)
  const criticalHigh = (summary?.critical_count ?? 0) + (summary?.high_count ?? 0)

  return (
    <div className="mx-auto max-w-7xl p-5 sm:p-8">
      {/* ── Dashboard Header ── */}
      <header className="mb-7 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#111827]">Dashboard</h1>
          <p className="mt-1 text-sm text-[#667085]">Security operations overview</p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={load}
            className="btn-ghost"
            aria-label="Refresh dashboard"
          >
            <RefreshCw className="mr-2 h-4 w-4 text-[#667085]" />
            Refresh
          </button>
          <Link href="/upload-logs" className="btn-primary">
            <Upload className="mr-2 h-4 w-4" />
            Upload logs
          </Link>
        </div>
      </header>

      {/* ── KPI Cards ── */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total incidents"
          value={summary?.total_incidents ?? 0}
          icon={ShieldAlert}
        />
        <MetricCard
          label="Open incidents"
          value={summary?.open_incidents ?? 0}
          icon={AlertTriangle}
          accentColor="#ea580c"
        />
        <MetricCard
          label="Critical / high"
          value={criticalHigh}
          icon={Activity}
          accentColor="#dc2626"
          detail={`${summary?.critical_count ?? 0} critical · ${summary?.high_count ?? 0} high`}
        />
        <MetricCard
          label="Logs processed"
          value={(summary?.events_processed_total ?? 0).toLocaleString()}
          icon={BarChart3}
          detail={`${summary?.events_flagged_total ?? 0} flagged`}
        />
      </section>

      {/* ── Severity Chart + Investigation Queue ── */}
      <section className="mt-6 grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
        {/* Severity Chart */}
        <div className="card flex flex-col justify-between p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-[#111827]">Incidents by severity</h2>
              <p className="mt-0.5 text-xs text-[#667085]">Current incident distribution</p>
            </div>
            <span className="inline-flex items-center rounded-md bg-[#f8fafc] border border-[#e6e8eb] px-2.5 py-1 text-xs font-semibold text-[#475467] tabular-nums">
              {summary?.total_incidents ?? 0} total
            </span>
          </div>
          <div className="w-full pt-1">
            <ResponsiveContainer width="100%" height={210}>
              <BarChart
                layout="vertical"
                data={severityData}
                margin={{ top: 8, right: 30, left: 75, bottom: 8 }}
                barCategoryGap="20%"
              >
                <XAxis type="number" hide domain={[0, maxVal]} />
                <YAxis
                  type="category"
                  dataKey="name"
                  axisLine={false}
                  tickLine={false}
                  tick={({ x, y, payload }) => {
                    const color = SEVERITY_COLORS[payload.value] || '#64748b'
                    return (
                      <g transform={`translate(${x},${y})`}>
                        <circle cx={-68} cy={0} r={3.5} fill={color} />
                        <text
                          x={-56}
                          y={0}
                          dy={4}
                          textAnchor="start"
                          fill="#374151"
                          fontSize={11}
                          fontWeight={600}
                        >
                          {payload.value}
                        </text>
                      </g>
                    )
                  }}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(248, 250, 252, 0.6)' }}
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload
                      return (
                        <div className="rounded-lg border border-[#e6e8eb] bg-white p-2.5 shadow-sm text-xs">
                          <div className="flex items-center gap-1.5 font-semibold text-[#111827]">
                            <span
                              className="h-2 w-2 rounded-full"
                              style={{ backgroundColor: data.fill }}
                            />
                            {data.name}
                          </div>
                          <p className="mt-1 text-xs text-[#475467]">
                            <span className="font-bold text-[#111827]">{data.value}</span>{' '}
                            {data.value === 1 ? 'incident' : 'incidents'}
                          </p>
                        </div>
                      )
                    }
                    return null
                  }}
                />
                <Bar
                  dataKey="value"
                  radius={[0, 4, 4, 0]}
                  barSize={12}
                  background={{ fill: '#f1f5f9', radius: 4 }}
                  isAnimationActive={true}
                  animationDuration={600}
                  animationEasing="ease-out"
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                  <LabelList
                    dataKey="value"
                    position="right"
                    fill="#111827"
                    fontSize={12}
                    fontWeight={700}
                    offset={10}
                  />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Investigation Queue */}
        <div className="card flex flex-col justify-between p-5">
          <div>
            <div className="flex items-center justify-between border-b border-[#f0f1f3] pb-3.5">
              <div>
                <h2 className="text-sm font-semibold text-[#111827]">Investigation queue</h2>
                <p className="mt-0.5 text-xs text-[#667085]">Prioritize open work by severity</p>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[#bbf7d0] bg-[#f0fdf4] px-2.5 py-0.5 text-xs font-medium text-[#168a52]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#168a52]" />
                Active
              </span>
            </div>

            <div className="divide-y divide-[#f0f1f3] text-sm">
              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2 w-2 rounded-full bg-[#dc2626]" />
                  <span className="text-xs font-medium text-[#475467]">Critical incidents</span>
                </div>
                <span className="text-sm font-bold tabular-nums text-[#dc2626]">
                  {summary?.critical_count ?? 0}
                </span>
              </div>

              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2 w-2 rounded-full bg-[#ea580c]" />
                  <span className="text-xs font-medium text-[#475467]">Open incidents</span>
                </div>
                <span className="text-sm font-bold tabular-nums text-[#111827]">
                  {summary?.open_incidents ?? 0}
                </span>
              </div>

              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2 w-2 rounded-full bg-[#2563eb]" />
                  <span className="text-xs font-medium text-[#475467]">Flagged events</span>
                </div>
                <span className="text-sm font-bold tabular-nums text-[#111827]">
                  {summary?.events_flagged_total ?? 0}
                </span>
              </div>
            </div>
          </div>

          <Link
            href="/incidents"
            className="btn-ghost mt-4 w-full justify-center text-xs font-medium text-[#344054] hover:border-[#b4c3b9] hover:text-[#111827]"
          >
            Review incidents <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
          </Link>
        </div>
      </section>

      {/* ── Recent Incidents Table ── */}
      <section className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#e6e8eb] px-6 py-4 bg-white">
          <div>
            <h2 className="text-sm font-semibold text-[#111827]">Recent incidents</h2>
            <p className="mt-0.5 text-xs text-[#667085]">Latest detected security events</p>
          </div>
          <Link
            href="/incidents"
            className="inline-flex items-center text-xs font-semibold text-[#168a52] hover:text-[#116f42] hover:underline"
          >
            View all <ArrowRight className="ml-1 h-3.5 w-3.5" />
          </Link>
        </div>
        {summary?.recent_incidents.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left">
              <thead className="bg-[#fafbfc] text-[11px] font-semibold uppercase tracking-wider text-[#667085] border-b border-[#e6e8eb]">
                <tr>
                  <th className="px-6 py-3">ID</th>
                  <th className="px-6 py-3">Incident</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Affected entity</th>
                  <th className="px-6 py-3">Time</th>
                  <th className="px-6 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f0f1f3] bg-white">
                {summary.recent_incidents.map((incident) => (
                  <IncidentRow key={incident.id} incident={incident} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-12 text-center">
            <p className="text-sm font-medium text-[#111827]">No incidents detected</p>
            <p className="mt-1 text-xs text-[#667085]">
              Upload security logs to begin automatic detection and correlation.
            </p>
          </div>
        )}
      </section>
    </div>
  )
}

