'use client'

import React, { useState } from 'react'
import { Check, Copy, ExternalLink, Shield, Terminal, User, Wifi, X } from 'lucide-react'
import { format } from 'date-fns'
import type { SecurityEvent } from '@/lib/types'

interface EventDrawerProps {
  event: SecurityEvent | null
  onClose: () => void
}

export function EventDrawer({ event, onClose }: EventDrawerProps) {
  const [copied, setCopied] = useState(false)

  if (!event) return null

  const handleCopyRaw = () => {
    if (!event.raw_log) return
    navigator.clipboard.writeText(event.raw_log)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
      {/* Click outside backdrop */}
      <div className="flex-1" onClick={onClose} />

      {/* Drawer panel */}
      <div className="w-full max-w-xl border-l border-[#1f2937] bg-[#11161d] p-6 shadow-2xl flex flex-col h-full overflow-y-auto">
        {/* Drawer Header */}
        <div className="flex items-center justify-between border-b border-[#1f2937] pb-4">
          <div>
            <span className="font-mono text-[11px] text-[#9ca3af] uppercase tracking-wider block">
              Event Inspector
            </span>
            <h2 className="text-base font-semibold text-[#f3f4f6] font-mono mt-0.5">
              {event.event_type}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1f2937] bg-[#171e28] text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Status Pills */}
        <div className="mt-4 flex flex-wrap gap-2">
          {event.is_flagged ? (
            <span className="inline-flex items-center gap-1 rounded border border-[#7f1d1d] bg-[#450a0a] px-2 py-0.5 text-xs font-mono text-[#f87171]">
              <Shield className="h-3 w-3" /> Flagged Event
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded border border-[#1f2937] bg-[#171e28] px-2 py-0.5 text-xs font-mono text-[#9ca3af]">
              Standard Telemetry
            </span>
          )}
          <span className="inline-flex items-center rounded border border-[#1f2937] bg-[#171e28] px-2 py-0.5 text-xs font-mono text-[#9ca3af]">
            {event.event_category}
          </span>
        </div>

        {/* Metadata Grid */}
        <div className="mt-6 grid grid-cols-2 gap-4 rounded-lg border border-[#1f2937] bg-[#0b0f14] p-4 text-xs font-mono">
          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Timestamp (UTC)</span>
            <span className="text-[#f3f4f6] font-medium block mt-0.5">
              {format(new Date(event.timestamp), 'yyyy-MM-dd HH:mm:ss')}
            </span>
          </div>

          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Source IP</span>
            <span className="text-[#38bdf8] font-medium block mt-0.5">
              {event.source_ip}
            </span>
          </div>

          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Destination IP</span>
            <span className="text-[#9ca3af] font-medium block mt-0.5">
              {event.destination_ip || '—'}
            </span>
          </div>

          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Target Username</span>
            <span className="text-[#facc15] font-medium block mt-0.5">
              {event.username || '—'}
            </span>
          </div>

          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Host</span>
            <span className="text-[#9ca3af] font-medium block mt-0.5">
              {event.hostname || '—'}
            </span>
          </div>

          <div>
            <span className="text-[#6b7280] block text-[10px] uppercase">Source File</span>
            <span className="text-[#9ca3af] font-medium block mt-0.5 truncate" title={event.source_file || ''}>
              {event.source_file || '—'}
            </span>
          </div>
        </div>

        {event.description && (
          <div className="mt-4">
            <span className="text-xs font-medium text-[#9ca3af] block mb-1">Description</span>
            <p className="text-xs text-[#d1d5db] bg-[#171e28] rounded-lg p-3 border border-[#1f2937]">
              {event.description}
            </p>
          </div>
        )}

        {/* Raw Log Payload */}
        <div className="mt-6 flex-1 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-[#f3f4f6] flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-[#10b981]" />
              Raw Log Payload
            </span>
            <button
              type="button"
              onClick={handleCopyRaw}
              className="inline-flex items-center gap-1 rounded border border-[#1f2937] bg-[#171e28] px-2 py-1 text-[11px] font-mono text-[#9ca3af] hover:text-[#f3f4f6] hover:border-[#374151] transition"
            >
              {copied ? <Check className="h-3 w-3 text-[#10b981]" /> : <Copy className="h-3 w-3" />}
              {copied ? 'Copied' : 'Copy Raw'}
            </button>
          </div>

          <pre className="flex-1 overflow-x-auto rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3.5 font-mono text-xs text-[#9ca3af] leading-relaxed whitespace-pre-wrap break-all select-all">
            {event.raw_log}
          </pre>
        </div>
      </div>
    </div>
  )
}
