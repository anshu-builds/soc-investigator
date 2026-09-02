'use client'

import { useEffect, useRef, useState } from 'react'
import { Loader2, Volume2, VolumeX } from 'lucide-react'
import { getMessageAudio } from '@/lib/api'

interface TtsControlsProps {
  messageId: string
}

type PlaybackState = 'idle' | 'loading' | 'playing' | 'error'

/** Opt-in, client-only playback for a server-authorized assistant message. */
export function TtsControls({ messageId }: TtsControlsProps) {
  const [state, setState] = useState<PlaybackState>('idle')
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const queueRef = useRef<string[]>([])
  const indexRef = useRef(0)
  const playbackIdRef = useRef(0)

  const stop = () => {
    playbackIdRef.current += 1
    abortRef.current?.abort()
    abortRef.current = null
    const audio = audioRef.current
    if (audio) {
      audio.onended = null
      audio.onerror = null
      audio.pause()
      audio.removeAttribute('src')
      audio.load()
    }
    audioRef.current = null
    queueRef.current = []
    indexRef.current = 0
    setState('idle')
  }

  useEffect(() => stop, [])

  const playNextClip = (playbackId: number) => {
    if (playbackId !== playbackIdRef.current) return
    const clip = queueRef.current[indexRef.current]
    if (!clip) {
      setState('idle')
      return
    }

    const audio = new Audio(`data:audio/wav;base64,${clip}`)
    audioRef.current = audio
    audio.onended = () => {
      if (playbackId !== playbackIdRef.current) return
      indexRef.current += 1
      playNextClip(playbackId)
    }
    audio.onerror = () => {
      if (playbackId === playbackIdRef.current) setState('error')
    }
    audio.play().catch(() => {
      if (playbackId === playbackIdRef.current) setState('error')
    })
  }

  const play = async () => {
    if (state === 'loading' || state === 'playing') return
    const playbackId = playbackIdRef.current + 1
    playbackIdRef.current = playbackId
    const controller = new AbortController()
    abortRef.current = controller
    setState('loading')
    try {
      const response = await getMessageAudio(messageId, controller.signal)
      if (playbackId !== playbackIdRef.current) return
      if (!response.audio_clips_base64.length) {
        setState('error')
        return
      }
      queueRef.current = response.audio_clips_base64
      indexRef.current = 0
      abortRef.current = null
      setState('playing')
      playNextClip(playbackId)
    } catch {
      if (playbackId === playbackIdRef.current) setState('error')
    }
  }

  return (
    <div className="mt-2 flex items-center gap-2 font-mono text-xs">
      {state === 'playing' ? (
        <div className="inline-flex items-center gap-2">
          <button
            type="button"
            onClick={stop}
            className="inline-flex items-center gap-1.5 rounded-md border border-[#ef4444]/40 bg-[#450a0a]/30 px-2.5 py-1 text-xs font-medium text-[#f87171] hover:bg-[#450a0a]/50 transition"
          >
            <VolumeX className="h-3.5 w-3.5 animate-pulse text-[#ef4444]" />
            <span>Stop Briefing</span>
          </button>
          <span className="text-[11px] text-[#6ee7b7] bg-[#10b981]/10 px-2 py-0.5 rounded border border-[#10b981]/20">
            Voice Briefing • Full evidence below
          </span>
        </div>
      ) : (
        <button
          type="button"
          onClick={play}
          disabled={state === 'loading'}
          title="Listen to a concise executive voice briefing; full details remain in the console"
          className="inline-flex items-center gap-1.5 rounded-md border border-[#10b981]/30 bg-[#10b981]/10 px-2.5 py-1 text-xs font-medium text-[#34d399] hover:bg-[#10b981]/20 transition disabled:cursor-not-allowed disabled:opacity-50"
        >
          {state === 'loading' ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-[#10b981]" />
          ) : (
            <Volume2 className="h-3.5 w-3.5 text-[#10b981]" />
          )}
          <span>{state === 'loading' ? 'Synthesizing Briefing…' : 'Voice Briefing'}</span>
        </button>
      )}
      {state === 'error' && (
        <span className="text-[11px] text-[#9ca3af]">Audio briefing temporarily unavailable</span>
      )}
    </div>
  )
}
