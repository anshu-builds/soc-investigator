'use client'

import { useRef, useState } from 'react'
import { Loader2, Volume2, VolumeX } from 'lucide-react'
import { getMessageAudio } from '@/lib/api'

interface TtsControlsProps {
  messageId: string
}

type PlaybackState = 'idle' | 'loading' | 'playing' | 'error'

/**
 * Play/Stop control for an assistant message. Deliberately opt-in per
 * message (no auto-play) and fails silently-but-visibly: a TTS error never
 * hides or affects the text answer already rendered above it, it just shows
 * a small inline notice next to the button.
 */
export function TtsControls({ messageId }: TtsControlsProps) {
  const [state, setState] = useState<PlaybackState>('idle')
  const [error, setError] = useState<string | null>(null)
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const queueRef = useRef<string[]>([])
  const indexRef = useRef(0)

  const stop = () => {
    audioRef.current?.pause()
    audioRef.current = null
    queueRef.current = []
    indexRef.current = 0
    setState('idle')
  }

  const playNextClip = () => {
    const clips = queueRef.current
    const i = indexRef.current
    if (i >= clips.length) {
      setState('idle')
      return
    }
    const audio = new Audio(`data:audio/wav;base64,${clips[i]}`)
    audioRef.current = audio
    audio.onended = () => {
      indexRef.current += 1
      playNextClip()
    }
    audio.onerror = () => {
      setError('Playback failed.')
      setState('error')
    }
    audio.play().catch(() => {
      setError('Playback failed.')
      setState('error')
    })
  }

  const play = async () => {
    if (state === 'loading' || state === 'playing') return // guard against repeated clicks
    setError(null)
    setState('loading')
    try {
      const response = await getMessageAudio(messageId)
      if (!response.audio_clips_base64.length) {
        setState('idle')
        return
      }
      queueRef.current = response.audio_clips_base64
      indexRef.current = 0
      setState('playing')
      playNextClip()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Audio unavailable')
      setState('error')
    }
  }

  return (
    <div className="mt-2 flex items-center gap-2">
      {state === 'playing' ? (
        <button
          onClick={stop}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#e6e8eb] bg-white px-2.5 py-1 text-xs font-medium text-[#344054] hover:bg-[#f8fafc]"
        >
          <VolumeX className="h-3.5 w-3.5" />
          Stop
        </button>
      ) : (
        <button
          onClick={play}
          disabled={state === 'loading'}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#e6e8eb] bg-white px-2.5 py-1 text-xs font-medium text-[#344054] hover:bg-[#f8fafc] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {state === 'loading' ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Generating audio…
            </>
          ) : (
            <>
              <Volume2 className="h-3.5 w-3.5" />
              Listen
            </>
          )}
        </button>
      )}
      {state === 'error' && (
        <span className="text-xs text-[#b42318]">{error} — text answer still available above.</span>
      )}
    </div>
  )
}
