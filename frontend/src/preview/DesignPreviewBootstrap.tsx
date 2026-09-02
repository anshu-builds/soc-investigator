'use client'

/**
 * ============================================================================
 * DESIGN PREVIEW ONLY — NOT FOR PRODUCTION
 * ============================================================================
 * Mounts the design-preview bypass (synthetic session token + /api fixture
 * interceptor) and shows a small, dismissible badge so it is obvious the UI
 * is running on synthetic data. Renders nothing in production builds.
 *
 * Remove by deleting `src/preview/` and the two preview lines in
 * `src/app/layout.tsx`.
 * ============================================================================
 */
import { useState } from 'react'
import { DESIGN_PREVIEW } from './config'
import { installDesignPreview } from './install'

// Run at module load (client) so the token is present before AppShell's
// auth effect reads it. Safe no-op on the server and in production.
installDesignPreview()

export function DesignPreviewBootstrap() {
  const [hidden, setHidden] = useState(false)

  if (!DESIGN_PREVIEW || hidden) return null

  return (
    <div
      role="status"
      className="fixed bottom-3 left-1/2 z-[100] -translate-x-1/2 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 backdrop-blur-sm"
    >
      <div className="flex items-center gap-2 font-mono text-[11px] text-amber-300">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
        </span>
        <span>DESIGN PREVIEW — synthetic data, no live backend</span>
        <button
          type="button"
          onClick={() => setHidden(true)}
          className="ml-1 rounded px-1 text-amber-300/70 transition-colors hover:text-amber-200"
          aria-label="Hide design preview badge"
        >
          ×
        </button>
      </div>
    </div>
  )
}
