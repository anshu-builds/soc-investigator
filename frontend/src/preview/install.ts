/**
 * ============================================================================
 * DESIGN PREVIEW ONLY — NOT FOR PRODUCTION
 * ============================================================================
 * Browser-side setup that lets the authenticated SOC UI be inspected in the
 * v0 sandbox without a live backend:
 *
 *   1. Seeds a synthetic (non-production) session token into localStorage so
 *      the existing, UNMODIFIED `AppShell` / `getCurrentUser()` logic mounts
 *      the protected screens. The real login flow, JWT verification, RBAC,
 *      and backend are untouched — this only places a client-side token that
 *      the app already knows how to read.
 *
 *   2. Wraps `window.fetch` so `/api/*` requests resolve to local fixtures
 *      instead of hitting the (unavailable) FastAPI backend. All non-`/api`
 *      requests fall through to the real fetch untouched.
 *
 * Guarded by `DESIGN_PREVIEW`, so this is a no-op in production builds.
 * ============================================================================
 */
import { DESIGN_PREVIEW } from './config'
import { resolveMock } from './mock-api'

const TOKEN_KEY = 'soc_token'

/** base64url-encode a string (browser). */
function b64url(input: string): string {
  return btoa(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Build a syntactically valid, clearly-synthetic JWT the app can parse. */
function buildPreviewToken(): string {
  const header = { alg: 'none', typ: 'JWT' }
  const payload = {
    sub: 'preview-analyst',
    email: 'analyst@soc.local',
    role: 'lead_analyst',
    // Far-future expiry so the preview session never lapses mid-inspection.
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365,
    preview: true,
  }
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.design-preview`
}

let installed = false

export function installDesignPreview(): void {
  if (!DESIGN_PREVIEW) return
  if (typeof window === 'undefined') return
  if (installed) return
  installed = true

  // 1) Seed the synthetic session token (only if none present).
  try {
    if (!localStorage.getItem(TOKEN_KEY)) {
      localStorage.setItem(TOKEN_KEY, buildPreviewToken())
    }
  } catch {
    /* localStorage unavailable — ignore in preview */
  }

  // 2) Intercept /api/* fetches.
  const originalFetch = window.fetch.bind(window)

  window.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url
    const method = init?.method || (input instanceof Request ? input.method : 'GET')

    const mock = resolveMock(url, method)
    if (!mock) {
      return originalFetch(input as RequestInfo, init)
    }

    // Small artificial latency so loading states are still exercised visually.
    await new Promise((r) => setTimeout(r, 180))

    return new Response(JSON.stringify(mock.body), {
      status: mock.status,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // eslint-disable-next-line no-console
  console.log('[v0] Design preview active — /api/* served from local fixtures (non-production only).')
}
