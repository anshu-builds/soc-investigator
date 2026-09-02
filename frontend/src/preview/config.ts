/**
 * ============================================================================
 * DESIGN PREVIEW ONLY — NOT FOR PRODUCTION
 * ============================================================================
 * Single source of truth for whether the design-preview bypass is active.
 *
 * Active only in NON-production builds, and can be force-disabled by setting
 * NEXT_PUBLIC_DESIGN_PREVIEW=0. It is ALWAYS inert in a production build
 * (`next build` / NODE_ENV === 'production'), so it can never weaken the real
 * authentication, JWT, RBAC, API, or security controls of the deployed app.
 *
 * To remove entirely: delete `src/preview/` and the two preview lines in
 * `src/app/layout.tsx`.
 * ============================================================================
 */
export const DESIGN_PREVIEW =
  process.env.NODE_ENV !== 'production' &&
  process.env.NEXT_PUBLIC_DESIGN_PREVIEW !== '0'
