---
name: jade-sky-ui-redesign
description: 'Redesign the SOC Investigator frontend with the Jade Sky visual identity while preserving all existing routes, React behavior, API integrations, forms, authentication, incident workflows, uploads, and real data. Use for premium glass UI redesigns, frontend visual refreshes, Jade Sky theme work, or responsive styling changes in this repository.'
argument-hint: 'Describe the frontend page or workflow to redesign in the Jade Sky theme'
user-invocable: true
disable-model-invocation: false
---

# Jade Sky UI Redesign

## Purpose

Apply a cohesive Jade Sky visual redesign to the existing SOC Investigator frontend. This skill changes presentation only. It must leave application behavior, data flow, and backend contracts intact.

## Scope

Work inside `frontend/` unless a UI-related import or configuration change is strictly required. The application currently uses Next.js, React, TypeScript, and Tailwind CSS. Preserve the established project structure and local component conventions. Do not modify Python backend, detection, correlation, AI, RAG, datasets, or report-generation code.

The redesign covers the entire existing frontend surface, including:

- Sidebar and shared layout
- Dashboard
- Incidents list and incident detail views
- Incident chat and report views
- Upload Logs
- Logs
- Login and authentication-related presentation
- Shared badges and UI primitives

## Non-Negotiable Invariants

Before editing, locate and record the current implementation of each invariant. After editing, verify that each remains unchanged in behavior:

- Routes, route names, links, redirects, and navigation destinations
- API URLs, request methods, payloads, response handling, and error handling
- Data fetching, loading states, empty states, and refresh behavior
- TypeScript interfaces, types, and API response contracts
- React state, effects, event handlers, form submission, validation, and reset behavior
- Authentication and login behavior
- Incident search, filtering, severity/status display, selection, and navigation
- Dashboard statistics, charts, incident data, and interactions
- File selection, drag-and-drop, validation, upload requests, progress, and success/error states
- Existing icons and active navigation-state logic

Do not replace live values with mock data, add placeholder records, remove API calls, rename routes, or rewrite working logic for visual convenience.

## Procedure

### 1. Analyze Before Editing

Inspect the repository and frontend structure before making any change. Establish one local hypothesis about how the current presentation is controlled and identify one cheap check that could disconfirm it.

Identify:

- Framework and language from `frontend/package.json`, `tsconfig.json`, and app structure
- Styling system and available UI libraries from `tailwind.config.js`, `globals.css`, package dependencies, and existing components
- Shared layout ownership, especially `src/components/layout/Sidebar.tsx`
- Page ownership for `src/app/dashboard`, `src/app/incidents`, `src/app/upload-logs`, `src/app/logs`, and `src/app/login`
- Incident nested routes under `src/app/incidents/[id]`
- API helpers, types, and state logic in `src/lib/api.ts` and `src/lib/types.ts`
- Existing project instructions such as `frontend/AGENTS.md` and `frontend/CLAUDE.md`
- Available scripts in `frontend/package.json`

Read the relevant page and component implementations, not only filenames. Prefer the nearest owning abstraction and neighboring patterns over broad refactors.

### 2. Establish the Theme Foundation

Create `frontend/src/components/ui/jade-sky.tsx` if it does not already exist. Use this component exactly as the shared atmospheric background layer:

```tsx
export function GradientBackground({
  className,
}: {
  className?: string
}) {
  return (
    <div
      aria-hidden="true"
      className={className}
      style={{
        position: "relative",
        overflow: "hidden",
        width: "100%",
        height: "100%",
        containerType: "size",
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: "-0.8cqmin",
          filter: "blur(0.4cqmin)",
          backgroundColor: "#CFE9F0",
          backgroundImage:
            "radial-gradient(circle at 65.34% 44.62%, rgba(238, 246, 227, 1) 0%, rgba(238, 246, 227, 0) 34.1%), radial-gradient(circle at 28.07% 74.48%, rgba(183, 217, 142, 1) 0%, rgba(183, 217, 142, 0) 45.65%), radial-gradient(circle at 52.42% 19.94%, rgba(127, 191, 154, 1) 0%, rgba(127, 191, 154, 0) 57.55%), radial-gradient(circle at 80.31% 84.47%, rgba(207, 233, 240, 1) 0%, rgba(207, 233, 240, 0) 69.1%)",
        }}
      />
    </div>
  )
}
```

Import it with:

```tsx
import { GradientBackground } from "@/components/ui/jade-sky"
```

Use it as a non-interactive background layer. Keep content above it with a positioned wrapper and `z-10` or an equivalent stacking context:

```tsx
<div className="relative min-h-screen overflow-hidden">
  <GradientBackground className="absolute inset-0" />
  <div className="relative z-10">
    {/* Existing content and functionality remain here. */}
  </div>
</div>
```

If a shared layout already owns the page shell, add the background there so nested routes inherit it instead of duplicating it on every page. Do not let the decorative layer intercept pointer events; use `pointer-events-none` when needed.

Define reusable Jade Sky tokens in the existing CSS/Tailwind mechanism rather than scattering arbitrary colors:

- Jade: `#7FBF9A`
- Sage: `#B7D98E`
- Sky: `#CFE9F0`
- Cream: `#EEF6E3`
- Dark text: `#18221F`

Use readable glass surfaces with restrained transparency, backdrop blur, subtle borders, soft shadows, rounded corners, and consistent spacing. Prioritize contrast and scanning over decorative effects.

### 3. Redesign Presentational Surfaces

Make the smallest JSX changes needed to improve layout and styling. Preserve existing expressions, handlers, hooks, API calls, and conditional branches whenever possible.

For the sidebar:

- Preserve every navigation item, icon, route, click handler, and active-state calculation
- Add a refined glass surface, clear jade active treatment, usable hover/focus states, and responsive behavior
- Ensure navigation remains keyboard-accessible and visible against the gradient

For the dashboard:

- Preserve all fetched statistics, charts, incident information, loading states, and interactions
- Improve hierarchy with a calm page shell, aligned metric surfaces, restrained emphasis, and responsive grids
- Keep chart containers dimensionally stable so loading and populated states do not shift the layout

For incidents:

- Preserve search, filters, API data, severity/status semantics, click handlers, and route navigation
- Keep severity colors distinct and accessible; Jade Sky styling must not erase warning or critical meaning
- Use consistent table/list alignment, empty/loading/error states, and mobile overflow behavior

For Upload Logs:

- Preserve file input, drag-and-drop handlers, validation, upload request, backend integration, and all result states
- Style the drop zone as a premium focused workspace with obvious hover, drag-over, invalid, uploading, success, and error states
- Keep the native file input behavior and keyboard access intact even if the visible drop zone is custom-styled

For logs, login, incident chat, and reports:

- Apply the same theme foundation and surface language
- Preserve authentication, log data, chat submission, report actions, and route behavior
- Do not force dense dashboard patterns onto workflows that need readable text or focused forms

### 4. Accessibility and Responsive Review

Check the redesigned UI at narrow and wide viewports. Confirm:

- Text remains within its container and maintains strong contrast
- Focus states are visible for links, buttons, inputs, file controls, and draggable upload interactions
- Decorative backgrounds are hidden from assistive technology
- Content does not sit below or compete with the gradient layer
- Sidebar collapse or overflow behavior does not remove access to navigation
- Tables, charts, forms, and cards have stable dimensions and usable mobile behavior
- Severity and status are conveyed with text or labels as well as color

Use animation sparingly for page-load or staggered reveals. Respect reduced-motion preferences and avoid animations that interfere with uploads, charts, or form feedback.

### 5. Validate Immediately After Each Slice

After the first substantive edit, run the narrowest available frontend check before further exploration or patching. Then validate the complete change set:

1. Run `npm run lint` from `frontend/` when available.
2. Run `npm run build` from `frontend/` when available.
3. Check TypeScript and import resolution through the project checks or `npx tsc --noEmit` when appropriate.
4. Review the changed frontend files and confirm no backend or unrelated files were modified.
5. Exercise the affected route(s) if a development server is available, checking loading, empty, error, and populated states without substituting mock data.
6. For UI changes, inspect desktop and mobile rendering and verify navigation, forms, incident actions, and upload interactions still work.

If a check fails, repair only the touched frontend slice and rerun the same focused check before widening scope. Do not silence errors by weakening types or removing behavior.

## Completion Checklist

- [ ] Existing frontend structure and local instructions were inspected before editing.
- [ ] `GradientBackground` exists at `frontend/src/components/ui/jade-sky.tsx` and is imported through the `@/components/ui/jade-sky` alias.
- [ ] Jade Sky styling is applied consistently across all existing frontend routes.
- [ ] Sidebar navigation, icons, active state, and responsive behavior are preserved.
- [ ] Dashboard data, charts, loading states, and interactions are preserved.
- [ ] Incident search, filters, severity/status states, data, and navigation are preserved.
- [ ] Upload selection, drag-and-drop, validation, submission, and result states are preserved.
- [ ] Login, logs, incident chat, and report behavior are preserved.
- [ ] No mock data, backend edits, route changes, or unrelated refactors were introduced.
- [ ] TypeScript, lint, build, import, and relevant interaction checks pass or any pre-existing failures are reported.
- [ ] The final summary names every changed file and calls out validation results.
