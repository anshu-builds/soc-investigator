# Frontend Dashboard Gap Analysis

## Scope

Audit of the Dashboard and Incident List frontend pages against the SOC Investigator frontend requirements.

Files reviewed:

- `frontend/src/app/dashboard/page.tsx`
- `frontend/src/app/incidents/page.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/lib/types.ts`

---

## 1. Dashboard

### Currently Implemented

- Dashboard UI and KPI cards are implemented.
- Dashboard fetches data through `getDashboardSummary()`.
- API endpoint is `/api/dashboard/summary`.
- KPI cards display total incidents, open incidents, critical/high incidents, events processed, and flagged events.
- Severity distribution is displayed as a chart.
- Recent incidents are displayed in a table.
- Recent incidents link to the corresponding incident detail page.
- API error state is implemented.
- Empty state for no recent incidents is implemented.

### Partially Implemented

- Dashboard has a loading state, but it currently uses a loading message/spinner rather than a full skeleton UI.
- Responsive behavior is implemented through responsive Tailwind classes but requires browser/device testing.

### Missing / Needs Verification

- `incidents_by_type` is available in the `DashboardSummary` API/type contract, but the Dashboard implementation needs to be verified for a corresponding visual chart.

---

## 2. Incident List

### Currently Implemented

- Incident list is connected to `getIncidents()`.
- Incident table displays severity, incident title, attack type, affected entity, source IP, confidence, status, and detection time.
- Severity filter is implemented.
- Status filter is implemented.
- Free-text search is implemented locally against incident title, affected username, and source IP.
- Empty state is implemented.
- Loading state is implemented.
- Incidents link to their detail pages.

### Missing

- Pagination UI is not implemented.
- Incident page does not currently send a `page` parameter.
- Attack-type filter is not implemented in the UI.
- URL search parameters are not synchronized with the selected filters.
- Loading state should be upgraded to a skeleton as required.

---

## 3. API and Type Support

### Currently Available

`frontend/src/lib/api.ts` already supports:

- `page`
- `limit`
- `severity`
- `status`
- `attack_type`

The `DashboardSummary` type already contains:

- `severity_distribution`
- `incidents_by_type`
- `recent_incidents`

The `IncidentListResponse` type contains:

- `total`
- `items`

Therefore the frontend API/type layer already provides the required structures for pagination, filtering, and dashboard charts.

---

## 4. Priority Gaps

1. Implement Incident List pagination.
2. Implement Attack Type filtering.
3. Synchronize Incident List filters with URL search parameters.
4. Add/upgrade loading skeletons for Dashboard and Incident List.
5. Verify and implement the Dashboard attack-type chart if missing.
6. Test responsive behavior across desktop and smaller screen sizes.

---

## 5. Summary

The existing frontend already contains substantial Dashboard and Incident List functionality. The primary remaining work is pagination, attack-type filtering, URL parameter synchronization, improved loading skeletons, and verification/completion of the attack-type Dashboard chart.
