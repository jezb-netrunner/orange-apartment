# Redesign: dashboard-style admin and tenant portal

## Summary
A full visual and UX refresh of Orange Apartment. Same features and data, no database changes.

- New look: warm cream background, white cards, Plus Jakarta Sans, the building's orange as the brand color, clear status colors (overdue / due / paid / ahead).
- Desktop shell: left sidebar with a permanent **Receive payment** button; per-page topbar with global search and a notification bell (bills due today and newly overdue).
- Dashboard: Net income (with trend), Due in the next 7 days (day strip), quick actions, auto-billing status, Income vs expenses chart (6/12 months), and a "Bills to chase" table with inline Mark paid + Undo.
- Tenants: filter tabs, search, floor filter, rent-cycle squares, grouped by floor.
- Tenant detail: summary card with balance and actions, bills with tabs, payments, rent cycles, details.
- Billing: stat tiles, filter tabs, bulk select (Mark paid / Copy reminders), recent payments.
- Receive payment and Add tenant are right-side drawers; the allocation preview shows exactly where the money goes.
- Expenses: one-row entry form, monthly table, category breakdown.
- Reports & insights merged under one nav item with tabs.
- Settings restyled; portal texts edit inline.
- Phones: restyled bottom nav plus a floating Receive payment button.
- Tenant portal: new sign-in, home, bills (by month, payments tab) and how-to-pay screens, plus a desktop layout.

## Files changed
- `redesign.css` (new) — the full visual layer
- `index.html` — font + stylesheet link
- `app.js` — sidebar markup, header search + bell, phone FAB, greeting (additive, no data logic)

## Implementation notes
- Tokens live in `app.css :root`; `--blue` usages move to the new accent tokens.
- Render functions keep their names and data flow. Only markup and classes change, plus a few small state additions (bell, search, bill selection, chart range, floor filter, insights tab, portal tab).
- Full spec: `design_handoff_dashboard_redesign/README.md`. HTML references: `design_handoff_dashboard_redesign/designs/`.

## Screenshots
_Add before/after screenshots of Dashboard, Tenants, Billing, Receive payment, and the tenant portal (phone)._

## Test plan
- [ ] Admin login → Dashboard renders with real data; figures match the old Home.
- [ ] Sidebar navigation on desktop; bottom nav + More sheet on phones (≤ 768px).
- [ ] Receive payment: quick-fill chips, the advance toggle, the over-payment warning, and the Record button label; the allocation matches `allocatePayment`.
- [ ] Mark paid (single + bulk) and Undo; Copy reminder toast.
- [ ] Bell count and list match bills due today / newly overdue (respects the grace period).
- [ ] Global search finds tenants by name/unit/code/phone/email and bills by label/tenant.
- [ ] Tenants filters + floor filter + search combine correctly; empty state shows.
- [ ] Add/Edit tenant drawer saves all fields; Generate code; inclusive vs itemized.
- [ ] Expenses add/edit/delete; month navigation; CSV export.
- [ ] Reports tabs; every report and export still opens.
- [ ] Settings: auto-billing toggle, lead time, Run now, grace period, portal texts.
- [ ] Tenant portal: code login and `?code=` link login; itemized and all-inclusive tenants; month pills; statement.
- [ ] Keyboard: visible focus, Esc closes drawers/popovers; contrast spot-check.
