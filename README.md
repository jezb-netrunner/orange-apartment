# Orange Apartment — Tenant Billing Portal

A single-page tenant billing portal for apartments and multi-level condominiums.
No build step, no framework: `index.html` + `app.js` + `app.css`, backed by
[Supabase](https://supabase.com) (Postgres + REST + RPC), hosted free on GitHub Pages.

## What it does

**For the landlord/admin** (email + password login). The admin portal is
split into modules — tabs on desktop, a bottom bar on phones (Reports,
Insights and Settings sit under *More*):

- **Home** — outstanding / overdue / collected / net at a glance, bills that
  need attention (mark paid or copy a reminder in one tap), quick actions,
  and the recurring-billing status.
- **Tenants** — searchable list with each tenant's balance and rent
  paid-through date; a **tenant page** with open bills, payment history,
  recurring charges, details, and the **billing-cycle strip**.
  Per-tenant **billing model**: *itemized* (rent + utilities as separate
  lines) or *all-inclusive* (one flat monthly rate; management shoulders
  utilities). Floor/group labels, archive & restore.
- **Billing** — every bill with status/month/floor/tenant filters (table on
  desktop, list on phones), **Receive payment**, quick-add bill, partial
  payments, CSV export, and the **Recurring & checker** tab.
- **Expenses** — ledger by month (electricity, water, maintenance…),
  optionally tagged to a floor, with *collected − spent = net cash*.
- **Reports** — printable **income statement** (accrual or cash basis;
  whole building, one floor, all floors side by side, or one page per
  floor), statements of account, CSV exports.
- **Insights** — revenue/cash/net vs the prior period, revenue vs expenses
  by month, money owed by age, where the money goes (incl. how much of the
  utility spend is billed back), per-floor performance, payment punctuality.
- **Settings** — automatic billing (on/off, lead time), payment
  instructions, announcements and property name pushed to every tenant
  portal.

### Recurring bills (annuity due) and reconciliation

- Each tenant's **recurring charges** (templates) post their bill
  automatically, *N* days before the admin-set due date (default 7) — rent
  is paid in advance and covers the cycle ahead. Posting runs whenever an
  admin opens the portal (and again on the next day if the tab stays open).
- Automatic posting covers the current and next cycle, and an active charge
  also catches up a cycle whose posting window passed while nobody opened
  the portal (up to two months back) — so no month silently goes unbilled.
  History from before a charge was active is never created behind your back;
  a charge switched back on (or a tenant restored) after a long pause
  restarts from the current cycle without posting an overdue one. A deleted
  recurring bill is never re-posted (its cycle is marked waived; undo it
  under Recurring charges). Turn auto-posting off globally (Settings) or per
  charge. Current-cycle bills that still aren't posted for tenants without a
  move-in date are listed under Billing › Recurring & checker.
  Background posting needs migration 2's `rev` column (so two devices can't
  overwrite each other); without it only *Run now* posts.
- The **checker** reconciles each charge from the tenant's **move-in date**
  (the reckoning date: cycle *k* runs from move-in + *k* months): cycles
  started, paid-through date, arrears, cash paid in advance, cycles never
  billed (post them or waive them in one tap), and overpayments not yet
  applied (**Apply credit** moves them forward with their original payment
  dates, so cash reports don't change).
- Tenants **without a move-in date** keep working exactly as before —
  their bills still post on their due dates; reconciliation simply stays
  off (and nothing is written) until a move-in date is set.
- **Receive payment** applies money to the oldest open bills first; any
  excess pays the next rent cycles in advance (they post early, marked
  paid). On the accrual income statement those advances sit as *unearned
  rent* until their cycle arrives.

### Income statement bases

- **Accrual (default, the general rule):** revenue is recognized in the
  billing cycle it pays for — optionally spread straight-line over each
  cycle's days — and the memo shows receivables and unearned (advance) rent
  at period end.
- **Cash:** revenue is counted when payment is received.
- **Per floor:** floor-tagged expenses are direct costs; building-wide
  expenses are split by headcount (tenants in residence each month) or by
  revenue share, or left unallocated. Archived tenants' history counts.

**For tenants** (access code or one-tap portal link):
- Their bills, balance, payment history, and printable statement.
- All-inclusive tenants see their flat rate ("utilities included") and a
  simple *Paid ✓ / Due in N days* status instead of a bill breakdown.
- "Keep me signed in" + `?code=XXXX` deep links — the reminder message logs
  them straight in.

## Setup for a new building

1. **Supabase project** — create one, then in the SQL editor create the base tables:
   ```sql
   CREATE TABLE tenants (
     id text PRIMARY KEY,
     name text NOT NULL, unit text NOT NULL, code text NOT NULL,
     phone text, email text, move_in_date date,
     bills jsonb NOT NULL DEFAULT '[]',
     templates jsonb NOT NULL DEFAULT '[]',
     archived_at timestamptz
   );
   CREATE TABLE settings ( key text PRIMARY KEY, value text NOT NULL DEFAULT '' );
   ```
2. Run `supabase-migration.sql` (RLS, tenant-login RPC, rate limiting).
3. Run `supabase-migration-2.sql` (billing models, expenses table, floor labels,
   unique access codes, per-IP login throttling, optimistic concurrency).
4. Run `supabase-migration-3.sql` (optional floor tag on expenses for the
   per-floor income statement). All three files are idempotent — safe to re-run.
5. Create the admin user under Supabase **Authentication → Users**.
6. In `app.js`, set `SB_URL` and `SB_KEY` to your project's URL and publishable
   key; update the `connect-src` host in `index.html`'s CSP to match.
7. Push to GitHub with Pages enabled — `.github/workflows/deploy.yml` runs the
   unit tests and deploys on every push to `main` (SQL files and tests are
   stripped from the published site).
8. Sign in as admin → **Settings → Property name** to set your building's name.

## Security model

- **Admin**: Supabase email auth (JWT). Row Level Security grants
  `authenticated` full CRUD on `tenants`, `settings`, `expenses`.
  Sessions live in memory and end with the tab unless the admin ticks
  **"Keep me signed in on this device"** at login — only then is the
  Supabase session (refresh token included) persisted to that device's
  localStorage. Signing out always clears it. Don't use the option on a
  shared computer.
- **Tenant**: an access code is exchanged for that tenant's row via the
  `login_tenant` RPC — the only anon path to tenant data. Failed attempts are
  rate-limited per code (5/15 min), per IP (20/15 min), and globally
  (circuit breaker). Successful logins are never throttled.
- Anon can additionally read only an allow-listed set of tenant-facing
  settings (payment instructions, announcements, property name). The
  automatic-billing settings are admin-only.
- Tenant PATCHes carry an optimistic-concurrency `rev` token so two admin
  devices can't silently overwrite each other's changes.
- The tenant access code is a bearer credential for a read-only view of that
  tenant's own bills. "Keep me signed in" stores it on the tenant's device;
  portal links embed it in the URL (stripped from the address bar on load).
  That trade-off is deliberate — nothing money-moving lives behind it.

## Files

| File | Purpose |
|---|---|
| `index.html` | Markup: login, app shell, modals. CSP locked to self + Supabase. |
| `billing-core.js` | Pure billing & accounting engine (no DOM): recurring cycles, auto-post plan, move-in reconciliation, payment allocation, accrual/cash income statement. |
| `app.js` | UI and data access (vanilla JS): auth, admin modules, tenant portal, modals, printing. |
| `app.css` | All styles, mobile-first responsive. |
| `tests/` | `node --test tests/*.test.js` — engine unit tests (run before every deploy). |
| `supabase-migration.sql` | v1 schema hardening: RLS, login RPC, rate limiting. |
| `supabase-migration-2.sql` | v2: billing models, expenses, floors, concurrency. |
| `supabase-migration-3.sql` | v3: optional floor tag on expenses. |
| `vendor/` | Pinned supabase-js, served locally so the CSP stays `'self'`. |
