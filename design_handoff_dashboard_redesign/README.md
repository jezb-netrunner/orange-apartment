# Handoff: Orange Apartment — dashboard redesign

Target repo: `jezb-netrunner/orange-apartment` (branch `main`) — a vanilla JS app (`index.html`, `app.css`, `app.js`, `billing-core.js`) on Supabase.

## Overview
A full visual and UX redesign of the admin app and the tenant portal. The goal: clean and modern but still inviting — a "property business" feel instead of the current mixed look. Same features, same data, no schema changes. Numbers come first, tables are clear, status reads at a glance, and the key action (**Receive payment**) is always one click/tap away.

## About the design files
The files in `designs/` are **design references built in HTML** (prototypes showing the intended look and behavior), not production code to paste in. Recreate them inside the existing app using its current patterns: string-built HTML in `app.js` render functions, classes in `app.css`, the existing modal/menu helpers, and Supabase calls. Do **not** add a framework.

Open `designs/Orange Apartment Redesign.dc.html` in a browser to see every screen on one canvas (pan/zoom). Each screen also opens on its own (e.g. `designs/Dashboard.dc.html`); sidebar links navigate between them. Sample data in the files is fictional.

## Fidelity
**High-fidelity.** Final colors, type, spacing, radii and interactions. Match them closely.

---

## Implementation plan (suggested PR scope)
1. **Tokens & type** — replace the `:root` block in `app.css` with the tokens below; swap Inter for **Plus Jakarta Sans** (400/500/600/700/800) in `index.html`. Replace every `var(--blue)` accent usage with the new accent tokens.
2. **Shell** — desktop (≥ 1024px): replace the sticky header + `#admin-tabs` row with a **left sidebar** (`renderAdminNav`). Phones (≤ 768px): keep `#bottom-nav` (Home, Tenants, Billing, Expenses, More) with the new styling, plus a floating **Receive payment** button. Tablet 769–1023px: collapse the sidebar to icons (72px).
3. **Page header** — change `pageHead()` into the topbar: title + subtitle left; global search + notification bell right. Page actions move to a toolbar row under it.
4. **Modules** — restyle and re-lay-out each render function per the screen specs below: `renderHome`, `renderTenantsModule`, `renderTenantDetail`, `renderBillingModule`, `openPayModal`/`renderPayPreview` (now a right drawer), `renderExpensesModule`, `renderReportsModule` + `renderInsightsModule` (merged under one nav item with tabs), `renderSettingsModule`, `openAddModal` (now a right drawer), the tenant login screen and the portal render (~`app.js` L5390).
5. **New behaviors** (front-end only): notification bell, global search, Billing bulk select, 6/12-month chart toggle, floor filter dropdown, inline "Mark paid" with Undo. Details in *Interactions*.

No database or Supabase changes are needed.

---

## Design tokens

### Colors
| Token | Hex | Use |
|---|---|---|
| `--bg` | `#F8F4EE` | App background (warm cream) |
| `--surface` | `#FFFFFF` | Cards, sidebar, drawers |
| `--ink` | `#1F1B16` | Primary text, headings |
| `--ink-2` | `#4A433B` | Secondary text, labels |
| `--muted` | `#6E665D` | Supporting text (5.6:1 on white) |
| `--faint` | `#9A9187` | Axis labels, placeholders, non-essential only |
| `--border` | `#ECE5DC` | Card borders, sidebar edge |
| `--border-strong` | `#E4DCD1` | Inputs, secondary buttons |
| `--divider` | `#F3EEE7` | Table row lines, card dividers |
| `--table-head` | `#FBF8F4` | Table header rows, card footers |
| `--track` | `#F5F0EA` (in cards) / `#EFE8DF` (on bg) | Segmented control tracks, chips |
| `--brand` | `#E8772E` | Logo mark, chart income bars, progress, focus ring, highlights |
| `--accent` | `#B9531A` | Filled primary buttons (white text 4.7:1) |
| `--accent-hover` | `#9F4614` | Primary hover |
| `--accent-text` | `#A84A15` | Links, active nav text |
| `--accent-soft` | `#FDEEE3` | Active nav bg, selected chips, focus halo |
| `--accent-tint` | `#FEF7F1` | Selected rows, chart highlight `#FEF3EA` |
| `--expense` | `#CDBFAE` | Expense bars |
| `--alert` | `#D9452F` | Notification/badge dot |

Status pills (text on background): **Overdue** `#C2362B` on `#FDECEA` · **Due soon / today** `#94590A` on `#FFF3DA` · **Paid** `#1E7A52` on `#E6F4EC` · **Paid ahead** `#2C62B0` on `#E8F0FB` · **Settled / neutral** `#5F574E` on `#F3EFEA`.

Rent-cycle squares: Paid `#A9D9BE` · Ahead `#DCE8F9` + inset 1.5px `#3B7BDB` · Due `#FFE7B8` + inset 1.5px `#E09B23` · Late `#EF9A90`.

Initials avatars (bg / text, chosen by a hash of the name): `#FDEEE3/#A84A15`, `#E8F0FB/#2C62B0`, `#E6F4EC/#1E7A52`, `#F1EAFB/#6A46B0`, `#FFF3DA/#8A5508`, `#E3F1F2/#1D6B73`. Font size = 34% of the avatar size, weight 700.

Expense categories (chip bg / text / bar): Electricity `#FFF3DA/#8A5508/#E9A93A` · Water `#E8F0FB/#2C62B0/#6E9BE0` · Internet `#F1EAFB/#6A46B0/#A68AD9` · Maintenance `#FDEEE3/#A84A15/#E8772E` · Taxes & Fees `#F3EFEA/#5F574E/#A89D90` · Other `#E3F1F2/#1D6B73/#6CB3B9`.

### Typography — Plus Jakarta Sans
| Role | Size / weight / tracking |
|---|---|
| Page title | 28px / 700 / -0.025em |
| Big figure (dashboard KPI) | 36px / 800 / -0.035em, tabular nums |
| Stat tile figure | 26px / 800 / -0.03em |
| Card title | 17px / 700 / -0.01em |
| Body / table cell | 14–14.5px / 400–600 |
| Field label | 13px / 600, `--ink-2` |
| Table header | 12.5px / 600, `--muted` |
| Supporting | 12.5–13.5px / 400, `--muted` |
| Section eyebrow | 11–12px / 700 / 0.07–0.08em, uppercase, `--faint` |
| Pill | 12.5px / 600 (11.5px on phones) |
All money and dates in figures/tables use `font-variant-numeric: tabular-nums`. Peso format stays `fmtMoney()` (whole pesos, no decimals unless centavos).

### Spacing, radii, shadows
- Page padding (desktop main): `30px 40px 44px`; gap between sections 24px (dashboard 28px).
- Card padding 22–24px (chart card `24px 28px`); table header row `12–13px 24px`; table rows `15–16px 24px`.
- Radii: cards 18px (stat tiles 16px) · buttons & inputs 10–11px · segmented track 12px, tab 9px · pills & chips 999px · icon tiles 9–11px · drawers 0 · phone sheets 22px.
- Shadows: segmented active `0 1px 3px rgba(60,40,20,.12)` · popovers `0 24px 48px -16px rgba(60,40,20,.28)` · drawers `-30px 0 60px -24px rgba(31,27,22,.4)` · scrim `rgba(31,27,22,.4)` · phone FAB `0 12px 26px -8px rgba(122,53,17,.55)`. Cards use a border only, with no shadow.
- Controls: buttons 42–44px tall (drawer footer 48px); inputs 44–46px; phone hit targets ≥ 44px.
- Focus: inputs `border-color #E8772E; box-shadow 0 0 0 4px #FDEEE3`. Buttons/links: `:focus-visible { outline: 2px solid #E8772E; outline-offset: 2px }`.

### Icons
Lucide-style 24×24 stroke icons, `stroke-width 1.8`, round caps/joins, `currentColor`. The app's existing `icon()` set can be reused. Sizes: nav 19px, buttons 16–18px, icon tiles 17–18px.

---

## Screens

### Shared — Sidebar (desktop)
256px wide, white, right border `--border`, padding `24px 18px 20px`, column with 24px gap.
- **Brand**: 36px rounded square (r11) `--brand` with white "O" (17px/800), then "Orange Apartment" (15px/700) and "Property admin" (12px, `--muted`). Use the `property_name` setting.
- **Receive payment**: full-width filled button, 44px, r11, `--accent`, cash icon.
- **Menu**: eyebrow "MENU", then Dashboard · Tenants (count, `--faint`) · Billing (overdue-count badge: 22px pill `#FDECEA`/`#C2362B`) · Expenses. Eyebrow "ANALYZE": Reports & insights · Settings. Items are 44px tall, r11, 12px gap, 14px; active = `--accent-soft` bg, `--accent-text`, 700.
- **Footer**: account card (38px initials avatar, "Owner" + email with ellipsis, sign-out icon button), then "Powered by JEZ" (11px, `--faint`).

### Shared — Topbar
Title (28/700) + subtitle (14.5, `--muted`); an optional back link above it ("‹ Tenants", 13/600). Right side: **search** (340×44, r22, search icon inset, placeholder "Search tenants, units or bills"), **bell** (44px circle, white, `--border-strong`) with a red count badge (20px, `--alert`, 2px cream ring).

### 1. Dashboard (`renderHome`)
Topbar: "Good morning" / "Friday, 2 October · here's how Orange Apartment is doing" (use the real date; greeting by time of day).
- **Row 1** — grid `1fr 1fr 300px`, gap 24:
  - **Net income** card: icon tile (`--accent-soft`/`--accent`) + "Net income" + period chip (last full month). Figure 36px; delta pill (Paid colors, "↑ 8.3%") + "vs August"; 150×56 sparkline of the last 6 months' net (2.5px `--brand` line, 10% fill, end dot). Footer (top divider) 3 columns: Income · Expenses · "October so far".
  - **Due in the next 7 days** card: icon tile (`#FFF3DA`/`#94590A`), "3 bills" chip, figure, "First one today: Maria Santos, rent ₱6,500". Footer: a 7-day strip (today through +6). Bars up to 40px tall, r7; today `--brand`, other days with bills `#F4C29C`, empty days a 4px `#F1EBE3` stub; short amount above ("6.5K"), day label below ("Today", "Sat"…).
  - **Quick actions**: three 52px rows with a border (icon tile, label, chevron): Add a bill · Add a tenant · Log an expense. Bottom: auto-billing status chip (Paid colors), e.g. "Auto-billing on · 4 bills posted today".
- **Income vs expenses** (full-width card): title + "Last 12 months · net income ₱484,000"; legend totals (Income, Expenses); a **6 months / 12 months** segmented toggle. Plot is 220px tall with a 44px y-axis (₱0/15K/30K/45K/60K), dashed gridlines `#EFE8DF`, and a solid baseline. Grouped bars per month (income `--brand`, expenses `--expense`), width 22px (12 months) / 40px (6 months), radius `6 6 2 2`; the current month is partial at 45% opacity. Hover selects a month: a soft `#FEF3EA` column highlight plus a one-line tooltip above the plot ("Sep 2026 · ▪ Income ₱53,900 · ▪ Expenses ₱8,300 · Net ₱45,600"). The last full month is selected by default.
- **Bills to chase** table card: title + "Overdue, and due in the next 7 days"; tabs **Needs action · Former tenants · All open** (with counts). Columns: Tenant (38px avatar, name, "Unit 204 · 2nd floor") · Bill · Due · Status pill (with dot) · Amount (right) · actions (36px reminder icon button = existing "copy payment reminder"; **Mark paid** outlined green). Mark paid → pill "Paid · just now", amount struck through, button becomes **Undo**. Footer: "6 open · ₱27,800" + "All open bills ›".

### 2. Tenants (`renderTenantsModule`)
Topbar "Tenants" / "8 active across 3 floors · ₱27,800 owed". Toolbar: tabs **All · Owing · Overdue · Paid ahead** (counts), search (300px; matches name/unit/code), **floor dropdown** (All floors / each floor), and **Add tenant** (filled, right). Table card with header row; columns `1.5fr 110px 1fr 170px 140px 110px 24px`: Tenant (40px avatar, name, phone) · Unit (+ floor) · Billing ("₱6,500 / month" + Itemized/All-inclusive) · Paid through (date + six 14px cycle squares) · Status pill · Balance (overdue in `#C2362B`, zero shows "—") · chevron. Rows are links to the tenant detail. Floor group header rows (uppercase 12px, "3 tenants · ₱6,500 owed") when grouped by floor. Footer: "Showing 8 of 8", cycle legend, "Archived tenants (2)". Empty state: "No tenants match. Try another filter or search."

### 3. Tenant detail (`renderTenantDetail`)
Topbar with back link "Tenants", title = name, subtitle "Unit 301 · 3rd floor · tenant since March 2024".
- **Summary card**, two rows. Top: 60px avatar, "Balance" + ₱7,000 (32/800), status pill; right side: **Receive payment** (filled), Add bill, Statement, ⋯. Bottom (divider) 4 stats: Rent ("₱6,500 / month", "Itemized utilities") · Paid through ("Oct 1, 2026", "Cycle starts on the 2nd") · Open bills ("2 · ₱7,000", "Next due Oct 5") · On-time payments ("11 of 11", "Last 12 months").
- Left column (1.75fr): **Bills** card with tabs Open/Paid/All; columns Bill (+ period or meter detail) · Due · Status · Amount · Paid on · ⋯ (existing bill menu). **Payments** card: Date · Note · Applied to · Amount.
- Right column: **Rent cycles** (12 months, 6 per row, 30px tiles + month label; legend). **Details**: access code chip + "Copy portal link" (turns to "Link copied") · Move-in date ("· billing date") · Recurring ("Rent ₱6,500, monthly" + green "Auto-posts 7 days before due") · Phone · Email.

### 4. Billing (`renderBillingModule`)
Topbar "Billing" / "9 open bills · ₱38,450 outstanding". Four stat tiles: Outstanding (with rent/utilities split) · Overdue (red figure; notes former-tenant share) · Due in 7 days · Collected this month (progress bar `--brand` + "58% of ₱54,000"). Toolbar: tabs **Open · Overdue · Due soon · Paid**, search, then Add bill + **Receive payment**. Table with a checkbox column (18px, r5; checked = `--accent` fill + white check). Selecting rows swaps the header for a bulk bar (`--accent-soft` bg): "2 selected · ₱13,000" + **Mark paid** (filled) · Copy reminders · Clear. The header checkbox selects or clears all visible rows. Columns: ☐ · Tenant · Bill (+ type/meter) · Due · Status · Amount · ⋯. Footer: count + total + "Bills CSV". Below: **Recent payments** table (Date · Tenant · Applied to · Note · Amount in green).

### 5. Receive payment (`openPayModal` → right drawer)
540px drawer over a 40% scrim. Header "Receive payment" / "Applied to the oldest open bills first" + close. Body:
- Tenant picker (avatar, "Maria Santos · Unit 301", "Owes ₱7,000 · rent paid through Oct 1", chevron).
- Amount field, 64px tall, 2px `--brand` border + 4px `--accent-soft` halo, 30px/800 figure. Quick-fill chips **Full balance ₱7,000** / **Balance + 1 month ₱13,500** (existing `payFill`).
- Date + optional Note.
- Checkbox "Apply any excess as advance rent" / "Extra money pays the next rent cycles" (existing `pay-advance`).
- **How it will be applied** box: one line per allocation (green check for settled bills, blue for advance), label + "Due Oct 2 · settled" / "Advance · covers Nov 2 – Dec 1" + amount. If the amount exceeds what's owed and advance is off, show the amber warning and disable the button ("Fix the amount first").
- Footer: Cancel · **Record ₱7,000** (label tracks the amount).

### 6. Expenses (`renderExpensesModule`)
Topbar "Expenses" / "October 2026 · ₱8,820 so far". **Log an expense** card with fields on one row: Date · Category · Amount (₱ prefix) · Floor (Building-wide or a floor) · Note · **Add**. Below, a grid `2.4fr 1fr`: the month table (prev/next month, "Expenses CSV"; columns Date · Category chip · Note · Floor · Amount · ⋯; footer count + total) and on the right **By category** bars (sorted, colored by category) and a compare card (last month's total and the difference; floor-tagged vs building-wide).

### 7. Reports & insights (`renderReportsModule` + `renderInsightsModule`)
One nav item. Underline tabs **Insights | Statements & exports** (2.5px `--brand` underline) with a period selector on the right.
- Insights: 4 tiles (Revenue, Expenses, Net income, Collection rate, each with the change vs the previous period) → **Net income by month** bars (best month `--brand`, others `#F4C29C`, current partial `#F8DCC6`, value labels, dashed 12-month average line) → two cards: **Money owed, by age** (buckets from `agingBuckets`, 10px bars from green to red; footer "Collected in advance" + "Tenant credits") and **Where the money goes** (stacked 14px bar + 2-column legend with % and ₱) → **By floor** table (Floor, Tenants, Revenue, Expenses, Net, Collection, Owed now, plus a Building-wide row and a totals footer).
- Statements & exports: 2×2 report cards (48px icon tile, title, description, actions): Income statement [Open] · Income statement per floor [Side by side] [One page per floor] · Statement of account [tenant picker] [Open] · Exports [Bills CSV] [Expenses CSV].

### 8. Settings (`renderSettingsModule`)
Two columns. Left: **Automatic billing** (switch 50×30, on = `--accent`; posting lead-time dropdown; footer with last-run status + **Run now**) · **Late payments** (grace-period segmented: None, 1, 2, 3, 5, 7 days) · **Database** (migration rows with Installed pills). Right: **Tenant portal** card with rows for Payment instructions, Announcements and Property name. Each shows its text in a `--table-head` box with **Edit** → inline textarea (2px `--brand` border) and **Save**, plus a hint line.

### 9. Add tenant (`openAddModal` → right drawer)
560px drawer. Sections with eyebrows. **Tenant**: Full name · Unit + Floor · Phone + Email (optional) · Portal access code (read-only display + **Generate** = `randCode()`; hint about copying the portal link after saving). **Billing**: segmented cards **Itemized** ("Rent plus metered utilities") / **All-inclusive** ("One flat monthly rate"); "Monthly rent" or "All-inclusive rate" (₱ … / month) + Move-in date; an explanation box that changes with the model; "+ Add a balance carried over from before" (the existing opening-bills list). Footer: Cancel · **Add tenant**. Edit mode reuses the drawer ("Save changes").

### 10. Admin on mobile (≤ 768px)
- **Home**: header (logo tile, date, "Good morning", bell with badge); 2 tiles (Net income + delta, Due in 7 days); a mini Income vs expenses chart (6 months); a **Bills to chase** list (avatar, name, bill · unit, amount, small pill); floating **Receive payment** pill (54px, `--accent`, bottom-right above the nav).
- **Tenants**: title + round add button; search (r22); filter chips (active = ink fill); floor-grouped list cards.
- **Receive payment**: full-screen sheet; Cancel / title; tenant picker; centered 46px amount; fill chips; Date + Note; advance switch; allocation box; sticky **Record ₱…** button (54px).
- Bottom nav: white, top border, 86px including the safe area; active = `--accent-text` 700; Billing badge.

### 11. Tenant portal (phone + desktop)
- **Sign in**: centered logo (68px), "Orange Apartment" / "Tenant portal"; card with "Sign in", Access code input (2px `--brand`, 20px/700, letter-spaced, uppercase), **Open my portal**; a note that the admin's portal link (`?code=`) signs you in without a code; "Lost your code? Ask the admin for a new one."
- **Home**: "Hi, Maria" + unit; hero card (`--accent` bg, white text): Amount due ₱7,000, a white "Rent due today" pill, "Rent is paid through Oct 1…", white **How to pay** button. Bill breakdown card (rent due today in amber text, water, electricity "Waiting for the meter reading"). Announcement card (`#FFF6E6`, border `#F5E1BC`). Recent payments list. **All-inclusive** variant: "Monthly rate ₱7,500 · Utilities included" + "Nothing owed right now".
- **Bills**: back link, "Your bills" + Statement button; **Bills | Payments** tabs; month pills (All / Oct / Sep / Aug — active = ink fill); bill rows with pills; footer "Owed for Oct ₱7,000" / "Nothing owed · Settled". Payments tab: date, amount, note, what it paid.
- **How to pay**: the `payment_instructions` setting shown as method rows (GCash / Bank transfer / Cash, each with Copy) plus an "After you pay" 2-step list. The setting is free text today; either keep it as text in one card or split it into one row per line.
- **Desktop portal** (1280px): white top bar (logo, tenant name + unit, avatar, Sign out); announcement banner; left column has a 3-stat balance strip (This month / Overdue / Total outstanding with breakdown; inclusive variant: Monthly rate / month status / Past due) and the bills table with month pills and a total footer; right column has the amount-due hero, How to pay and Payment history (+ Statement).

---

## Interactions & behavior
- **Notification bell**: count = bills due today + bills that became overdue in the last few days (due date + grace period passed). The popover (380px) lists them with an icon tile, title ("Rent due today" / "Now overdue"), relative time and "Tenant · Unit · Bill · ₱"; footer "View open bills" → Billing. Clicking outside closes it.
- **Global search**: filters as you type (no submit). Matches tenants (name, unit, code, phone, email) and open bills (label, tenant). Up to 6 results with a type tag ("TENANT" / "BILL") → tenant detail or Billing filtered to that bill. "Nothing matches “…”." when empty. Esc clears.
- **Mark paid / bulk mark paid**: call the existing `quickMarkPaid` per bill; show Undo for the session (use the existing undo/receipt flow where possible).
- **Copy reminder**: the existing reminder-copy behavior; show a toast.
- **Chart**: hover/focus selects a month; the 6/12 toggle re-scales the columns.
- **Drawers** (Receive payment, Add tenant): slide in from the right (200ms ease-out), scrim fades; Esc or scrim click closes; focus is trapped inside. On phones they become full-screen sheets.
- **Hover states**: rows `#FDFBF8`; secondary buttons `#FBF8F4`; primary `--accent-hover`; nav items `#F7F2EC`.
- **Loading**: keep the existing `setLoading` overlay; table skeleton rows use `--divider` blocks.
- Respect `prefers-reduced-motion` (already in `app.css`).

## Responsive
- ≥ 1280px: as designed (content fills the width; 1440px reference).
- 1024–1279px: Dashboard row 1 becomes 2 columns (Quick actions moves under them); four stat tiles become 2×2.
- 769–1023px: icon-only sidebar (72px); tables hide secondary columns (Billing: Bill type; Tenants: Billing).
- ≤ 768px: bottom nav + FAB, phone layouts as designed; tables become row cards (current `.t-row` mobile grid logic).

## State (front-end)
Existing globals cover the data. Add: `bellOpen`, `searchQuery`, `billSelection` (Set of bill ids), `chartRange` (6|12), `tenantFloorFilter`, `insightsTab`, `portalMonth` (exists), `portalTab` (bills|payments).

## Assets
No images. The logo is the CSS orange square with "O". Fonts come from Google Fonts. Icons are inline SVG (reuse `icon()`).

## Files (in `designs/`)
`Orange Apartment Redesign.dc.html` (overview canvas) · `OA Sidebar.dc.html` · `OA Topbar.dc.html` · `Dashboard.dc.html` · `Tenants.dc.html` · `Tenant Detail.dc.html` · `Billing.dc.html` · `Receive Payment.dc.html` · `Expenses.dc.html` · `Reports.dc.html` · `Settings.dc.html` · `Add Tenant.dc.html` · `Mobile Admin.dc.html` · `Tenant Portal.dc.html` · `Tenant Portal Desktop.dc.html` · `support.js` (runtime that renders the `.dc.html` files; not needed in the app).

Inline styles in these files are the source of exact values. The logic class at the bottom of each file shows the sample data and the state behavior.
