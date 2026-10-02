# Implementation — ready to commit

These three files are the working code for the redesign of `jezb-netrunner/orange-apartment`. Drop them into the repo root (two replace existing files, one is new) and open the PR.

| File | Change |
|---|---|
| `redesign.css` | **New.** The redesign layer, loaded after `app.css`: new tokens (warm cream, white cards, brand orange), Plus Jakarta Sans, desktop sidebar shell, header search + bell, restyled cards/KPIs/buttons/chips/tables/forms/menus, modals as right-side drawers on desktop, phone bottom nav + floating Receive payment button, and the tenant portal and login. |
| `index.html` | Swaps the Google Fonts link to Plus Jakarta Sans and adds `<link rel="stylesheet" href="redesign.css?v=__ASSET_V__">` after `app.css`. Nothing else changes (CSP already allows Google Fonts; `deploy.yml` stamps `__ASSET_V__` and uploads the whole repo, so the new file deploys automatically). |
| `app.js` | Small, additive edits only: (1) four new icons in `ICON_PATHS` (search, bell, clock, logout); (2) `renderAdminNav()` renders the sidebar (brand, Receive payment, Menu/Analyze groups, tenant count, account + sign out); (3) `renderAdminNav()` calls the new `renderHeaderTools()`; (4) Home heading becomes a time-of-day greeting; (5) new functions at the end of the file: `renderHeaderTools`, `_bellItems`, `hdrSearch`, `hdrGo`, `_greeting`, `_initials`. No billing, data or Supabase logic is touched. |

## Behavior added
- **Notification bell**: counts bills due today plus bills that became overdue (past the grace period) within the last 7 days. The list opens the tenant; the footer goes to open bills. Esc or an outside click closes it.
- **Global search** in the header: as-you-type over tenants (name, unit, floor, code, phone, email) and open bills (label, tenant). Up to 8 results; Enter/click opens the tenant; Esc clears.
- **Phones**: a floating "Receive payment" button above the bottom nav.
- **Desktop**: tenant and payment modals slide in as right-side drawers.

## Commit and open the PR
```bash
git checkout -b redesign/dashboard-2026
cp <download>/implementation/{index.html,app.js,redesign.css} .
node --test tests/*.test.js        # billing tests (unchanged logic) should still pass
git add index.html app.js redesign.css
git commit -m "Redesign: dashboard-style admin and tenant portal"
git push -u origin redesign/dashboard-2026
gh pr create --title "Redesign: dashboard-style admin and tenant portal" --body-file <download>/PR_DESCRIPTION.md
```
Or hand this folder to Claude Code in the repo and ask it to commit these files on a branch and open the PR with `PR_DESCRIPTION.md`.

## What's next (optional follow-ups)
The look is applied app-wide through CSS, so every existing screen gets the new style. Matching the reference layouts 1:1 (dashboard cards with sparkline and 7-day strip, Billing bulk select, the redesigned tenant detail summary, the portal's Bills/Payments tabs) means changing markup in the matching render functions. `../README.md` specifies each one, and `../designs/` shows the target.
