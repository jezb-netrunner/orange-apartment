// ─────────────────────────────────────────────────────────────────────────
// BILLING CORE — pure billing & accounting logic. No DOM, no network.
//
// Loaded as a classic script before app.js (its function declarations are
// globals the app calls directly) and require()-able from Node for tests.
//
// Data model additions (all optional and additive — rows written before
// this file existed keep working unchanged):
//   bill.tmplId        id of the recurring template that produced the bill
//   bill.period        'YYYY-MM' billing cycle the bill belongs to
//   template.auto      false = never auto-post (default: auto-post)
//   template.postedThrough  last cycle auto-posted/generated ('YYYY-MM');
//                      auto-post never goes at or before it, so a bill the
//                      admin deletes is never silently recreated
//   template.skip      ['YYYY-MM', …] cycles the admin waived
//   template.aliases   labels the charge had before a rename
//   template.since     'YYYY-MM' cycle a charge was set up in (a charge
//                      that isn't the main rent is reckoned from then)
//   template.rates     [{until:'YYYY-MM', amount}] earlier amounts, so a
//                      rate change never reprices past cycles
//   template.retired   true = charge stopped (no longer billed or owed);
//                      its bills stay as history
//   bill.rid           receipt that posted the bill early (undoReceipt)
//   bill.preMoveOut    the bill as it was before a move-out changed it
//
// Recurring bills follow an ANNUITY-DUE schedule: each cycle's bill falls
// due at the START of the cycle it pays for (rent in advance, consumed
// forward). Due dates are the admin's (template day of month). For
// reconciliation the tenant's move-in date is the reckoning date: cycle k
// runs from move-in + k months to move-in + k+1 months.
// ─────────────────────────────────────────────────────────────────────────

const RE_YM  = /^\d{4}-(0[1-9]|1[0-2])$/;
const RE_ISO = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const MAX_CYCLES = 600; // 50 years — backstop against malformed dates

// ── Dates (all string math on 'YYYY-MM-DD' / 'YYYY-MM', UTC-safe) ──
function _pad2(n) { return String(n).padStart(2, '0'); }
function isYM(s) { return RE_YM.test(String(s == null ? '' : s)); }
function isISODate(s) {
  const v = String(s == null ? '' : s).slice(0, 10);
  if(!RE_ISO.test(v)) return false;
  const [y, m, d] = v.split('-').map(Number);
  return d <= daysInMonth(y, m);
}
function isoOrEmpty(s) { return isISODate(s) ? String(s).slice(0, 10) : ''; }
function ymOf(iso) { const v = String(iso == null ? '' : iso).slice(0, 7); return isYM(v) ? v : ''; }
function daysInMonth(y, m) { return new Date(Date.UTC(y, m, 0)).getUTCDate(); }
function addYM(ym, n) {
  let [y, m] = ym.split('-').map(Number);
  const t = y * 12 + (m - 1) + n;
  return Math.floor(t / 12) + '-' + _pad2((t % 12 + 12) % 12 + 1);
}
// Day `day` of month `ym`, capped to the month's last day.
function dateInMonth(ym, day) {
  const [y, m] = ym.split('-').map(Number);
  const d = Math.min(Math.max(1, Math.floor(Number(day) || 1)), daysInMonth(y, m));
  return ym + '-' + _pad2(d);
}
function lastDayOf(ym) { return dateInMonth(ym, 31); }
function _utc(iso) { const [y, m, d] = iso.split('-').map(Number); return Date.UTC(y, m - 1, d); }
function diffDays(a, b) { return Math.round((_utc(b) - _utc(a)) / 86400000); } // b − a
function addDaysISO(iso, n) {
  const dt = new Date(_utc(iso) + n * 86400000);
  return dt.getUTCFullYear() + '-' + _pad2(dt.getUTCMonth() + 1) + '-' + _pad2(dt.getUTCDate());
}
// Inclusive list of 'YYYY-MM' keys between two months (order-tolerant).
function ymRange(from, to) {
  const out = [];
  if(!isYM(from) || !isYM(to)) return out;
  if(from > to) { const s = from; from = to; to = s; }
  for(let ym = from, i = 0; i < MAX_CYCLES; i++, ym = addYM(ym, 1)) {
    out.push(ym);
    if(ym === to) break;
  }
  return out;
}

// ── Money ──
function _num(v) { const n = Number(v); return isFinite(n) ? n : 0; }
function r2(v) { return Math.round(_num(v) * 100) / 100; }
const EPS = 0.005;

// ── Bills ──
const BILL_CATEGORIES = [
  { key:'rent',      label:'Monthly Rent'  },
  { key:'utilities', label:'Utilities'     },
  { key:'other',     label:'Other Charges' }
];
// Categories are inferred from the label so existing data just works.
function billCategory(b) {
  const l = String((b && b.label) || '').toLowerCase();
  if(/\brenta?\b|\bupa\b/.test(l)) return 'rent';   // whole word: not rental or current
  if(/electric|kuryente|power|beneco|meralco|water|tubig|internet|wi-?fi|gas\b|cable|utilit/.test(l)) return 'utilities';
  return 'other';
}
function billTotalPaid(b) {
  if(!b || !b.payments || !b.payments.length) return 0;
  return b.payments.reduce((s, p) => s + _num(p.amount), 0);
}
function billRemaining(b) { return _num(b.amount) - billTotalPaid(b); }
// Cash that has gone toward a bill. A bill marked paid is settled in full
// even when its payments weren't logged; logged overpayments still count.
function billSettled(b) {
  const logged = billTotalPaid(b);
  return b.status === 'paid' ? Math.max(_num(b.amount), logged) : logged;
}
function billOpen(b) { return b.status === 'paid' ? 0 : Math.max(0, r2(billRemaining(b))); }
// An unpaid bill with no amount yet — a metered charge's placeholder
// waiting for its reading. Not owed, not late: it needs the admin.
function billAwaitingAmount(b) { return !!b && b.status !== 'paid' && !(_num(b.amount) > 0); }
function billPeriod(b) { return isYM(b && b.period) ? b.period : ymOf(b && b.due); }
function normLabel(s) { return String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' '); }

// Every cash receipt on a bill as {date, amount}; date '' = unknown. The
// residual of a bill marked paid beyond its logged payments lands on the
// paid date (this also covers legacy bills with no payment log at all).
function billCashEvents(b) {
  const ev = [];
  let logged = 0;
  (b.payments || []).forEach(p => {
    const v = _num(p.amount);
    logged += v;
    if(v) ev.push({ date: isoOrEmpty(p.date), amount: v });
  });
  if(b.status === 'paid') {
    const resid = r2(_num(b.amount) - logged);
    if(resid > 0) ev.push({ date: isoOrEmpty(b.paidDate), amount: resid });
  }
  return ev;
}

// ── Templates ──
function tmplDay(tmpl) {
  const d = Math.floor(Number(tmpl && tmpl.dayOfMonth));
  return d >= 1 && d <= 31 ? d : 1;
}
function tmplRate(tmpl) { return (!tmpl || tmpl.pendingAmount) ? 0 : r2(tmpl.amount); }
// The amount in force for cycle `ym`: an earlier rate from the template's
// history when the cycle predates a rate change, else the current rate.
function tmplRateAt(tmpl, ym) {
  if(!tmpl || tmpl.pendingAmount) return 0;
  let best = null;
  (Array.isArray(tmpl.rates) ? tmpl.rates : []).forEach(r => {
    if(r && isYM(r.until) && ym <= r.until && (!best || r.until < best.until)) best = r;
  });
  return best ? r2(best.amount) : tmplRate(tmpl);
}
// Every amount the charge has had (current first).
function _tmplRates(tmpl) {
  const out = [tmplRate(tmpl)];
  (Array.isArray(tmpl && tmpl.rates) ? tmpl.rates : []).forEach(r => { if(r && _num(r.amount) > 0) out.push(r2(r.amount)); });
  return out.filter(v => v > 0);
}
function isAutoTemplate(tmpl) { return !!tmpl && tmpl.auto !== false && !tmpl.retired; }
// Charges still in force (a stopped charge is neither posted nor owed).
function activeTemplates(t) { return ((t && t.templates) || []).filter(x => x && !x.retired); }
function moveInOf(t) { return isoOrEmpty(t && t.move_in_date); }

// The admin's due date for a template in a month. A cycle can't fall due
// before the tenancy starts, so in the move-in month an earlier template
// day moves to the move-in date itself.
function templateDueDate(t, tmpl, ym) {
  const due = dateInMonth(ym, tmplDay(tmpl));
  const mi = moveInOf(t);
  return (mi && ymOf(mi) === ym && due < mi) ? mi : due;
}

// The tenant's main recurring charge — the one advance payments roll into.
// Order-independent: among rent charges the one labelled like monthly rent,
// then the highest rate (a "Parking" or "Rent penalty" listed first can't
// take over). An all-inclusive tenant with no rent-labelled charge at all
// ("Room + utilities") falls back to their highest charge — but a rent
// charge that is merely pending or ₱0 never hands its role to another
// charge (a rent payment must not turn into months of prepaid parking).
function primaryTemplate(t) {
  const all = activeTemplates(t);
  const list = all.filter(x => tmplRate(x) > 0);
  const score = x => (/^\s*(monthly\s+)?rent\b/i.test(x.label || '') ? 1 : 0);
  const best = arr => arr.slice().sort((a, b) => score(b) - score(a) || tmplRate(b) - tmplRate(a))[0] || null;
  const rent = best(list.filter(x => billCategory(x) === 'rent'));
  if(rent) return rent;
  if(all.some(x => billCategory(x) === 'rent')) return null;
  if(!t || t.billing_model !== 'inclusive') return null;
  // All-inclusive with a custom-named main charge: the one that matches
  // the flat rate — never a small add-on (Parking) standing in for it.
  const flat = _num(t.flat_rate);
  if(flat > 0) {
    const near = list.filter(x => tmplRate(x) >= flat * 0.5)
      .sort((a, b) => Math.abs(tmplRate(a) - flat) - Math.abs(tmplRate(b) - flat))[0];
    return near || null;
  }
  return best(list);
}

// Template ids that still exist on the tenant. A bill tagged with a
// deleted template's id is treated like an untagged legacy bill, so
// deleting a charge and re-adding it (same name) keeps its history.
function _liveIds(t) { return new Set(((t && t.templates) || []).map(x => x && x.id).filter(Boolean)); }
// Which template an untagged bill belongs to, by its label: the charge
// with that CURRENT name; else one that had it as an old name (never one
// another charge uses now); else the charge whose name begins the label
// ("Water - Sept" → "Water"; the longest name wins). Deposits, balances,
// penalties and fees never match by prefix. Returns fn(bill) → template.
function _labelOwner(t) {
  const list = ((t && t.templates) || []).filter(x => x && normLabel(x.label));
  const cur = new Map();
  list.forEach(x => { const n = normLabel(x.label); if(!cur.has(n)) cur.set(n, x); });
  return b => {
    const l = normLabel(b && b.label);
    if(!l) return null;
    if(cur.has(l)) return cur.get(l);
    const al = list.find(x => Array.isArray(x.aliases) && x.aliases.some(a => normLabel(a) === l));
    if(al) return al;
    if(_NOT_MONTHLY_RENT.test(l)) return null;
    let best = null, len = 0;
    list.forEach(x => {
      const n = normLabel(x.label);
      if(n.length > len && l.startsWith(n) && /[^a-z0-9]/.test(l.charAt(n.length)) && _periodSuffix(l.slice(n.length))) { best = x; len = n.length; }
    });
    return best;
  };
}
// Does what follows a charge's name only say which month it is for?
// ("- Sept", "(Aug 2026)", "bill for October", "2026-09") — never a one-off
// like "heater repair", "refill (5 gal)" or "router replacement".
const _PERIOD_WORDS = new Set(('jan feb mar apr may jun jul aug sep sept oct nov dec january february march april june july august '
  + 'september october november december enero pebrero marso abril mayo hunyo hulyo agosto setyembre oktubre nobyembre disyembre '
  + 'bill billing reading for of the month monthly to and').split(' '));
function _periodSuffix(rest) {
  const words = String(rest).toLowerCase().split(/[^a-z]+/).filter(Boolean);
  return words.every(w => _PERIOD_WORDS.has(w));
}
const _sameTmpl = (a, b) => !!a && !!b && (a === b || (!!a.id && a.id === b.id));
// Does bill `b` belong to template `tmpl`? Bills tagged with a live
// template follow their tag; everything else by label (see _labelOwner).
function billOfTemplate(b, tmpl, liveIds, owner) {
  if(!b) return false;
  if(b.tmplId && liveIds.has(b.tmplId)) return b.tmplId === tmpl.id;
  return _sameTmpl((owner || _labelOwner({ templates: [tmpl] }))(b), tmpl);
}
// The recurring charge a bill belongs to (tag or label), or null.
function templateOfBill(t, b) {
  const list = (t && t.templates) || [];
  if(b && b.tmplId) { const x = list.find(y => y && y.id === b.tmplId); if(x) return x; }
  return _labelOwner(t)(b);
}
const _NOT_MONTHLY_RENT = /deposit|advance|penalt|late|fee|surcharge|interest|reserv|balance|arrear|carr(y|ied)|previous|back ?rent|past ?due|utang/i;
// A hand-typed bill that stands for the main rent in its month: untagged,
// named after no charge, not a deposit/penalty/fee — and either labelled
// as rent ("Rent - March", "Upa - March") or, when it isn't a utility,
// for exactly an amount the rent has had ("Monthly Bill - March" ₱6,000).
function _isLooseRent(b, t, liveIds, owner, rates) {
  if(!b || (b.tmplId && liveIds.has(b.tmplId)) || owner(b)) return false;
  if(_NOT_MONTHLY_RENT.test(b.label || '')) return false;
  const cat = billCategory(b);
  if(cat === 'rent') return true;
  return cat !== 'utilities' && !!rates && rates.includes(r2(b.amount));
}

// Bills that belong to a template (see billOfTemplate). With `fallback`, a
// period that has no such bill also accepts one hand-typed rent bill (see
// _isLooseRent) — so "Rent - March" typed by hand still counts as March's
// rent when reconciling the primary charge.
function templateBills(t, tmpl, fallback) {
  const bills = (t && t.bills) || [];
  const liveIds = _liveIds(t);
  const owner = _labelOwner(t);
  const byPeriod = new Map();
  const all = [];
  const add = (b, i) => {
    const p = billPeriod(b);
    all.push(i);
    if(!byPeriod.has(p)) byPeriod.set(p, []);
    byPeriod.get(p).push(i);
  };
  bills.forEach((b, i) => { if(billOfTemplate(b, tmpl, liveIds, owner)) add(b, i); });
  if(fallback) {
    const rates = _tmplRates(tmpl);
    // History from before the charge's first own bill may be hand-typed
    // under any monthly label ("Room - March", "Room - April", …): a label
    // repeated over 3+ months counts as that month's rent, at any amount.
    const firstOwn = Array.from(byPeriod.keys()).filter(isYM).sort()[0] || '9999-12';
    const series = _monthlySeries(bills, liveIds, owner);
    bills.forEach((b, i) => {
      const p = billPeriod(b);
      if(!p || byPeriod.has(p)) return;
      if(_isLooseRent(b, t, liveIds, owner, rates) || (p < firstOwn && series(b))) add(b, i);
    });
  }
  return { byPeriod, all };
}
// fn(bill) → is it one of a monthly series of untagged, unowned bills
// (same label apart from the month, in 3+ different months)?
function _monthlySeries(bills, liveIds, owner) {
  const stem = b => String(b.label || '').toLowerCase().split(/[^a-z]+/).filter(w => w && !_PERIOD_WORDS.has(w)).join(' ');
  const ok = b => b && !(b.tmplId && liveIds.has(b.tmplId)) && !owner(b) && !_NOT_MONTHLY_RENT.test(b.label || '')
    && billCategory(b) !== 'utilities' && billPeriod(b);
  const months = new Map();
  bills.forEach(b => {
    if(!ok(b)) return;
    const k = stem(b);
    if(!k) return;
    if(!months.has(k)) months.set(k, new Set());
    months.get(k).add(billPeriod(b));
  });
  return b => ok(b) && (months.get(stem(b)) || new Set()).size >= 3;
}

// Is cycle `ym` of `tmpl` already billed? Used before creating a bill
// (auto-post, generate, advance, backfill) so nothing is billed twice.
// For the primary rent charge a hand-typed rent bill in that month also
// counts, whatever its amount — the same rule reconciliation uses, so a
// month the checker counts as billed is never billed a second time.
function templateBillExists(t, tmpl, ym) {
  const bills = (t && t.bills) || [];
  const liveIds = _liveIds(t);
  const owner = _labelOwner(t);
  if(bills.some(b => b && billPeriod(b) === ym && billOfTemplate(b, tmpl, liveIds, owner))) return true;
  const prim = primaryTemplate(t);
  if(!_sameTmpl(prim, tmpl)) return false;
  const rates = _tmplRates(tmpl);
  return bills.some(b => billPeriod(b) === ym && _isLooseRent(b, t, liveIds, owner, rates));
}
// First activation on an all-inclusive tenant billed by hand: any bill
// already typed for that month is this month's charge, so turning
// automatic posting on never bills the month twice.
function _handTypedMonth(t, tmpl, ym) {
  if(!t || t.billing_model !== 'inclusive' || !_sameTmpl(primaryTemplate(t), tmpl)) return false;
  const liveIds = _liveIds(t), owner = _labelOwner(t);
  return (t.bills || []).some(b => b && billPeriod(b) === ym && !(b.tmplId && liveIds.has(b.tmplId)) && !owner(b) && !_NOT_MONTHLY_RENT.test(b.label || ''));
}

// Raise postedThrough only across cycles that really are billed (or
// waived), never over a gap — so generating a future month by hand can't
// make automatic billing skip the months in between. An unset value stays
// unset (first activation keeps its own rules).
function bumpPostedThrough(t, tmpl) {
  if(!isYM(tmpl.postedThrough)) return;
  const skip = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
  for(let i = 0; i < 240; i++) {
    const nx = addYM(tmpl.postedThrough, 1);
    if(!(skip.has(nx) || templateBillExists(t, tmpl, nx))) break;
    tmpl.postedThrough = nx;
  }
}

function makeTemplateBill(tmpl, ym, due) {
  const pending = !!tmpl.pendingAmount;
  return {
    label: String(tmpl.label || ''),
    amount: pending ? 0 : tmplRateAt(tmpl, ym),
    due,
    status: 'unpaid',
    remark: pending ? 'Pending amount — to be updated' : '',
    scanLink: '',
    paidDate: '',
    payments: [],
    tmplId: tmpl.id,
    period: ym
  };
}

function _clone(v) { return JSON.parse(JSON.stringify(v == null ? null : v)); }
function _defaultUid() {
  return 'x' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// ── AUTO-POST ─────────────────────────────────────────────────────────────
// Which recurring bills should exist by now. Annuity due: a cycle's bill
// posts `leadDays` before its due date so the tenant sees it in advance.
//
// An active template (postedThrough within the last two months) catches up
// every cycle since postedThrough whose posting window has opened — so a
// month nobody opened the portal in is still billed. A template that was
// never active, or was paused/restored after two months or more, starts at
// the current cycle: an already-overdue current cycle is recorded as
// handled but NOT posted (the checker lists it), so reactivation never
// piles overdue bills onto a tenant. Months before that are never created.
// postedThrough only ever advances one cycle at a time.
// Returns { bills: [new bills], templates: updated copy, changed }.
const CATCH_UP_LIMIT = 12;
function planAutoPost(t, opts) {
  opts = opts || {};
  const out = { bills: [], templates: _clone((t && t.templates) || []), changed: false };
  if(!t || t.archived_at || !isISODate(opts.today)) return out;
  const today = String(opts.today).slice(0, 10);
  const lead = Math.min(27, Math.max(0, Math.floor(Number(opts.leadDays) || 0)));
  const uid = opts.uid || _defaultUid;
  const cur = ymOf(today);
  const mi = moveInOf(t);
  const existing = (t.bills || []).slice();
  out.templates.forEach(tmpl => {
    if(!tmpl || !isAutoTemplate(tmpl) || !normLabel(tmpl.label)) return;
    if(!tmpl.id) { tmpl.id = uid(); out.changed = true; }
    const pt = isYM(tmpl.postedThrough) ? tmpl.postedThrough : '';
    const stale = !pt || pt < addYM(cur, -2);
    const firstRun = !pt;
    const skip = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
    const last = addYM(cur, 1);
    let ym = stale ? cur : addYM(pt, 1);
    const mark = p => { if(!isYM(tmpl.postedThrough) || p > tmpl.postedThrough) { tmpl.postedThrough = p; out.changed = true; } };
    for(let i = 0; i < CATCH_UP_LIMIT && ym <= last; i++, ym = addYM(ym, 1)) {
      if(mi && ym < ymOf(mi)) { if(!stale) mark(ym); continue; }   // before the tenancy
      if(skip.has(ym)) { mark(ym); continue; }                       // waived
      const due = templateDueDate(t, tmpl, ym);
      if(diffDays(today, due) > lead) break;                         // posting window not open yet
      const holder = { bills: existing.concat(out.bills), templates: out.templates, billing_model: t.billing_model, flat_rate: t.flat_rate };
      if(templateBillExists(holder, tmpl, ym) || (firstRun && _handTypedMonth(holder, tmpl, ym))) { mark(ym); continue; }
      if(stale && due < today) { mark(ym); continue; }               // (re)activation: leave overdue to the checker
      out.bills.push(makeTemplateBill(tmpl, ym, due));
      mark(ym);
    }
  });
  if(out.bills.length) out.changed = true;
  return out;
}

// ── RECONCILIATION (move-in reckoning, annuity due) ───────────────────────
// Cycle for month `ym`: starts on the move-in day of that month (capped),
// ends where the next one starts.
function cycleWindow(moveIn, ym) {
  const day = Number(moveIn.slice(8, 10));
  return { start: dateInMonth(ym, day), end: dateInMonth(addYM(ym, 1), day) };
}

// One recurring charge, reconciled from the move-in date:
//   cyclesStarted  cycles that are payable: started, or their bill's due
//                  date (the admin's, often before the start) has arrived
//   covered        cycles fully paid, consuming all cash toward the charge
//                  forward from the first cycle (advances included)
//   paidThrough    last day covered ('' if nothing is)
//   arrears        unpaid amount on cycles already past their due date
//   credit         cash beyond every started cycle (paid in advance)
//   missing        started cycles with no bill that aren't waived
//   excess         logged overpayment sitting on individual bills
// Returns null when the tenant has no move-in date (reconciliation off).
// A charge set up after move-in (tmpl.since) is reckoned from then — the
// main rent included — so adding or switching a charge never creates
// back-dated arrears. The main rent that existed from the start is
// reckoned from move-in; any other charge from its first bill (or, with
// no bill yet, the current cycle).
function _reckonFrom(tmpl, byPeriod, isPrimary, miYM, today) {
  if(isYM(tmpl.since)) return tmpl.since > miYM ? tmpl.since : miYM;
  if(isPrimary) return miYM;
  const first = Array.from(byPeriod.keys()).filter(isYM).sort()[0];
  const from = first || ymOf(today);
  return from < miYM ? miYM : from;
}
function reconcileCharge(t, tmpl, opts) {
  const mi = moveInOf(t);
  if(!mi || !tmpl) return null;
  opts = opts || {};
  const today = String(opts.today).slice(0, 10);
  const bills = t.bills || [];
  const isPrimary = !!(opts.primary && opts.primary === tmpl);
  const { byPeriod, all } = templateBills(t, tmpl, isPrimary);
  const skip = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
  const rate = tmplRate(tmpl);
  const miYM = ymOf(mi);

  // Where the charge is reckoned from. The main rent: the move-in cycle
  // (the reckoning date). Any other charge didn't necessarily exist then,
  // so: its first bill or the cycle it was set up in, whichever is
  // earlier — never before move-in; with neither, the current cycle.
  const startYM = _reckonFrom(tmpl, byPeriod, isPrimary, miYM, today);

  // A real bill always sets the cycle's cost (even in a waived month);
  // only an unbilled waived cycle is free, and an unbilled one costs the
  // rate in force back then.
  const cycleCost = ym => {
    const idx = byPeriod.get(ym);
    if(idx && idx.length) return r2(idx.reduce((s, i) => s + _num(bills[i].amount), 0));
    return skip.has(ym) ? 0 : tmplRateAt(tmpl, ym);
  };
  // A billed cycle falls due when its bill does (the admin may have moved
  // it); an unbilled one on the template's day.
  const cycleDue = ym => {
    const idx = byPeriod.get(ym) || [];
    const dues = idx.map(i => bills[i]).filter(b => isISODate(b.due));
    const open = dues.filter(b => billOpen(b) > EPS);
    const pick = (open.length ? open : dues).map(b => String(b.due).slice(0, 10)).sort()[0];
    return pick || templateDueDate(t, tmpl, ym);
  };

  const cycles = [];
  for(let ym = startYM, i = 0; i < MAX_CYCLES; i++, ym = addYM(ym, 1)) {
    const due = cycleDue(ym);
    if(cycleWindow(mi, ym).start > today && due > today) break;
    const idx = byPeriod.get(ym) || [];
    cycles.push({ ym, due, cost: cycleCost(ym), billed: idx.length > 0, waived: skip.has(ym) && !idx.length });
  }

  // A cycle is "missing" once its bill should have been posted: due date
  // within the posting lead window (or already past).
  const lead = Math.max(0, Math.floor(Number(opts.leadDays) || 0));
  const missing = cycles
    .filter(c => !c.billed && !c.waived && diffDays(today, c.due) <= lead)
    .map(c => ({ period: c.ym, due: c.due, amount: tmplRateAt(tmpl, c.ym) }));

  // Only bills that fall in a counted cycle go toward coverage: bills dated
  // before it (before move-in, or before the charge was reckoned from), or
  // with no date at all, can't be placed on the cycle timeline (they're
  // reported, not silently counted).
  const inScope = all.filter(i => { const p = billPeriod(bills[i]); return p && p >= startYM; });
  const outScope = all.filter(i => !inScope.includes(i));
  const ignoredCash = r2(outScope.reduce((s, i) => s + billSettled(bills[i]), 0));

  // Overpayments logged on individual bills of a FIXED charge. A variable
  // (pending-amount) bill paid before its reading isn't overpaid — the
  // money waits for the real amount.
  let excess = 0;
  const excessBills = [];
  if(rate > 0) inScope.forEach(i => {
    const b = bills[i];
    const over = r2(billTotalPaid(b) - _num(b.amount));
    if(over > EPS) { excess = r2(excess + over); excessBills.push(i); }
  });

  const res = {
    tmplId: tmpl.id, label: tmpl.label, rate, moveIn: mi, startYM,
    variable: rate <= 0, cyclesStarted: cycles.length,
    missing, excess, excessBills, ignored: outScope.length, ignoredCash,
    covered: 0, remainder: 0, paidThrough: '', arrears: 0, credit: 0, pool: 0,
    nextDue: '', nextAmount: 0, aheadCycles: 0, status: 'variable',
    openCovered: [], dues: {}
  };
  cycles.forEach(c => { res.dues[c.ym] = c.due; });
  if(res.variable) return res; // pending-amount charges vary monthly: gap check only

  const pool = r2(inScope.reduce((s, i) => s + billSettled(bills[i]), 0));
  res.pool = pool;

  // Consume the pool forward, cycle by cycle (advances roll into future cycles).
  let rem = pool, covered = 0, ym = startYM;
  const cap = cycles.length + 240;
  for(let i = 0; i < cap; i++, ym = addYM(ym, 1)) {
    const cost = cycleCost(ym);
    if(cost <= EPS) { if(i >= cycles.length && !(skip.has(ym) && !byPeriod.get(ym))) break; covered++; continue; }
    if(rem + EPS < cost) break;
    rem = r2(rem - cost);
    covered++;
  }
  res.covered = covered;
  res.remainder = rem;
  const firstOpen = addYM(startYM, covered);
  res.paidThrough = covered > 0 ? addDaysISO(cycleWindow(mi, firstOpen).start, -1) : '';
  res.nextDue = cycleDue(firstOpen);
  res.nextAmount = r2(Math.max(0, cycleCost(firstOpen) - rem));
  res.aheadCycles = covered - cycles.length;

  const owedStarted = r2(cycles.reduce((s, c) => s + c.cost, 0));
  const owedPastDue = r2(cycles.filter(c => c.due < today).reduce((s, c) => s + c.cost, 0));
  res.arrears = r2(Math.max(0, owedPastDue - pool));
  res.credit = r2(Math.max(0, pool - owedStarted));
  res.status = res.arrears > EPS ? 'behind' : (res.aheadCycles > 0 ? 'advance' : 'current');

  // Open bills whose cycle the pooled cash already covers — "Apply credit"
  // settles them by moving the overpayment onto them.
  for(let i = 0; i < covered; i++) {
    const p = addYM(startYM, i);
    (byPeriod.get(p) || []).forEach(bi => { if(billOpen(bills[bi]) > EPS) res.openCovered.push(bi); });
  }
  return res;
}

function reconcileTenant(t, opts) {
  opts = opts || {};
  const mi = moveInOf(t);
  const templates = activeTemplates(t).filter(x => normLabel(x.label));
  if(!templates.length) return { enabled: false, reason: 'no-templates', charges: [] };
  if(!mi) return { enabled: false, reason: 'no-move-in', charges: [] };
  const primary = primaryTemplate(t);
  const charges = templates.map(tmpl => reconcileCharge(t, tmpl, Object.assign({}, opts, { primary })))
    .filter(Boolean);
  // Primary charge first, then fixed charges, then variable ones.
  charges.sort((a, b) => (b.tmplId === (primary && primary.id)) - (a.tmplId === (primary && primary.id))
    || (a.variable - b.variable));
  return { enabled: true, reason: '', charges, primaryId: primary ? primary.id : null };
}

// ── PAYMENT ALLOCATION ────────────────────────────────────────────────────
// Apply cash `chunks` ([{amount, date, note}], in order) to the tenant's
// open bills — oldest due date first, rent before other charges on the same
// day, undated bills last — then, if cash remains and `advance` is on, roll
// it into future cycles of the primary recurring charge (annuity due: the
// next unposted cycle is posted early and paid). Pure: works on copies.
// Returns { bills, templates, lines, leftover, changed }.
function _openOrder(bills) {
  const rank = { rent: 0, utilities: 1, other: 2 };
  return bills.map((b, i) => ({ b, i }))
    .filter(x => x.b && billOpen(x.b) > EPS)
    .sort((x, y) => (x.b.due || '9999-99-99').localeCompare(y.b.due || '9999-99-99')
      || rank[billCategory(x.b)] - rank[billCategory(y.b)] || x.i - y.i)
    .map(x => x.i);
}

function allocatePayment(t, chunks, opts) {
  opts = opts || {};
  const bills = _clone((t && t.bills) || []);
  const templates = _clone((t && t.templates) || []);
  const lines = [];
  // Every entry a receipt writes carries its receipt id (`rid`), so the
  // whole payment can be undone as one unit (see undoReceipt).
  const queue = (chunks || []).map(c => ({ amount: r2(c.amount), date: isoOrEmpty(c.date), note: String(c.note || ''), src: c.src, rid: c.rid || opts.rid || '' }))
    .filter(c => c.amount > EPS);
  const take = (bill, maxAmt, label) => {
    let applied = 0;
    while(queue.length && maxAmt - applied > EPS) {
      const c = queue[0];
      const amt = r2(Math.min(c.amount, maxAmt - applied));
      bill.payments = bill.payments || [];
      const entry = { amount: amt, date: c.date, note: c.note || label || '' };
      if(c.rid) { entry.rid = c.rid; if(!bill.rid && bill._new) bill.rid = c.rid; }
      bill.payments.push(entry);
      applied = r2(applied + amt);
      c.amount = r2(c.amount - amt);
      if(c.amount <= EPS) queue.shift();
      if(billOpen(bill) <= EPS) { bill.status = 'paid'; bill.paidDate = c.date || bill.paidDate || ''; }
    }
    return applied;
  };

  for(const i of _openOrder(bills)) {
    if(!queue.length) break;
    const b = bills[i];
    const before = billOpen(b);
    const applied = take(b, before);
    if(applied > EPS) lines.push({ kind: 'bill', index: i, label: b.label, due: b.due || '', period: billPeriod(b),
      apply: applied, settles: billOpen(b) <= EPS, remaining: billOpen(b) });
  }

  // Advance into future cycles of the primary charge.
  let tmpl = null;
  if(queue.length && opts.advance !== false) {
    tmpl = primaryTemplate({ templates, billing_model: t && t.billing_model, flat_rate: t && t.flat_rate });
  }
  if(tmpl && isISODate(opts.today)) {
    const uid = opts.uid || _defaultUid;
    if(!tmpl.id) tmpl.id = uid();
    const skip = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
    const mi = moveInOf(t);
    let ym = ymOf(opts.today);
    if(mi && ymOf(mi) > ym) ym = ymOf(mi);
    const holder = { bills, templates, billing_model: t && t.billing_model, flat_rate: t && t.flat_rate };
    for(let n = 0; queue.length && n < 240; n++, ym = addYM(ym, 1)) {
      if(skip.has(ym) || templateBillExists(holder, tmpl, ym)) continue;
      const due = templateDueDate(t, tmpl, ym);
      const bill = makeTemplateBill(tmpl, ym, due);
      bill._new = true; // lets take() stamp the receipt that created it
      const applied = take(bill, _num(bill.amount), 'Advance payment');
      delete bill._new;
      bill.remark = billOpen(bill) <= EPS ? 'Paid in advance' : 'Partly paid in advance';
      bills.push(bill);
      bumpPostedThrough(holder, tmpl);
      lines.push({ kind: 'advance', index: bills.length - 1, label: bill.label, due, period: ym,
        window: mi ? cycleWindow(mi, ym) : null, apply: applied, settles: billOpen(bill) <= EPS, remaining: billOpen(bill) });
    }
  }
  const leftover = r2(queue.reduce((s, c) => s + c.amount, 0));
  return { bills, templates, lines, leftover, rest: queue, changed: lines.length > 0 };
}

// Move overpayments sitting on a charge's bills onto the tenant's open
// bills (then future cycles when it's the primary charge). Payment dates
// travel with the money, so cash-basis figures are unchanged. Whatever
// can't be placed goes back onto the bill it came from — nothing is lost.
function applyCredit(t, tmplId, opts) {
  opts = opts || {};
  const tmpl = ((t && t.templates) || []).find(x => x && x.id === tmplId);
  if(!tmpl || tmplRate(tmpl) <= 0) return null; // variable charges have no fixed amount to be "over"
  const primary = primaryTemplate(t);
  const src = { bills: _clone(t.bills || []), templates: t.templates, billing_model: t.billing_model, flat_rate: t.flat_rate, move_in_date: t.move_in_date };
  const { all, byPeriod } = templateBills(src, tmpl, primary === tmpl);
  const chunks = [];
  // Same scope as the checker: with a move-in date, only bills in a
  // counted cycle (the ones whose overpayment the checker reports).
  const mi = moveInOf(t);
  const from = mi && isISODate(opts.today) ? _reckonFrom(tmpl, byPeriod, primary === tmpl, ymOf(mi), String(opts.today).slice(0, 10)) : (mi ? ymOf(mi) : '');
  all.filter(i => !mi || (billPeriod(src.bills[i]) && billPeriod(src.bills[i]) >= from)).forEach(i => {
    const b = src.bills[i];
    if(_num(b.amount) <= 0) return;
    let over = r2(billTotalPaid(b) - _num(b.amount));
    if(over <= EPS) return;
    const pays = b.payments;
    for(let k = pays.length - 1; k >= 0 && over > EPS; k--) {
      const v = _num(pays[k].amount);
      const cut = r2(Math.min(v, over));
      if(cut <= EPS) continue;
      const ref = String(pays[k].note || '').trim();
      chunks.push({ amount: cut, date: isoOrEmpty(pays[k].date), note: (ref ? ref + ' · ' : '') + 'credit from ' + b.label + (billPeriod(b) ? ' (' + billPeriod(b) + ')' : ''), src: i, origNote: pays[k].note || '', rid: pays[k].rid || '' });
      pays[k].amount = r2(v - cut);
      over = r2(over - cut);
      if(pays[k].amount <= EPS) pays.splice(k, 1);
    }
    if(b.status !== 'paid' && billOpen(b) <= EPS) {
      b.status = 'paid';
      b.paidDate = b.paidDate || (pays.length ? isoOrEmpty(pays[pays.length - 1].date) : '') || '';
    }
  });
  if(!chunks.length) return null;
  const moved = allocatePayment(src, chunks, Object.assign({}, opts, { advance: primary === tmpl }));
  // Whatever couldn't be placed goes back on the bill it came from, with
  // its own payment date — cash-by-date figures never move.
  const byKey = new Map(chunks.map(c => [c.src + '|' + c.date + '|' + c.note, c]));
  moved.rest.forEach(r => {
    const home = moved.bills[r.src];
    if(!home) return;
    const orig = byKey.get(r.src + '|' + r.date + '|' + r.note);
    home.payments = home.payments || [];
    const back = { amount: r.amount, date: r.date, note: orig ? orig.origNote : '' };
    if(r.rid) back.rid = r.rid;
    home.payments.push(back);
  });
  return Object.assign(moved, { movedTotal: r2(chunks.reduce((s, c) => s + c.amount, 0) - moved.leftover) });
}

// Undo one Receive-payment receipt (rid): its entries leave every bill,
// bills it had settled reopen, and bills it posted early for cycles not
// yet due — now empty — are removed (not waived), with postedThrough
// rolled back so those cycles post normally when due. Pure.
function undoReceipt(t, rid, opts) {
  opts = opts || {};
  if(!rid || !t) return null;
  const today = isISODate(opts.today) ? String(opts.today).slice(0, 10) : '';
  const bills = _clone(t.bills || []);
  const templates = _clone(t.templates || []);
  let amount = 0, touched = 0;
  bills.forEach(b => {
    const pays = b.payments || [];
    const keep = pays.filter(p => p.rid !== rid);
    if(keep.length === pays.length) return;
    touched++;
    amount = r2(amount + pays.filter(p => p.rid === rid).reduce((s, p) => s + _num(p.amount), 0));
    // Marked paid beyond its logged payments: that implied balance was real
    // money on the paid date — log it, so removing the mistaken entry
    // reopens the bill instead of moving the cash to the paid date.
    const implied = b.status === 'paid' ? r2(_num(b.amount) - billTotalPaid(b)) : 0;
    if(implied > EPS) keep.push({ amount: implied, date: isoOrEmpty(b.paidDate), note: 'Balance marked paid' });
    b.payments = keep;
    if(b.status === 'paid' && billTotalPaid(b) < _num(b.amount) - EPS) { b.status = 'unpaid'; b.paidDate = ''; }
    if(/paid in advance/i.test(b.remark || '') && billTotalPaid(b) <= EPS) b.remark = '';
  });
  if(!touched) return null;
  const drop = new Set();
  bills.forEach((b, i) => {
    if(b.rid === rid && b.status !== 'paid' && billTotalPaid(b) <= EPS && isISODate(b.due) && (!today || b.due > today)) drop.add(i);
  });
  drop.forEach(i => {
    const b = bills[i];
    const tm = templates.find(x => x && x.id === b.tmplId);
    if(tm && isYM(b.period) && isYM(tm.postedThrough) && b.period <= tm.postedThrough) tm.postedThrough = addYM(b.period, -1);
  });
  const kept = bills.filter((b, i) => !drop.has(i));
  // A kept early bill still carries money from another receipt: hand the
  // "posted early by" mark to it, so undoing that one can still remove it.
  kept.forEach(b => {
    if(b.rid !== rid) return;
    const other = (b.payments || []).find(p => p.rid && p.rid !== rid);
    if(other) b.rid = other.rid; else delete b.rid;
  });
  const holder = { bills: kept, templates, billing_model: t.billing_model, flat_rate: t.flat_rate };
  templates.forEach(tm => { if(tm) bumpPostedThrough(holder, tm); });
  return { bills: kept, templates, amount, touched, removed: drop.size };
}

// Create bills for the given (missing) cycles of a template. Pure.
function backfillCycles(t, tmplId, periods, opts) {
  opts = opts || {};
  const bills = _clone((t && t.bills) || []);
  const templates = _clone((t && t.templates) || []);
  const tmpl = templates.find(x => x && x.id === tmplId);
  if(!tmpl) return null;
  const added = [];
  const holder = { bills, templates, billing_model: t && t.billing_model, flat_rate: t && t.flat_rate };
  (periods || []).filter(isYM).sort().forEach(ym => {
    if(templateBillExists(holder, tmpl, ym)) return;
    const b = makeTemplateBill(tmpl, ym, templateDueDate(t, tmpl, ym));
    bills.push(b);
    added.push(b);
  });
  bumpPostedThrough(holder, tmpl);
  return { bills, templates, added };
}

// Mark cycles as waived so the checker stops listing them. Pure.
function waiveCycles(t, tmplId, periods) {
  const templates = _clone((t && t.templates) || []);
  const tmpl = templates.find(x => x && x.id === tmplId);
  if(!tmpl) return null;
  const set = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
  (periods || []).filter(isYM).forEach(p => set.add(p));
  tmpl.skip = Array.from(set).sort();
  return { templates };
}

// ── MOVE-OUT ──────────────────────────────────────────────────────────────
// What archiving a tenant does to their bills. `lastDay` = last day in the
// unit. A bill for a cycle that starts after it (rent and other fixed
// charges; an unfilled metered placeholder for a later month):
//   nothing received  → removed (never owed)
//   money received    → opts.prepaid 'refund': amount ₱0 and the money paid
//                       back on opts.refundDate (a dated negative payment,
//                       so cash reports show the receipt and the refund);
//                       'keep': left as is — forfeited, and recognized at
//                       move-out (see billRecognition)
// Everything else stays; whatever is unpaid is still owed. Pure.
// When the service a bill pays for starts: its cycle for rent and any
// fixed-amount recurring charge (Internet, a flat Water fee, an inclusive
// "Room + utilities" charge — tagged or matched by name). Metered bills
// and one-offs are for usage already consumed: '' (never "after move-out").
function _billStart(t, b) {
  const w = billCoverageWindow(t, b);
  if(w) return w.start;
  const tm = templateOfBill(t, b);
  if(!tm || !(tmplRate(tm) > 0)) return '';
  const period = billPeriod(b);
  if(!period) return '';
  const mi = moveInOf(t);
  if(mi && period >= ymOf(mi)) return cycleWindow(mi, period).start;
  return isoOrEmpty(b.due) || dateInMonth(period, 1);
}
function planMoveOut(t, lastDay, opts) {
  opts = opts || {};
  const out = { bills: [], templates: _clone((t && t.templates) || []), removed: [], prepaid: [], prepaidTotal: 0, owed: 0, awaiting: [] };
  if(!isISODate(lastDay)) return out;
  const refundDate = isISODate(opts.refundDate) ? String(opts.refundDate).slice(0, 10) : lastDay;
  const snap = b => ({ amount: b.amount, status: b.status, paidDate: b.paidDate || '', remark: b.remark || '', payments: _clone(b.payments || []) });
  _clone((t && t.bills) || []).forEach(b => {
    if(!b) return;
    const start = _billStart(t, b);
    if(start && start > lastDay) {
      const got = r2(billSettled(b));
      if(got <= EPS) { out.removed.push(b); return; }
      out.prepaid.push({ label: b.label, period: billPeriod(b), amount: got });
      out.prepaidTotal = r2(out.prepaidTotal + got);
      if(opts.prepaid === 'refund') {
        b.preMoveOut = snap(b);
        // Any receipt implied by "marked paid" stays on its paid date (see
        // billCashEvents), so receipt − refund nets to zero.
        b.payments = (b.payments || []).concat([{ amount: -got, date: refundDate, note: 'Refunded on move-out' }]);
        b.amount = 0;
        b.status = 'paid';
        b.paidDate = b.paidDate || refundDate;
        b.remark = 'Refunded on move-out (' + got.toFixed(2).replace(/\.00$/, '') + ')';
      } else if(opts.prepaid === 'keep') {
        // Forfeited: settled at what was received — nothing more is owed.
        b.preMoveOut = snap(b);
        b.amount = got;
        b.status = 'paid';
        b.paidDate = b.paidDate || ((b.payments || []).map(p => isoOrEmpty(p.date)).filter(Boolean).sort().pop() || lastDay);
        b.remark = 'Forfeited on move-out';
      }
    } else {
      if(billAwaitingAmount(b)) out.awaiting.push(b);
      out.owed = r2(out.owed + billOpen(b));
    }
    out.bills.push(b);
  });
  // Removed cycles post again normally if the tenant is ever restored.
  out.removed.forEach(b => {
    const tm = out.templates.find(x => x && x.id === b.tmplId);
    if(tm && isYM(b.period) && isYM(tm.postedThrough) && b.period <= tm.postedThrough) tm.postedThrough = addYM(b.period, -1);
  });
  return out;
}

// Reverse a move-out when an archive is undone: bills it refunded or
// marked forfeited go back to how they were (removed unpaid cycles post
// again on their own — planMoveOut rolled postedThrough back). Pure.
function undoMoveOut(t) {
  const bills = _clone((t && t.bills) || []);
  let n = 0;
  bills.forEach(b => {
    if(!b || !b.preMoveOut) return;
    const pm = b.preMoveOut;
    b.amount = pm.amount; b.status = pm.status; b.paidDate = pm.paidDate; b.remark = pm.remark; b.payments = pm.payments;
    delete b.preMoveOut;
    n++;
  });
  return { bills, restored: n };
}

// A former tenant's bill for a cycle that starts after their last day:
// only money actually received on it counts, earned on the last day (the
// unpaid rest was never owed). null = not such a bill.
function _postMoveOut(t, b) {
  const out = moveOutOf(t);
  if(!out || !b) return null;
  const start = _billStart(t, b);
  if(!start || start <= out) return null;
  return { amount: r2(Math.min(_num(b.amount), billSettled(b))), ym: ymOf(out) };
}

// ── REVENUE RECOGNITION ───────────────────────────────────────────────────
// Rent and fixed recurring charges are earned over the cycle they pay
// for; with `prorate` their amount is spread over that cycle's days
// (straight-line). Utilities, one-off charges — and every charge when
// prorate is off — are recognized in their billing period. Returns [{ym, amount}], ym '' when
// the bill carries no date at all.
function billCoverageWindow(t, b) {
  // Rent and other fixed recurring charges accrue over their cycle.
  // Utilities are billed for consumption already used — point in time.
  const cat = billCategory(b);
  if(!(cat === 'rent' || (b.tmplId && cat !== 'utilities'))) return null;
  const period = billPeriod(b);
  if(!period) return null;
  const mi = moveInOf(t);
  if(mi && period >= ymOf(mi)) return cycleWindow(mi, period); // move-in is the reckoning date
  const due = isoOrEmpty(b.due);
  if(!due) return null;
  const nextYM = addYM(ymOf(due), 1);
  return { start: due, end: dateInMonth(nextYM, Number(due.slice(8, 10))) };
}

// A former tenant's last day in the unit (archived_at, local date).
function moveOutOf(t) { return t && t.archived_at ? _localDate(t.archived_at) : ''; }
function billRecognition(t, b, prorate) {
  const amt = r2(b && b.amount);
  if(!amt) return [];
  // Nothing is earned after a tenant moves out: a cycle running past the
  // last day is earned by then, and one starting after it (kept, i.e.
  // forfeited, prepaid rent) is earned on the day they leave.
  const pm = _postMoveOut(t, b);
  if(pm) return pm.amount > EPS ? [{ ym: pm.ym, amount: pm.amount }] : [];
  const out = moveOutOf(t);
  if(prorate) {
    let w = billCoverageWindow(t, b);
    if(w && out) {
      const cap = addDaysISO(out, 1);
      if(w.end > cap) w = { start: w.start, end: cap };
    }
    const total = w ? diffDays(w.start, w.end) : 0;
    if(total > 0) {
      const segs = [];
      let cur = w.start, left = amt, daysLeft = total;
      while(daysLeft > 0) {
        const ym = ymOf(cur);
        const monthEnd = addDaysISO(lastDayOf(ym), 1);
        const segEnd = monthEnd < w.end ? monthEnd : w.end;
        const days = diffDays(cur, segEnd);
        const part = segEnd === w.end ? left : r2(amt * days / total);
        segs.push({ ym, amount: part });
        left = r2(left - part);
        daysLeft -= days;
        cur = segEnd;
      }
      return segs;
    }
  }
  const ym = billPeriod(b) || (b.status === 'paid' ? ymOf(b.paidDate) : '');
  return [{ ym, amount: amt }];
}

// ── REPORTS ───────────────────────────────────────────────────────────────
const EXPENSE_CATEGORY_KEYS = ['electricity', 'water', 'internet', 'maintenance', 'taxes', 'other'];
function _expCat(k) { return EXPENSE_CATEGORY_KEYS.includes(k) ? k : 'other'; }
function floorKey(t) { return String((t && t.floor) || '').trim(); }
// Floors compare by a folded key (case and spacing ignored), so '3rd floor',
// '3rd  Floor' and '3RD FLOOR ' are one floor, shown by the first spelling
// seen. floorCanon(spellings) → fn(spelling) → that canonical spelling.
function floorNorm(s) { return String(s == null ? '' : s).trim().replace(/\s+/g, ' ').toLowerCase(); }
function floorCanon(spellings) {
  const m = new Map();
  (spellings || []).forEach(s => { const k = floorNorm(s); if(k && !m.has(k)) m.set(k, String(s).trim().replace(/\s+/g, ' ')); });
  return s => m.get(floorNorm(s)) || '';
}
function _emptyRev() { return { rent: 0, utilities: 0, other: 0, total: 0 }; }
function _emptyExp() { const o = { total: 0 }; EXPENSE_CATEGORY_KEYS.forEach(k => { o[k] = 0; }); return o; }
function _addRev(o, cat, v) { o[cat] = r2(o[cat] + v); o.total = r2(o.total + v); }
function _addExp(o, cat, v) { o[cat] = r2(o[cat] + v); o.total = r2(o.total + v); }

// A timestamp (archived_at is written as UTC ISO) as a LOCAL calendar date,
// so archiving just after midnight in Manila isn't read as the day before.
function _localDate(ts) {
  const s = String(ts || '');
  if(!s) return '';
  if(/T\d/.test(s)) {
    const d = new Date(s);
    if(!isNaN(d.getTime())) return d.getFullYear() + '-' + _pad2(d.getMonth() + 1) + '-' + _pad2(d.getDate());
  }
  return isoOrEmpty(s.slice(0, 10));
}

// Was the tenant in the building during month `ym`? From the move-in date
// (else their earliest bill) to the archive date.
function occupiedInMonth(t, ym) {
  let start = moveInOf(t);
  if(!start) {
    let first = '';
    (t.bills || []).forEach(b => { const p = billPeriod(b); if(p && (!first || p < first)) first = p; });
    if(!first) return false;
    start = first + '-01';
  }
  const end = _localDate(t.archived_at);
  return start <= lastDayOf(ym) && (!end || end >= ym + '-01');
}

// Cash received toward a bill up to and including `endISO` (unknown dates
// count as received). Amount recognized as revenue through month `endYM`.
function _cashThrough(b, endISO) {
  return r2(billCashEvents(b).reduce((s, e) => s + ((!e.date || e.date <= endISO) ? e.amount : 0), 0));
}
function _recognizedThrough(t, b, endYM, prorate) {
  return r2(billRecognition(t, b, prorate).reduce((s, g) => s + ((!g.ym || g.ym <= endYM) ? g.amount : 0), 0));
}

// The whole income statement as numbers. params:
//   tenants     every tenant row, archived included (past income counts)
//   expenses    expense rows ({expense_date, category, amount, floor?})
//   from, to    'YYYY-MM' range (ignored when allTime)
//   allTime     include undated items too
//   basis       'accrual' (default) | 'cash'
//   prorate     accrual: spread recurring charges over their cycle days
//   allocation  shared (untagged) expenses → floors: 'headcount' | 'revenue' | 'none'
//   hasExpenses false = expenses ledger unavailable (income only)
// Returns { months, floors, columns{key→col}, total, unallocated, perMonth, memo, undated }.
function computeIncomeStatement(params) {
  const P = Object.assign({ basis: 'accrual', prorate: true, allocation: 'headcount', hasExpenses: true }, params || {});
  const tenants = P.tenants || [];
  const expenses = P.hasExpenses ? (P.expenses || []) : [];
  const months = ymRange(P.from, P.to);
  const inRange = new Set(months);
  const rFrom = months[0], rTo = months[months.length - 1];
  const endISO = rTo ? lastDayOf(rTo) : '';
  const accrual = P.basis !== 'cash';

  // Floors: every tenant floor plus any floor an expense is tagged with.
  const canon = P.floorCanon || floorCanon(tenants.map(t => t && t.floor).concat(expenses.map(x => x && x.floor)));
  const fk = t => canon(t && t.floor);
  const floorSet = new Set();
  tenants.forEach(t => floorSet.add(fk(t)));
  expenses.forEach(x => { const f = canon(x.floor); if(f) floorSet.add(f); });
  const floors = Array.from(floorSet);

  const col = () => ({ revenue: _emptyRev(), direct: _emptyExp(), shared: _emptyExp(), expenses: 0, net: 0 });
  const columns = {}; floors.forEach(f => { columns[f] = col(); });
  const revByMonth = {}; floors.forEach(f => { revByMonth[f] = {}; months.forEach(m => { revByMonth[f][m] = 0; }); });
  const undated = {}; floors.forEach(f => { undated[f] = _emptyRev(); });

  // Revenue
  tenants.forEach(t => {
    const f = fk(t);
    (t.bills || []).forEach(b => {
      if(!b) return;
      const cat = billCategory(b);
      if(accrual) {
        billRecognition(t, b, P.prorate).forEach(g => {
          if(g.ym ? inRange.has(g.ym) : P.allTime) {
            _addRev(columns[f].revenue, cat, g.amount);
            if(g.ym) revByMonth[f][g.ym] = r2(revByMonth[f][g.ym] + g.amount);
            else _addRev(undated[f], cat, g.amount);
          }
        });
      } else {
        billCashEvents(b).forEach(e => {
          const ym = ymOf(e.date);
          if(ym ? inRange.has(ym) : P.allTime) {
            _addRev(columns[f].revenue, cat, e.amount);
            if(ym) revByMonth[f][ym] = r2(revByMonth[f][ym] + e.amount);
            else _addRev(undated[f], cat, e.amount);
          }
        });
      }
    });
  });

  // Expenses: floor-tagged = direct; untagged = shared, allocated per month.
  const unallocated = _emptyExp();
  const periodRev = {}; floors.forEach(f => { periodRev[f] = columns[f].revenue.total; });
  const weightsFor = ym => {
    const w = {};
    if(P.allocation === 'headcount') {
      floors.forEach(f => { w[f] = 0; });
      tenants.forEach(t => { if(occupiedInMonth(t, ym)) w[fk(t)] += 1; });
    } else if(P.allocation === 'revenue') {
      floors.forEach(f => { w[f] = Math.max(0, revByMonth[f][ym] || 0); });
      if(!floors.some(f => w[f] > 0)) floors.forEach(f => { w[f] = Math.max(0, periodRev[f]); });
    } else return null;
    const sum = floors.reduce((s, f) => s + w[f], 0);
    return sum > 0 ? { w, sum } : null;
  };
  const wCache = {};
  const expByMonth = {}; floors.forEach(f => { expByMonth[f] = {}; months.forEach(m => { expByMonth[f][m] = 0; }); });
  const totalExpByMonth = {}; months.forEach(m => { totalExpByMonth[m] = 0; });
  const total = col();
  expenses.forEach(x => {
    const ym = ymOf(x.expense_date);
    if(!inRange.has(ym)) return;
    const amt = r2(x.amount);
    if(!amt) return;
    const cat = _expCat(x.category);
    const tag = canon(x.floor);
    totalExpByMonth[ym] = r2(totalExpByMonth[ym] + amt);
    if(tag) {
      _addExp(total.direct, cat, amt);
      _addExp(columns[tag].direct, cat, amt);
      expByMonth[tag][ym] = r2(expByMonth[tag][ym] + amt);
      return;
    }
    _addExp(total.shared, cat, amt);
    if(!(ym in wCache)) wCache[ym] = weightsFor(ym);
    const W = wCache[ym];
    if(!W) { _addExp(unallocated, cat, amt); return; }
    let left = amt;
    const live = floors.filter(f => W.w[f] > 0);
    live.forEach((f, i) => {
      const part = i === live.length - 1 ? left : r2(amt * W.w[f] / W.sum);
      left = r2(left - part);
      _addExp(columns[f].shared, cat, part);
      expByMonth[f][ym] = r2(expByMonth[f][ym] + part);
    });
  });

  floors.forEach(f => {
    const c = columns[f];
    c.expenses = r2(c.direct.total + c.shared.total);
    c.net = r2(c.revenue.total - c.expenses);
  });
  floors.forEach(f => {
    ['rent', 'utilities', 'other'].forEach(k => _addRev(total.revenue, k, columns[f].revenue[k]));
  });
  total.expenses = r2(total.direct.total + total.shared.total);
  total.net = r2(total.revenue.total - total.expenses);

  // Month-by-month rows per floor and for the whole building.
  const perMonth = { __total: months.map(m => {
    const rev = r2(floors.reduce((s, f) => s + revByMonth[f][m], 0));
    return { ym: m, revenue: rev, expenses: totalExpByMonth[m], net: r2(rev - totalExpByMonth[m]) };
  }) };
  floors.forEach(f => {
    perMonth[f] = months.map(m => ({ ym: m, revenue: revByMonth[f][m], expenses: expByMonth[f][m], net: r2(revByMonth[f][m] - expByMonth[f][m]) }));
  });

  // Memo: collections (cash) and balance-sheet items at period end (accrual).
  const memo = {};
  const memoFor = list => {
    let billed = 0, collected = 0, outstanding = 0, receivable = 0, unearned = 0, billedAhead = 0, credits = 0;
    list.forEach(t => (t.bills || []).forEach(b => {
      if(!b) return;
      // After move-out only received money counts (see _postMoveOut).
      const pm = _postMoveOut(t, b);
      const p = pm ? pm.ym : billPeriod(b);
      const amt = pm ? pm.amount : r2(b.amount);
      if(p ? inRange.has(p) : P.allTime) billed = r2(billed + amt);
      billCashEvents(b).forEach(e => {
        const ym = ymOf(e.date);
        if(ym ? inRange.has(ym) : P.allTime) collected = r2(collected + e.amount);
      });
      if(!pm && b.status !== 'paid' && (P.allTime || (p && inRange.has(p)))) outstanding = r2(outstanding + billOpen(b));
      if(endISO) {
        // Gross presentation at period end, per bill:
        //   receivable   billed (cycle on/before period end) and not yet paid
        //   unearned     cash received for revenue not yet earned
        //   billedAhead  billed but neither paid nor earned yet
        //   credits      cash beyond the bill amount (tenant credit balance)
        // Identity: recognized − cash = receivable − unearned − billedAhead − credits.
        const R = _recognizedThrough(t, b, rTo, P.prorate && accrual);
        const C = _cashThrough(b, endISO);
        const billedByEnd = (!p || p <= rTo) ? amt : 0;
        const paidPart = Math.min(C, amt);
        receivable = r2(receivable + Math.max(0, billedByEnd - C));
        unearned = r2(unearned + Math.max(0, paidPart - R));
        billedAhead = r2(billedAhead + Math.max(0, Math.max(billedByEnd, paidPart) - Math.max(R, paidPart)));
        credits = r2(credits + Math.max(0, C - amt));
      }
    }));
    return { billed, collected, outstanding, receivable, unearned, billedAhead, credits,
      rate: billed > 0 ? Math.round(collected / billed * 100) : null };
  };
  floors.forEach(f => { memo[f] = memoFor(tenants.filter(t => fk(t) === f)); });
  memo.__total = memoFor(tenants);

  const undatedTotal = _emptyRev();
  floors.forEach(f => ['rent', 'utilities', 'other'].forEach(k => _addRev(undatedTotal, k, undated[f][k])));
  undated.__total = undatedTotal;

  // Floors in building order: numbered floors ascending, ground first,
  // unassigned last (the caller supplies a ranker for label-aware order).
  const rank = P.floorRank || (s => s);
  floors.sort((a, b) => { if(!a) return 1; if(!b) return -1; const r = rank(a) - rank(b); return (isNaN(r) ? 0 : r) || a.localeCompare(b); });

  return { months, from: rFrom, to: rTo, basis: accrual ? 'accrual' : 'cash', prorate: !!(accrual && P.prorate),
    floors, columns, total, unallocated, perMonth, memo, undated };
}

// ── ANALYTICS HELPERS (Insights module) ───────────────────────────────────
// Receivables aging by days past due, on the given `today`.
function agingBuckets(tenants, today) {
  const buckets = [
    { key: 'current', label: 'Not yet due', amount: 0, count: 0 },
    { key: 'd30', label: '1–30 days', amount: 0, count: 0 },
    { key: 'd60', label: '31–60 days', amount: 0, count: 0 },
    { key: 'd90', label: '61–90 days', amount: 0, count: 0 },
    { key: 'd90p', label: '90+ days', amount: 0, count: 0 },
    { key: 'nodate', label: 'No due date', amount: 0, count: 0 }
  ];
  (tenants || []).forEach(t => (t.bills || []).forEach(b => {
    const open = b ? billOpen(b) : 0;
    if(open <= EPS) return;
    const due = isoOrEmpty(b.due);
    const late = due ? diffDays(due, today) : 0;
    const k = !due ? 5 : late <= 0 ? 0 : late <= 30 ? 1 : late <= 60 ? 2 : late <= 90 ? 3 : 4;
    buckets[k].amount = r2(buckets[k].amount + open);
    buckets[k].count++;
  }));
  return buckets;
}

// Per-tenant punctuality over bills DUE in the window [fromYM, toYM] and
// already due by `today`: paid on/before the due date = on time; paid late,
// or still unpaid past the due date (late until today), = late. Future paid
// dates are typos → skipped.
function paymentReliability(tenants, fromYM, toYM, today) {
  const out = [];
  (tenants || []).forEach(t => {
    let n = 0, late = 0, lateDays = 0, unpaidLate = 0;
    (t.bills || []).forEach(b => {
      if(!b) return;
      const due = isoOrEmpty(b.due);
      if(!due || due >= today) return;
      const p = ymOf(due);
      if(p < fromYM || p > toYM) return;
      if(b.status === 'paid') {
        const pd = isoOrEmpty(b.paidDate);
        if(!pd || pd > today) return;
        const d = diffDays(due, pd);
        n++;
        if(d > 0) { late++; lateDays += d; }
      } else if(billOpen(b) > EPS) {
        n++; late++; unpaidLate++;
        lateDays += diffDays(due, today);
      }
    });
    if(n) out.push({ id: t.id, name: t.name, unit: t.unit, floor: floorKey(t), n, late, unpaidLate,
      onTimePct: Math.round((n - late) / n * 100), avgLate: late ? Math.round(lateDays / late) : 0 });
  });
  return out;
}

const BillingCore = {
  isYM, isISODate, isoOrEmpty, ymOf, addYM, daysInMonth, dateInMonth, lastDayOf, diffDays, addDaysISO, ymRange, r2,
  BILL_CATEGORIES, billCategory, billTotalPaid, billRemaining, billSettled, billOpen, billAwaitingAmount, billPeriod, normLabel, billCashEvents,
  tmplDay, tmplRate, tmplRateAt, isAutoTemplate, moveInOf, templateDueDate, primaryTemplate, templateBills, templateBillExists, makeTemplateBill,
  billOfTemplate, templateOfBill, bumpPostedThrough, planAutoPost, cycleWindow, reconcileCharge, reconcileTenant, allocatePayment, applyCredit, undoReceipt, backfillCycles, waiveCycles,
  planMoveOut, undoMoveOut, moveOutOf, activeTemplates, billCoverageWindow, billRecognition, occupiedInMonth, floorKey, floorNorm, floorCanon, computeIncomeStatement, agingBuckets, paymentReliability,
  EXPENSE_CATEGORY_KEYS
};
if(typeof module !== 'undefined' && module.exports) module.exports = BillingCore;
