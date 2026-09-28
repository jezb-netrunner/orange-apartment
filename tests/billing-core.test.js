// Run: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const BC = require('../billing-core.js');

let _n = 0;
const uid = () => 'id' + (++_n);
const rentT = (over) => Object.assign({ id: 'T1', label: 'Monthly Rent', amount: 6000, dayOfMonth: 5, pendingAmount: false }, over || {});
const tenant = (over) => Object.assign({ id: 'A', name: 'Ana', unit: '1', floor: '1st', bills: [], templates: [rentT()] }, over || {});
const bill = (over) => Object.assign({ label: 'Monthly Rent', amount: 6000, due: '', status: 'unpaid', payments: [], paidDate: '' }, over || {});
const cashSum = bills => bills.reduce((s, b) => s + BC.billCashEvents(b).reduce((a, e) => a + e.amount, 0), 0);

test('date helpers clamp and roll months', () => {
  assert.equal(BC.addYM('2026-12', 1), '2027-01');
  assert.equal(BC.addYM('2026-01', -1), '2025-12');
  assert.equal(BC.dateInMonth('2026-02', 31), '2026-02-28');
  assert.equal(BC.dateInMonth('2028-02', 31), '2028-02-29');
  assert.equal(BC.diffDays('2026-03-01', '2026-03-31'), 30);
  assert.equal(BC.addDaysISO('2026-03-01', -1), '2026-02-28');
  assert.equal(BC.isISODate('2026-02-30'), false);
  assert.deepEqual(BC.ymRange('2026-11', '2027-01'), ['2026-11', '2026-12', '2027-01']);
});

test('auto-post: posts current cycle inside lead window, never backfills', () => {
  const t = tenant({ templates: [rentT({ postedThrough: '2026-08' })] });
  const plan = BC.planAutoPost(t, { today: '2026-09-27', leadDays: 7, uid });
  // September (due Sep 5) is current and not yet posted → posted (catch-up);
  // October (due Oct 5) is 8 days out → outside a 7-day window.
  assert.equal(plan.bills.length, 1);
  assert.equal(plan.bills[0].period, '2026-09');
  assert.equal(plan.bills[0].due, '2026-09-05');
  assert.equal(plan.bills[0].tmplId, 'T1');
  assert.equal(plan.templates[0].postedThrough, '2026-09');
  const plan2 = BC.planAutoPost(t, { today: '2026-09-28', leadDays: 7, uid });
  assert.deepEqual(plan2.bills.map(b => b.period), ['2026-09', '2026-10']);
  // July is before postedThrough → never recreated.
  assert.ok(!plan2.bills.some(b => b.period < '2026-09'));
});

test('auto-post: first activation leaves an already-overdue cycle to the checker', () => {
  const t = tenant();
  const plan = BC.planAutoPost(t, { today: '2026-09-27', leadDays: 7, uid });
  assert.equal(plan.bills.length, 0);
  // Recorded as handled, so activation is a one-time event (checker lists September).
  assert.equal(plan.templates[0].postedThrough, '2026-09');
  const plan2 = BC.planAutoPost(t, { today: '2026-09-29', leadDays: 7, uid });
  assert.deepEqual(plan2.bills.map(b => b.period), ['2026-10']);
});

test('auto-post: legacy bill with the same label counts as posted; deleted bills are not recreated', () => {
  const t = tenant({ bills: [bill({ due: '2026-10-05' })] });
  const plan = BC.planAutoPost(t, { today: '2026-09-29', leadDays: 7, uid });
  assert.equal(plan.bills.length, 0);
  assert.equal(plan.templates[0].postedThrough, '2026-10');
  assert.equal(plan.changed, true);
  const after = tenant({ bills: [], templates: plan.templates });
  assert.equal(BC.planAutoPost(after, { today: '2026-10-02', leadDays: 7, uid }).bills.length, 0);
});

test('auto-post: respects move-in, auto:false, skip, archived; pending amount posts at 0', () => {
  const future = tenant({ move_in_date: '2026-10-20' });
  const p1 = BC.planAutoPost(future, { today: '2026-09-29', leadDays: 7, uid });
  assert.equal(p1.bills.length, 0); // Oct due clamps to move-in Oct 20 → outside window
  const p2 = BC.planAutoPost(future, { today: '2026-10-14', leadDays: 7, uid });
  assert.equal(p2.bills[0].due, '2026-10-20');
  assert.equal(BC.planAutoPost(tenant({ templates: [rentT({ auto: false })] }), { today: '2026-10-01', leadDays: 7 }).bills.length, 0);
  assert.equal(BC.planAutoPost(tenant({ templates: [rentT({ skip: ['2026-10'] })] }), { today: '2026-10-01', leadDays: 7 }).bills.length, 0);
  assert.equal(BC.planAutoPost(tenant({ archived_at: '2026-01-01' }), { today: '2026-10-01', leadDays: 7 }).bills.length, 0);
  const pend = BC.planAutoPost(tenant({ templates: [rentT({ label: 'Water', pendingAmount: true })] }), { today: '2026-10-01', leadDays: 7 });
  assert.equal(pend.bills[0].amount, 0);
  assert.match(pend.bills[0].remark, /Pending amount/);
});

test('auto-post: template without id gets one and bills reference it', () => {
  const t = tenant({ templates: [{ label: 'Monthly Rent', amount: 5000, dayOfMonth: 1 }] });
  const plan = BC.planAutoPost(t, { today: '2026-09-28', leadDays: 7, uid });
  assert.ok(plan.templates[0].id);
  assert.equal(plan.bills[0].tmplId, plan.templates[0].id);
});

test('reconcile: disabled without move-in date (no data touched)', () => {
  const t = tenant({ bills: [bill({ due: '2026-09-05' })] });
  const before = JSON.stringify(t);
  const r = BC.reconcileTenant(t, { today: '2026-09-27' });
  assert.equal(r.enabled, false);
  assert.equal(r.reason, 'no-move-in');
  assert.equal(JSON.stringify(t), before);
});

test('reconcile: annuity due cycles from move-in, advance payment → paid-through ahead', () => {
  // Moved in Jul 15; cycles Jul 15, Aug 15, Sep 15 have started by Sep 27.
  const t = tenant({ move_in_date: '2026-07-15', templates: [rentT({ dayOfMonth: 15 })], bills: [
    bill({ due: '2026-07-15', status: 'paid', paidDate: '2026-07-15', tmplId: 'T1', period: '2026-07' }),
    bill({ due: '2026-08-15', status: 'paid', paidDate: '2026-08-14', tmplId: 'T1', period: '2026-08' }),
    bill({ due: '2026-09-15', status: 'paid', paidDate: '2026-09-15', tmplId: 'T1', period: '2026-09' }),
    bill({ due: '2026-10-15', status: 'paid', paidDate: '2026-09-15', tmplId: 'T1', period: '2026-10', remark: 'Paid in advance' })
  ] });
  const r = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 7 }).charges[0];
  assert.equal(r.cyclesStarted, 3);
  assert.equal(r.covered, 4);
  assert.equal(r.paidThrough, '2026-11-14');
  assert.equal(r.status, 'advance');
  assert.equal(r.aheadCycles, 1);
  assert.equal(r.credit, 6000);
  assert.equal(r.arrears, 0);
  assert.deepEqual(r.missing, []);
});

test('reconcile: missing cycles and arrears; waived cycles cost nothing', () => {
  const t = tenant({ move_in_date: '2026-06-01', templates: [rentT({ dayOfMonth: 1 })], bills: [
    bill({ due: '2026-06-01', status: 'paid', paidDate: '2026-06-01' }),
    bill({ due: '2026-08-01' })
  ] });
  const r = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 7 }).charges[0];
  assert.equal(r.cyclesStarted, 4); // Jun..Sep
  assert.deepEqual(r.missing.map(m => m.period), ['2026-07', '2026-09']);
  assert.equal(r.paidThrough, '2026-06-30');
  assert.equal(r.status, 'behind');
  assert.equal(r.arrears, 18000);
  const waived = tenant(Object.assign({}, t, { templates: [rentT({ dayOfMonth: 1, skip: ['2026-07'] })] }));
  const r2 = BC.reconcileTenant(waived, { today: '2026-09-27', leadDays: 7 }).charges[0];
  assert.deepEqual(r2.missing.map(m => m.period), ['2026-09']);
  assert.equal(r2.paidThrough, '2026-07-31'); // July waived → free
  assert.equal(r2.arrears, 12000);
});

test('reconcile: fallback matches hand-typed rent labels for the primary charge only', () => {
  const t = tenant({ move_in_date: '2026-08-01', templates: [rentT({ dayOfMonth: 1 })], bills: [
    bill({ label: 'Rent - August', due: '2026-08-01', status: 'paid', paidDate: '2026-08-01' })
  ] });
  const r = BC.reconcileTenant(t, { today: '2026-08-20', leadDays: 7 }).charges[0];
  assert.deepEqual(r.missing, []);
  assert.equal(r.paidThrough, '2026-08-31');
});

test('allocate: FIFO oldest first, settles bills, advance posts future cycles', () => {
  const t = tenant({ move_in_date: '2026-09-10', templates: [rentT({ dayOfMonth: 10 })], bills: [
    bill({ label: 'Water', amount: 400, due: '2026-09-12' }),
    bill({ due: '2026-09-10', tmplId: 'T1', period: '2026-09' })
  ] });
  const res = BC.allocatePayment(t, [{ amount: 18400, date: '2026-09-20', note: 'GCash' }], { today: '2026-09-20', uid });
  assert.equal(res.leftover, 0);
  assert.deepEqual(res.lines.map(l => l.kind + ':' + (l.period)), ['bill:2026-09', 'bill:2026-09', 'advance:2026-10', 'advance:2026-11']);
  assert.equal(res.bills[1].status, 'paid'); // rent (due Sep 10) first
  assert.equal(res.bills[0].status, 'paid');
  assert.equal(res.bills[0].paidDate, '2026-09-20');
  const adv = res.bills.slice(2);
  assert.deepEqual(adv.map(b => [b.period, b.due, b.status]), [['2026-10', '2026-10-10', 'paid'], ['2026-11', '2026-11-10', 'paid']]);
  // First activation: postedThrough stays unset (auto-post marks cycles it finds).
  assert.equal(res.templates[0].postedThrough, undefined);
  assert.equal(cashSum(res.bills), 18400);
  // Original tenant untouched (pure).
  assert.equal(t.bills.length, 2);
  // Paid-through now reflects the advance.
  const r = BC.reconcileTenant(Object.assign({}, t, { bills: res.bills, templates: res.templates }), { today: '2026-09-20' }).charges[0];
  assert.equal(r.paidThrough, '2026-12-09');
});

test('allocate: partial last cycle stays open; no template → leftover reported', () => {
  const t = tenant({ templates: [rentT()], bills: [] });
  const res = BC.allocatePayment(t, [{ amount: 9000, date: '2026-09-20' }], { today: '2026-09-20', uid });
  assert.equal(res.leftover, 0);
  assert.equal(res.bills.length, 2);
  assert.equal(res.bills[1].status, 'unpaid');
  assert.equal(BC.billOpen(res.bills[1]), 3000);
  const none = tenant({ templates: [], bills: [bill({ amount: 100, due: '2026-09-01' })] });
  const r2 = BC.allocatePayment(none, [{ amount: 500, date: '2026-09-20' }], { today: '2026-09-20' });
  assert.equal(r2.leftover, 400);
});

test('applyCredit: moves overpayment with its original date; cash totals unchanged', () => {
  const t = tenant({ move_in_date: '2026-08-05', bills: [
    bill({ due: '2026-08-05', tmplId: 'T1', period: '2026-08', payments: [{ amount: 12000, date: '2026-08-03', note: 'cash' }] }),
    bill({ due: '2026-09-05', tmplId: 'T1', period: '2026-09' })
  ] });
  const r = BC.reconcileTenant(t, { today: '2026-09-10' }).charges[0];
  assert.equal(r.excess, 6000);
  assert.deepEqual(r.openCovered, [1]);
  const res = BC.applyCredit(t, 'T1', { today: '2026-09-10', uid });
  assert.equal(res.movedTotal, 6000);
  assert.equal(res.bills[0].status, 'paid');
  assert.equal(res.bills[1].status, 'paid');
  assert.equal(res.bills[1].payments[0].date, '2026-08-03');
  assert.equal(cashSum(res.bills), 12000);
});

test('backfill and waive are pure and idempotent', () => {
  const t = tenant({ move_in_date: '2026-06-01', templates: [rentT({ dayOfMonth: 1 })] });
  const b = BC.backfillCycles(t, 'T1', ['2026-07', '2026-06', '2026-07']);
  assert.deepEqual(b.added.map(x => x.period), ['2026-06', '2026-07']);
  assert.equal(t.bills.length, 0);
  const w = BC.waiveCycles(t, 'T1', ['2026-06', 'bad']);
  assert.deepEqual(w.templates[0].skip, ['2026-06']);
});

test('recognition: prorates recurring charges over the move-in cycle; one-offs point in time', () => {
  const t = tenant({ move_in_date: '2026-03-15' });
  const segs = BC.billRecognition(t, bill({ amount: 6000, due: '2026-03-15', period: '2026-03', tmplId: 'T1' }), true);
  // Mar 15 → Apr 15: 17 days in March, 14 in April (31 days).
  assert.deepEqual(segs.map(s => s.ym), ['2026-03', '2026-04']);
  assert.equal(segs[0].amount + segs[1].amount, 6000);
  assert.equal(segs[0].amount, Math.round(6000 * 17 / 31 * 100) / 100);
  assert.deepEqual(BC.billRecognition(t, bill({ label: 'Repair', amount: 800, due: '2026-03-20' }), true), [{ ym: '2026-03', amount: 800 }]);
  assert.deepEqual(BC.billRecognition(t, bill({ amount: 6000, due: '2026-03-15' }), false), [{ ym: '2026-03', amount: 6000 }]);
});

test('income statement: accrual vs cash, advances are unearned', () => {
  const t = tenant({ bills: [
    bill({ due: '2026-09-01', status: 'paid', paidDate: '2026-09-01' }),
    bill({ due: '2026-10-01', status: 'paid', paidDate: '2026-09-01', period: '2026-10', tmplId: 'T1' }),
    bill({ label: 'Water', amount: 500, due: '2026-09-10' })
  ] });
  const base = { tenants: [t], expenses: [{ expense_date: '2026-09-15', category: 'water', amount: 700 }], from: '2026-09', to: '2026-09' };
  const acc = BC.computeIncomeStatement(Object.assign({ basis: 'accrual', prorate: false }, base));
  assert.equal(acc.total.revenue.total, 6000);                 // water billed back is pass-through, not revenue
  assert.equal(acc.total.passThrough.billed, 500);
  assert.equal(acc.total.passThrough.outstanding, 500);
  // The ₱500 water billed back offsets the ₱700 water cost: only ₱200 is the building's.
  assert.equal(acc.total.recovered.water, 500);
  assert.equal(acc.total.expenses, 200);
  assert.equal(acc.total.net, 5800);
  assert.equal(acc.memo.__total.receivable, 0);
  assert.equal(acc.memo.__total.unearned, 6000);
  const cash = BC.computeIncomeStatement(Object.assign({ basis: 'cash' }, base));
  assert.equal(cash.total.revenue.total, 12000);
  assert.equal(cash.total.net, 11300);                          // nothing recovered in cash yet
});

test('income statement: per-floor with direct + shared allocation by occupied units', () => {
  const a = tenant({ id: 'A', floor: '1st', move_in_date: '2026-01-01', bills: [bill({ due: '2026-09-01', status: 'paid', paidDate: '2026-09-01' })] });
  const b = tenant({ id: 'B', floor: '2nd', move_in_date: '2026-01-01', bills: [bill({ amount: 4000, due: '2026-09-01' })] });
  const c = tenant({ id: 'C', unit: '2', floor: '2nd', move_in_date: '2026-01-01', bills: [] });
  const ex = [
    { expense_date: '2026-09-02', category: 'electricity', amount: 900, floor: '' },   // shared
    { expense_date: '2026-09-03', category: 'maintenance', amount: 300, floor: '2nd' } // direct
  ];
  const is = BC.computeIncomeStatement({ tenants: [a, b, c], expenses: ex, from: '2026-09', to: '2026-09', basis: 'accrual', prorate: false, allocation: 'units' });
  assert.equal(is.columns['1st'].shared.electricity, 300);
  assert.equal(is.columns['2nd'].shared.electricity, 600);
  assert.equal(is.columns['2nd'].direct.maintenance, 300);
  assert.equal(is.columns['2nd'].net, 4000 - 900);
  assert.equal(is.total.expenses, 1200);
  const sumNet = is.floors.reduce((s, f) => s + is.columns[f].net, 0);
  assert.equal(sumNet, is.total.net);
  const none = BC.computeIncomeStatement({ tenants: [a, b, c], expenses: ex, from: '2026-09', to: '2026-09', allocation: 'none', prorate: false });
  assert.equal(none.unallocated.total, 900);
  assert.equal(none.columns['1st'].expenses, 0);
});

test('income statement: archived tenant history still counts; aging buckets', () => {
  const gone = tenant({ archived_at: '2026-08-31T00:00:00Z', bills: [bill({ due: '2026-08-01', status: 'paid', paidDate: '2026-08-02' })] });
  const is = BC.computeIncomeStatement({ tenants: [gone], expenses: [], from: '2026-08', to: '2026-08', basis: 'cash' });
  assert.equal(is.total.revenue.total, 6000);
  const ag = BC.agingBuckets([tenant({ bills: [bill({ due: '2026-09-01' }), bill({ due: '2026-06-01', amount: 100 }), bill({ due: '2026-10-01', amount: 50 })] })], '2026-09-27');
  assert.equal(ag[0].amount, 50);
  assert.equal(ag[1].amount, 6000);
  assert.equal(ag[4].amount, 100);
});

test('reconcile: variable (pending-amount) charges are gap-checked only from their first bill', () => {
  const t = tenant({ move_in_date: '2026-03-15', templates: [rentT({ id: 'W', label: 'Water', pendingAmount: true, amount: 0, dayOfMonth: 20 })], bills: [
    bill({ label: 'Water', amount: 400, due: '2026-08-20', tmplId: 'W', period: '2026-08', status: 'paid', paidDate: '2026-08-21' })
  ] });
  const r = BC.reconcileTenant(t, { today: '2026-10-25', leadDays: 7 }).charges[0];
  assert.equal(r.variable, true);
  assert.deepEqual(r.missing.map(m => m.period), ['2026-09', '2026-10']);
});

// ── Regression tests from the code review ──
test('deleted + re-added charge (same name) keeps its history: no double bill, no false gaps', () => {
  const tagged = p => bill({ due: p + '-05', tmplId: 'OLD', period: p, status: 'paid', paidDate: p + '-05' });
  const t = tenant({ move_in_date: '2026-07-05', templates: [rentT({ id: 'NEW' })], bills: ['2026-07', '2026-08', '2026-09', '2026-10'].map(tagged) });
  const plan = BC.planAutoPost(t, { today: '2026-09-29', leadDays: 7, uid });
  assert.equal(plan.bills.length, 0);
  const r = BC.reconcileTenant(t, { today: '2026-09-29', leadDays: 7 }).charges[0];
  assert.deepEqual(r.missing, []);
  assert.equal(r.status, 'advance');
  // A renamed charge still owns its untagged legacy bills through aliases.
  const renamed = tenant({ templates: [rentT({ label: 'Rent', aliases: ['Monthly Rent'] })], bills: [bill({ due: '2026-10-05' })] });
  assert.equal(BC.planAutoPost(renamed, { today: '2026-09-29', leadDays: 7, uid }).bills.length, 0);
});

test('postedThrough never jumps over an unposted cycle', () => {
  const tm = rentT({ dayOfMonth: 15, postedThrough: '2026-08' });
  const t = tenant({ templates: [tm], bills: [bill({ due: '2026-10-15', tmplId: 'T1', period: '2026-10' })] });
  BC.bumpPostedThrough(t, tm);
  assert.equal(tm.postedThrough, '2026-08'); // September is still missing
  const plan = BC.planAutoPost(t, { today: '2026-09-10', leadDays: 7, uid });
  assert.deepEqual(plan.bills.map(b => b.period), ['2026-09']);
});

test('reconcile ignores bills before the move-in month (no false "current")', () => {
  const t = tenant({ move_in_date: '2026-06-01', templates: [rentT({ dayOfMonth: 1 })], bills:
    ['2026-03', '2026-04', '2026-05', '2026-06'].map(p => bill({ due: p + '-01', status: 'paid', paidDate: p + '-01' }))
      .concat(['2026-07', '2026-08', '2026-09'].map(p => bill({ due: p + '-01' }))) });
  const r = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 7 }).charges[0];
  assert.equal(r.status, 'behind');
  assert.equal(r.arrears, 18000);
  assert.equal(r.paidThrough, '2026-06-30');
  assert.equal(r.ignored, 3);
});

test('due day before the move-in day: an unpaid bill past its due date is arrears, on-time is not "ahead"', () => {
  const mk = (st) => tenant({ move_in_date: '2026-07-20', templates: [rentT({ dayOfMonth: 1 })], bills: [
    bill({ due: '2026-07-20', period: '2026-07', tmplId: 'T1', status: 'paid', paidDate: '2026-07-20' }),
    bill({ due: '2026-08-01', period: '2026-08', tmplId: 'T1', status: 'paid', paidDate: '2026-08-01' }),
    bill({ due: '2026-09-01', period: '2026-09', tmplId: 'T1', status: st, paidDate: st === 'paid' ? '2026-09-01' : '' })] });
  const behind = BC.reconcileTenant(mk('unpaid'), { today: '2026-09-15' }).charges[0];
  assert.equal(behind.status, 'behind');
  assert.equal(behind.arrears, 6000);
  const onTime = BC.reconcileTenant(mk('paid'), { today: '2026-09-15' }).charges[0];
  assert.equal(onTime.status, 'current');
  assert.equal(onTime.aheadCycles, 0);
});

test('applyCredit returns unplaced cash to its own bill and date', () => {
  const park = { id: 'P', label: 'Parking', amount: 1000, dayOfMonth: 1, pendingAmount: false };
  const t = tenant({ templates: [park], bills: [
    bill({ label: 'Parking', amount: 1000, due: '2026-01-01', tmplId: 'P', period: '2026-01', status: 'paid', paidDate: '2026-01-01', payments: [{ amount: 1500, date: '2026-01-01' }] }),
    bill({ label: 'Parking', amount: 1000, due: '2026-03-01', tmplId: 'P', period: '2026-03', status: 'paid', paidDate: '2026-03-01', payments: [{ amount: 1500, date: '2026-03-01' }] }),
    bill({ label: 'Repair', amount: 300, due: '2026-04-01' })] });
  const byMonth = bills => { const m = {}; bills.forEach(b => BC.billCashEvents(b).forEach(e => { const k = e.date.slice(0, 7); m[k] = (m[k] || 0) + e.amount; })); return m; };
  const before = byMonth(t.bills);
  const res = BC.applyCredit(t, 'P', { today: '2026-04-10', uid });
  assert.equal(res.movedTotal, 300);
  assert.deepEqual(byMonth(res.bills), before);
  assert.equal(res.bills[2].status, 'paid');
});

test('advance payment does not duplicate a hand-typed rent bill for the month', () => {
  const t = tenant({ templates: [rentT({ dayOfMonth: 5 })], bills: [bill({ label: 'Rent – September', due: '2026-09-05', status: 'paid', paidDate: '2026-09-05' })] });
  const res = BC.allocatePayment(t, [{ amount: 6000, date: '2026-09-20' }], { today: '2026-09-20', uid });
  assert.deepEqual(res.lines.map(l => l.period), ['2026-10']);
});

test('memo identity holds for random data: recognized − cash = receivable − unearned − billedAhead − credits', () => {
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  for(let n = 0; n < 200; n++) {
    const months = ['2026-06', '2026-07', '2026-08', '2026-09', '2026-10', '2026-11'];
    const bills = Array.from({ length: 6 }, () => {
      const p = months[Math.floor(rnd() * months.length)];
      const amt = Math.round(rnd() * 8000);
      const paidAll = rnd() < 0.4;
      const pays = rnd() < 0.5 ? [{ amount: Math.round(rnd() * amt * 1.3), date: months[Math.floor(rnd() * 4)] + '-10' }] : [];
      return bill({ label: rnd() < 0.7 ? 'Monthly Rent' : 'Water', amount: amt, due: p + '-05', period: p, tmplId: 'T1',
        status: paidAll ? 'paid' : 'unpaid', paidDate: paidAll ? p + '-06' : '', payments: pays });
    });
    const t = tenant({ move_in_date: '2026-03-12', bills });
    for(const prorate of [true, false]) {
      const is = BC.computeIncomeStatement({ tenants: [t], expenses: [], from: '2026-06', to: '2026-08', basis: 'accrual', prorate });
      const m = is.memo.__total;
      let R = 0, C = 0;
      bills.filter(b => !BC.isPassThrough(b)).forEach(b => {
        BC.billRecognition(t, b, prorate).forEach(g => { if(!g.ym || g.ym <= '2026-08') R += g.amount; });
        BC.billCashEvents(b).forEach(e => { if(!e.date || e.date <= '2026-08-31') C += e.amount; });
      });
      const lhs = Math.round((R - C) * 100) / 100;
      const rhs = Math.round((m.receivable - m.unearned - m.billedAhead - m.credits) * 100) / 100;
      assert.ok(Math.abs(lhs - rhs) < 0.05, `case ${n} prorate=${prorate}: ${lhs} vs ${rhs}`);
    }
  }
});

test('auto-post catches up a missed month for an active template; stale templates never pile up overdue bills', () => {
  const active = tenant({ templates: [rentT({ dayOfMonth: 28, postedThrough: '2026-09' })] });
  // Nobody opened the portal Oct 21–31; on Nov 3 October is still posted.
  const p = BC.planAutoPost(active, { today: '2026-11-03', leadDays: 7, uid });
  assert.deepEqual(p.bills.map(b => b.period), ['2026-10']);
  assert.equal(p.templates[0].postedThrough, '2026-10');
  // Restored after months away: overdue current cycle is not posted.
  const stale = tenant({ templates: [rentT({ dayOfMonth: 5, postedThrough: '2026-05' })] });
  const s = BC.planAutoPost(stale, { today: '2026-09-27', leadDays: 7, uid });
  assert.equal(s.bills.length, 0);
  assert.equal(s.templates[0].postedThrough, '2026-09');
});

test('primary template is order-independent; waived-but-billed cycles count; due-today is not arrears', () => {
  const t = tenant({ templates: [{ id: 'P', label: 'Parking rent', amount: 500, dayOfMonth: 1 }, rentT()] });
  assert.equal(BC.primaryTemplate(t).id, 'T1');
  const w = tenant({ move_in_date: '2026-09-01', templates: [rentT({ dayOfMonth: 1, skip: ['2026-09'] })], bills: [bill({ due: '2026-09-01', tmplId: 'T1', period: '2026-09' })] });
  const r = BC.reconcileTenant(w, { today: '2026-09-20' }).charges[0];
  assert.equal(r.status, 'behind');
  assert.equal(r.arrears, 6000);
  const d = tenant({ move_in_date: '2026-09-20', templates: [rentT({ dayOfMonth: 20 })], bills: [bill({ due: '2026-09-20', tmplId: 'T1', period: '2026-09' })] });
  assert.equal(BC.reconcileTenant(d, { today: '2026-09-20' }).charges[0].status, 'current');
});

// ── Round-2 review regressions ──
const paidBill = (ym, over) => bill(Object.assign({ due: ym + '-05', status: 'paid', paidDate: ym + '-05' }, over || {}));
const months = (from, to) => BC.ymRange(from, to);

test('a charge added mid-tenancy is reckoned from when it was set up, not from move-in', () => {
  const t = tenant({ move_in_date: '2026-01-10',
    templates: [rentT({ dayOfMonth: 10 }), { id: 'P', label: 'Parking', amount: 500, dayOfMonth: 10, since: '2026-09' }],
    bills: months('2026-01', '2026-09').map(ym => paidBill(ym, { due: ym + '-10', paidDate: ym + '-10' })) });
  const r = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 3 });
  const park = r.charges.find(c => c.tmplId === 'P');
  assert.equal(park.startYM, '2026-09');
  assert.deepEqual(park.missing.map(m => m.period), ['2026-09']);
  assert.equal(park.arrears, 500);
  // A legacy template with no `since` and no bills: nothing before today's cycle.
  delete t.templates[1].since;
  const park2 = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 3 }).charges.find(c => c.tmplId === 'P');
  assert.equal(park2.startYM, '2026-09');
  // The main rent is still reckoned from move-in.
  assert.equal(r.charges.find(c => c.tmplId === 'T1').startYM, '2026-01');
});

test('hand-typed history under other labels counts as the rent cycle; balances do not', () => {
  const t = tenant({ move_in_date: '2026-03-01', templates: [rentT({ dayOfMonth: 1 })],
    bills: months('2026-03', '2026-05').map(ym => paidBill(ym, { label: 'Upa - ' + ym, due: ym + '-01' }))
      .concat(months('2026-06', '2026-09').map(ym => paidBill(ym, { label: 'Monthly Bill ' + ym, due: ym + '-01' }))) });
  const c = BC.reconcileTenant(t, { today: '2026-09-15', leadDays: 3 }).charges[0];
  assert.equal(c.status, 'current');
  assert.equal(c.missing.length, 0);
  assert.equal(c.arrears, 0);
  // A carried-over balance is not "the rent" for its month.
  const t2 = tenant({ move_in_date: '2026-09-01', templates: [rentT({ dayOfMonth: 1, postedThrough: '2026-08' })],
    bills: [bill({ label: 'Rent balance from August', amount: 1500, due: '2026-09-03' })] });
  assert.equal(BC.templateBillExists(t2, t2.templates[0], '2026-09'), false);
});

test('a rate change keeps past cycles at the old price and never double-posts a hand-typed rent', () => {
  const tmpl = rentT({ amount: 7000, rates: [{ until: '2026-08', amount: 6000 }] });
  assert.equal(BC.tmplRateAt(tmpl, '2026-07'), 6000);
  assert.equal(BC.tmplRateAt(tmpl, '2026-09'), 7000);
  const t = tenant({ move_in_date: '2026-03-05', templates: [tmpl],
    bills: months('2026-03', '2026-09').filter(ym => ym !== '2026-07').map(ym => paidBill(ym)) });
  const c = BC.reconcileTenant(t, { today: '2026-09-20', leadDays: 3 }).charges[0];
  assert.deepEqual(c.missing.map(m => [m.period, m.amount]), [['2026-07', 6000]]);
  assert.equal(c.arrears, 6000);
  const fill = BC.backfillCycles(t, 'T1', ['2026-07']);
  assert.equal(fill.added[0].amount, 6000);
  // "Rent - October" ₱6,000 typed before the raise counts as October's rent.
  const t3 = tenant({ templates: [rentT({ amount: 7000, dayOfMonth: 1, postedThrough: '2026-09', rates: [{ until: '2026-09', amount: 6000 }] })],
    bills: [bill({ label: 'Rent - October', amount: 6000, due: '2026-10-01', status: 'paid', paidDate: '2026-09-15' })] });
  assert.equal(BC.planAutoPost(t3, { today: '2026-09-28', leadDays: 5, uid }).bills.length, 0);
});

test('a billed cycle falls due on its bill\'s date, not the template\'s current day', () => {
  const t = tenant({ move_in_date: '2026-09-01', templates: [rentT({ dayOfMonth: 28 })],
    bills: [bill({ due: '2026-09-05', tmplId: 'T1', period: '2026-09' })] });
  const c = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 0 }).charges[0];
  assert.equal(c.status, 'behind');
  assert.equal(c.arrears, 6000);
});

test('an old name never lets one charge claim another charge\'s bills', () => {
  const t = tenant({ move_in_date: '2026-03-05',
    templates: [rentT({ aliases: ['Parking'] }), { id: 'P', label: 'Parking', amount: 500, dayOfMonth: 5 }],
    bills: months('2026-03', '2026-09').filter(ym => ym !== '2026-07').map(ym => paidBill(ym))
      .concat(months('2026-03', '2026-09').map(ym => paidBill(ym, { label: 'Parking', amount: 500 }))) });
  const rent = BC.reconcileTenant(t, { today: '2026-09-20', leadDays: 3 }).charges.find(c => c.tmplId === 'T1');
  assert.deepEqual(rent.missing.map(m => m.period), ['2026-07']);
  assert.equal(BC.templateBillExists(t, t.templates[0], '2026-07'), false);
});

test('a pending/₱0 rent never hands the advance role to another charge', () => {
  const t = { billing_model: 'inclusive', templates: [
    { id: 'R', label: 'Monthly Rent (All-Inclusive)', amount: 0, pendingAmount: true, dayOfMonth: 1 },
    { id: 'P', label: 'Parking', amount: 500, dayOfMonth: 1 }] };
  assert.equal(BC.primaryTemplate(t), null);
  // With no rent-labelled charge at all, the all-inclusive charge still leads.
  assert.equal(BC.primaryTemplate({ billing_model: 'inclusive', templates: [{ id: 'X', label: 'Room + utilities', amount: 7000 }] }).id, 'X');
});

test('floors match regardless of case and spacing', () => {
  const mk = (id, floor) => tenant({ id, floor, move_in_date: '2026-01-01', bills: [paidBill('2026-07', { amount: 10000 })] });
  const is = BC.computeIncomeStatement({ tenants: [mk('a', '3rd Floor'), mk('b', '3rd Floor'), mk('c', '2nd Floor')],
    expenses: [{ expense_date: '2026-07-10', category: 'repairs', amount: 8000, floor: '3rd floor' },
               { expense_date: '2026-07-11', category: 'repairs', amount: 2000, floor: ' 3RD  FLOOR ' }],
    from: '2026-07', to: '2026-07', basis: 'accrual', prorate: false, allocation: 'units' });
  assert.deepEqual(is.floors.slice().sort(), ['2nd Floor', '3rd Floor']);
  assert.equal(is.columns['3rd Floor'].net, 10000);
});

// ── Round-3 review regressions ──
test('move-out: unpaid later cycles are removed; prepaid ones are refunded (dated) or kept', () => {
  const t = tenant({ move_in_date: '2026-03-01', templates: [rentT({ dayOfMonth: 1 })], bills: [
    bill({ due: '2026-09-01', tmplId: 'T1', period: '2026-09' }),                                   // owed
    bill({ due: '2026-10-01', tmplId: 'T1', period: '2026-10' }),                                   // after move-out, unpaid
    bill({ due: '2026-11-01', tmplId: 'T1', period: '2026-11', status: 'paid', paidDate: '2026-09-10',
      payments: [{ amount: 6000, date: '2026-09-10', note: 'adv' }] }),                             // prepaid
    bill({ label: 'Electricity', amount: 0, due: '2026-10-20', tmplId: 'E', period: '2026-10' })   // placeholder
  ] });
  t.templates.push({ id: 'E', label: 'Electricity', amount: 0, pendingAmount: true, dayOfMonth: 20 });
  const keep = BC.planMoveOut(t, '2026-09-30', { prepaid: 'keep' });
  assert.equal(keep.removed.length, 1);          // Oct rent; the meter placeholder is usage before move-out
  assert.equal(keep.awaiting.length, 1);
  assert.equal(keep.owed, 6000);
  assert.equal(keep.prepaidTotal, 6000);
  assert.equal(keep.templates[0].postedThrough, undefined);
  const refund = BC.planMoveOut(t, '2026-09-30', { prepaid: 'refund', refundDate: '2026-09-30' });
  const nov = refund.bills.find(b => b.period === '2026-11');
  assert.equal(nov.amount, 0);
  assert.equal(BC.billOpen(nov), 0);
  const ev = BC.billCashEvents(nov);
  assert.deepEqual(ev.map(e => [e.date, e.amount]), [['2026-09-10', 6000], ['2026-09-30', -6000]]);
});

test('nothing is earned after move-out: kept prepaid rent lands on the last day, cycles are clipped', () => {
  const t = tenant({ move_in_date: '2026-03-15', archived_at: '2026-09-30T12:00:00', templates: [rentT({ dayOfMonth: 15 })] });
  const kept = bill({ due: '2026-11-15', tmplId: 'T1', period: '2026-11', status: 'paid', paidDate: '2026-09-10' });
  assert.deepEqual(BC.billRecognition(t, kept, true), [{ ym: '2026-09', amount: 6000 }]);
  assert.deepEqual(BC.billRecognition(t, kept, false), [{ ym: '2026-09', amount: 6000 }]);
  const sep = bill({ due: '2026-09-15', tmplId: 'T1', period: '2026-09', status: 'paid', paidDate: '2026-09-15' });
  const segs = BC.billRecognition(t, sep, true);
  assert.deepEqual(segs.map(s => s.ym), ['2026-09']);
  assert.equal(segs.reduce((a, s) => a + s.amount, 0), 6000);
});

test('undoing a receipt removes it everywhere and drops the early bills it created', () => {
  const t = tenant({ move_in_date: '2026-09-05', templates: [rentT({ postedThrough: '2026-09' })],
    bills: [bill({ due: '2026-09-05', tmplId: 'T1', period: '2026-09', payments: [{ amount: 3000, date: '2026-09-05', note: 'cash' }] })] });
  const plan = BC.allocatePayment(t, [{ amount: 21000, date: '2026-09-20', note: 'typo' }], { today: '2026-09-20', uid, rid: 'R1' });
  assert.equal(plan.bills.length, 4);                       // Sep settled + Oct, Nov, Dec in advance
  assert.ok(plan.bills.slice(1).every(b => b.rid === 'R1'));
  const after = Object.assign({}, t, { bills: plan.bills, templates: plan.templates });
  const u = BC.undoReceipt(after, 'R1', { today: '2026-09-20' });
  assert.equal(u.amount, 21000);
  assert.equal(u.removed, 3);
  assert.equal(u.bills.length, 1);
  assert.deepEqual(u.bills[0].payments.map(p => p.amount), [3000]); // the genuine partial payment stays
  assert.equal(u.bills[0].status, 'unpaid');
  assert.equal(u.templates[0].postedThrough, '2026-09');
});

test('a bill named after a charge ("Water - Sept") is that charge\'s bill; placeholders need an amount', () => {
  const t = tenant({ templates: [rentT(), { id: 'W', label: 'Water', amount: 0, pendingAmount: true, dayOfMonth: 20, postedThrough: '2026-08' }],
    bills: [bill({ label: 'Water - September', amount: 380, due: '2026-09-20' })] });
  assert.equal(BC.templateBillExists(t, t.templates[1], '2026-09'), true);
  assert.equal(BC.templateOfBill(t, { label: 'Water deposit' }), null);
  assert.equal(BC.templateOfBill(t, { label: 'Waterfront fee' }), null);
  const plan = BC.planAutoPost(t, { today: '2026-09-15', leadDays: 7, uid });
  assert.equal(plan.bills.filter(b => b.label === 'Water').length, 0);
  assert.equal(BC.billAwaitingAmount({ amount: 0, status: 'unpaid' }), true);
  assert.equal(BC.billAwaitingAmount({ amount: 0, status: 'paid' }), false);
});

test('a new metered charge is reckoned from the month it was set up', () => {
  const t = tenant({ move_in_date: '2026-01-10', templates: [rentT({ dayOfMonth: 10 }), { id: 'E', label: 'Electricity', amount: 0, pendingAmount: true, dayOfMonth: 20, since: '2026-10' }],
    bills: months('2026-01', '2026-09').map(ym => paidBill(ym, { due: ym + '-10', paidDate: ym + '-10' })) });
  const e = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 3 }).charges.find(c => c.tmplId === 'E');
  assert.equal(e.missing.length, 0);
});

// ── Round-4 (fix verification) regressions ──
test('only a label that IS the rent stands in for it; one-offs named after a charge are not its monthly bill', () => {
  assert.equal(BC.billCategory({ label: 'Electric bill (current)' }), 'utilities');
  assert.equal(BC.billCategory({ label: 'Monthly Rental' }), 'rent');           // reporting stays permissive
  for(const l of ['Rent - Oct', 'Monthly Rental', 'Room rent', 'October rent', 'Upa - Marso', 'Renta - Oktubre']) assert.equal(BC.isRentLabel(l), true, l);
  for(const l of ['Aircon rental', 'Parking rent', 'Appliance rent', 'Electric bill (current)']) assert.equal(BC.isRentLabel(l), false, l);
  const t = tenant({ templates: [rentT({ postedThrough: '2026-09' }), { id: 'W', label: 'Water', amount: 0, pendingAmount: true, dayOfMonth: 1, postedThrough: '2026-09' }],
    bills: [bill({ label: 'Parking rent', amount: 500, due: '2026-10-05' }), bill({ label: 'Water refill (5 gal)', amount: 60, due: '2026-10-01' })] });
  assert.equal(BC.templateBillExists(t, t.templates[0], '2026-10'), false);
  assert.equal(BC.templateBillExists(t, t.templates[1], '2026-10'), false);
  assert.ok(BC.templateOfBill(t, { label: 'Water (Aug-Sep 2026)' }));
  assert.equal(BC.templateOfBill(t, { label: 'Water heater repair' }), null);
});

test('a charge set up later is reckoned from then; a replacement rent keeps the stopped rent\'s history', () => {
  const t = tenant({ move_in_date: '2026-01-05', templates: [
      rentT({ id: 'OLD', label: 'Monthly Rent (old rate)', retired: true }),
      rentT({ id: 'NEW', amount: 7000, since: '2026-10' }),
      { id: 'E', label: 'Electricity', amount: 1000, dayOfMonth: 10, since: '2026-10' }],
    bills: months('2026-01', '2026-09').map(ym => paidBill(ym, { tmplId: 'OLD', period: ym }))
      .concat([paidBill('2026-06', { label: 'Electricity - June', amount: 800 })]) });
  const r = BC.reconcileTenant(t, { today: '2026-09-27', leadDays: 3 });
  assert.equal(r.charges.length, 2);                   // the stopped charge isn't reconciled
  const nw = r.charges.find(c => c.tmplId === 'NEW'), e = r.charges.find(c => c.tmplId === 'E');
  assert.equal(nw.arrears, 0); assert.equal(nw.missing.length, 0);   // the stopped rent's bills are its history
  assert.equal(e.startYM, '2026-10'); assert.equal(e.arrears, 0);
  assert.equal(BC.primaryTemplate(t).id, 'NEW');
});

test('legacy rent typed under a monthly label at an older amount still counts', () => {
  const t = tenant({ move_in_date: '2026-03-01', templates: [rentT({ dayOfMonth: 1 })],
    bills: months('2026-03', '2026-09').map(ym => paidBill(ym, { label: 'Room - ' + ym, amount: 5500, due: ym + '-01' })) });
  const c = BC.reconcileTenant(t, { today: '2026-09-20', leadDays: 3 }).charges[0];
  assert.equal(c.missing.length, 0);
  assert.equal(c.arrears, 0);
});

test('all-inclusive main charge: never handed to a small add-on; first activation respects a hand-typed bill', () => {
  const t = { billing_model: 'inclusive', flat_rate: 8000, templates: [
    { id: 'R', label: 'Room + utilities', amount: 0, pendingAmount: true, dayOfMonth: 1 },
    { id: 'P', label: 'Parking', amount: 500, dayOfMonth: 1 }] };
  assert.equal(BC.primaryTemplate(t), null);
  t.templates[0] = { id: 'R', label: 'Room + utilities', amount: 8000, dayOfMonth: 1 };
  assert.equal(BC.primaryTemplate(t).id, 'R');
  const t2 = { billing_model: 'inclusive', flat_rate: 7200, templates: [{ id: 'I', label: 'Monthly Rent (All-Inclusive)', amount: 7200, dayOfMonth: 3 }],
    bills: [bill({ label: 'Monthly Bill - October', amount: 6500, due: '2026-10-03' })] };
  assert.equal(BC.planAutoPost(t2, { today: '2026-09-28', leadDays: 7, uid }).bills.length, 0);
});

test('move-out: fixed utilities count as cycles; keep settles at what was paid; restore puts it back', () => {
  const t = tenant({ move_in_date: '2026-03-01', templates: [rentT({ dayOfMonth: 1, postedThrough: '2026-10' }), { id: 'I', label: 'Internet', amount: 1000, dayOfMonth: 1, postedThrough: '2026-10' }],
    bills: [bill({ due: '2026-10-01', tmplId: 'T1', period: '2026-10', payments: [{ amount: 2000, date: '2026-09-05', note: 'adv', rid: 'R' }], remark: 'Partly paid in advance' }),
            bill({ label: 'Internet', amount: 1000, due: '2026-10-01', tmplId: 'I', period: '2026-10' })] });
  const k = BC.planMoveOut(t, '2026-09-27', { prepaid: 'keep' });
  assert.equal(k.removed.length, 1);                   // Internet Oct
  const oct = k.bills.find(b => b.tmplId === 'T1');
  assert.equal(oct.amount, 2000); assert.equal(oct.status, 'paid'); assert.equal(BC.billOpen(oct), 0);
  const inet = k.bills.find(b => b.tmplId === 'I');
  assert.equal(inet.amount, 0); assert.equal(inet.remark, 'Cancelled on move-out');   // kept, not deleted
  const back = BC.undoMoveOut(Object.assign({}, t, { bills: k.bills }));
  assert.equal(back.restored, 2);
  assert.equal(back.bills.find(b => b.tmplId === 'T1').amount, 6000);
  assert.equal(back.bills.find(b => b.tmplId === 'I').amount, 1000);
});

test('an archived tenant\'s unpaid later bill is not revenue (memo still ties out)', () => {
  const f = { id: 'F', floor: '1st', archived_at: '2026-06-20T02:00:00Z', templates: [],
    bills: months('2026-01', '2026-06').map(ym => bill({ amount: 5800, due: ym + '-01', status: 'paid', paidDate: ym + '-02' }))
      .concat([bill({ amount: 5800, due: '2026-07-01', tmplId: 'X', period: '2026-07' })]) };
  f.templates = [{ id: 'X', label: 'Monthly Rent', amount: 5800, dayOfMonth: 1 }];
  for(const prorate of [true, false]) {
    const is = BC.computeIncomeStatement({ tenants: [f], expenses: [], from: '2026-01', to: '2026-07', basis: 'accrual', prorate, allocation: 'none' });
    assert.equal(is.total.revenue.total, 34800);
    const m = is.memo.__total, cash = 34800;
    assert.equal(BC.r2(is.total.revenue.total - cash), BC.r2(m.receivable - m.unearned - m.billedAhead - m.credits));
  }
});

test('undo keeps a marked-paid balance as real money and hands the early-bill mark on', () => {
  const t = tenant({ templates: [rentT({ postedThrough: '2026-11' })], bills: [
    bill({ amount: 7500, due: '2026-08-15', status: 'paid', paidDate: '2026-09-01', payments: [{ amount: 2000, date: '2026-08-10', rid: 'M' }] }),
    bill({ due: '2026-11-05', tmplId: 'T1', period: '2026-11', rid: 'R1', payments: [{ amount: 2000, date: '2026-09-20', rid: 'R1' }, { amount: 4000, date: '2026-09-25', rid: 'R2' }], status: 'paid', paidDate: '2026-09-25' })] });
  const u = BC.undoReceipt(t, 'M', { today: '2026-09-27' });
  const aug = u.bills[0];
  assert.equal(aug.status, 'unpaid');
  assert.deepEqual(BC.billCashEvents(aug).map(e => [e.date, e.amount]), [['2026-09-01', 5500]]);
  const u1 = BC.undoReceipt(t, 'R1', { today: '2026-09-27' });
  const nov = u1.bills.find(b => b.period === '2026-11');
  assert.equal(nov.rid, 'R2');
  const u2 = BC.undoReceipt(Object.assign({}, t, { bills: u1.bills, templates: u1.templates }), 'R2', { today: '2026-09-27' });
  assert.equal(u2.bills.some(b => b.period === '2026-11'), false);
});

// ── Round-5 regressions ──
test('rent paid ahead as an overpayment is offered on move-out; restore reverses everything', () => {
  const t = tenant({ move_in_date: '2026-02-01', templates: [rentT({ amount: 5500, dayOfMonth: 1 })],
    bills: [bill({ amount: 5500, due: '2026-09-01', tmplId: 'T1', period: '2026-09', status: 'paid', paidDate: '2026-09-01', payments: [{ amount: 11000, date: '2026-09-01', note: 'Sep + Oct' }] }),
            bill({ amount: 5500, due: '2026-10-01', tmplId: 'T1', period: '2026-10' })] });
  const k = BC.planMoveOut(t, '2026-09-28', { prepaid: 'keep' });
  assert.equal(k.prepaidTotal, 5500);
  const forfeit = k.bills.find(b => /Forfeited credit/.test(b.label));
  assert.equal(forfeit.amount, 5500);
  assert.equal(cashSum(k.bills), 11000);                             // cash unchanged
  const r = BC.planMoveOut(t, '2026-09-28', { prepaid: 'refund', refundDate: '2026-09-28' });
  assert.equal(cashSum(r.bills), 5500);
  const back = BC.undoMoveOut(Object.assign({}, t, { bills: k.bills }));
  assert.equal(back.bills.length, 2); assert.equal(cashSum(back.bills), 11000); assert.equal(back.bills[1].amount, 5500);
});

test('first activation and replacement rent never double-bill or drop the rent', () => {
  // inclusive, first run, a one-off in the month: rent still posts
  const t1 = { billing_model: 'inclusive', flat_rate: 8000, templates: [{ id: 'I', label: 'Monthly Rent (All-Inclusive)', amount: 8000, dayOfMonth: 30 }],
    bills: [bill({ label: 'Aircon cleaning', amount: 800, due: '2026-09-12' })] };
  assert.equal(BC.planAutoPost(t1, { today: '2026-09-28', leadDays: 7, uid }).bills.length, 1);
  // itemized first run: a hand-typed "Room - October" at the old rate counts
  const t2 = { billing_model: 'itemized', templates: [{ id: 'R', label: 'Monthly Rent', amount: 7200, dayOfMonth: 5 }],
    bills: [bill({ label: 'Room - October', amount: 6500, due: '2026-10-05' })] };
  assert.equal(BC.planAutoPost(t2, { today: '2026-09-30', leadDays: 7, uid }).bills.length, 0);
  // replacement rent: the stopped charge already posted October
  const t3 = tenant({ templates: [rentT({ id: 'OLD', amount: 5000, retired: true, postedThrough: '2026-10' }), rentT({ id: 'NEW', label: 'Rent', amount: 5500, since: '2026-10' })],
    bills: [bill({ amount: 5000, due: '2026-10-05', tmplId: 'OLD', period: '2026-10' })] });
  assert.equal(BC.planAutoPost(t3, { today: '2026-09-30', leadDays: 7, uid }).bills.length, 0);
  // resume: nothing before since is posted
  const t4 = tenant({ templates: [rentT({ postedThrough: '2026-07', since: '2026-10' })] });
  assert.deepEqual(BC.planAutoPost(t4, { today: '2026-09-28', leadDays: 7, uid }).bills.map(b => b.period), ['2026-10']);
  // item rents never stand in for the rent
  const t5 = tenant({ templates: [rentT({ postedThrough: '2026-09' })], bills: [bill({ label: 'Parking rent', amount: 500, due: '2026-10-05' })] });
  assert.equal(BC.templateBillExists(t5, t5.templates[0], '2026-10'), false);
});

test('legacy series: "Monthly Bill - <m>" counts, a Parking series never does', () => {
  const mk = (l, a) => months('2026-03', '2026-09').map(ym => paidBill(ym, { label: l + ' - ' + ym, amount: a, due: ym + '-05' }));
  const ok = BC.reconcileTenant(tenant({ move_in_date: '2026-03-05', bills: mk('Monthly Bill', 5500) }), { today: '2026-09-20', leadDays: 3 }).charges[0];
  assert.equal(ok.missing.length, 0);
  const bad = BC.reconcileTenant(tenant({ move_in_date: '2026-03-05', bills: mk('Parking', 500) }), { today: '2026-09-20', leadDays: 3 }).charges[0];
  assert.equal(bad.missing.length, 7);
});

test('auto-post pays a new cycle from money logged ahead; ordinary suffixes still belong to their charge', () => {
  const t = tenant({ templates: [rentT({ amount: 5000, dayOfMonth: 1, postedThrough: '2026-09' })],
    bills: [bill({ amount: 5000, due: '2026-09-01', status: 'paid', paidDate: '2026-09-01', payments: [{ amount: 10000, date: '2026-09-01', note: 'Sep + Oct' }] })] });
  const plan = BC.planAutoPost(t, { today: '2026-09-28', leadDays: 7, uid });
  assert.equal(plan.bills[0].status, 'paid');
  assert.ok(plan.allBills);
  assert.equal(cashSum(plan.allBills), 10000);
  assert.equal(BC.billTotalPaid(plan.allBills[0]), 5000);
  const n = tenant({ templates: [{ id: 'I', label: 'Internet', amount: 1500, dayOfMonth: 1 }] });
  assert.ok(BC.templateOfBill(n, { label: 'Internet - Oct 2026 (PLDT)' }));
  assert.ok(BC.templateOfBill(n, { label: 'Internet - Sept (prorated)' }));
  assert.equal(BC.templateOfBill(n, { label: 'Internet router replacement' }), null);
});

test('without a move-in date, rent due on the 31st is that month\'s revenue in full', () => {
  const t = tenant({ templates: [rentT({ amount: 19000, dayOfMonth: 31 })],
    bills: [bill({ amount: 19000, due: '2026-01-31', status: 'paid', paidDate: '2026-01-28' }),
            bill({ label: 'Electric Bill', amount: 1844, due: '2026-01-23', status: 'paid', paidDate: '2026-01-28' })] });
  for(const prorate of [true, false]) {
    const is = BC.computeIncomeStatement({ tenants: [t], expenses: [], from: '2026-01', to: '2026-01', basis: 'accrual', prorate });
    assert.equal(is.total.revenue.total, 19000);
    assert.equal(is.total.passThrough.billed, 1844);
  }
});

test('default accrual: a mid-month move-in keeps a flat rent whole in each billing month', () => {
  const t = tenant({ move_in_date: '2026-06-15', templates: [rentT({ amount: 4000, dayOfMonth: 15 })],
    bills: ['06', '07', '08'].map(m => bill({ amount: 4000, due: `2026-${m}-15`, status: 'paid', paidDate: `2026-${m}-15` })) });
  // Spreading over the 15th-to-15th cycle is what produced the decimals.
  assert.notEqual(BC.computeIncomeStatement({ tenants: [t], expenses: [], from: '2026-06', to: '2026-06', prorate: true }).total.revenue.total, 4000);
  for(const ym of ['2026-06', '2026-07', '2026-08']) {
    const m = BC.computeIncomeStatement({ tenants: [t], expenses: [], from: ym, to: ym });
    assert.equal(m.total.revenue.total, 4000, ym);
  }
});

test('utility costs are offset per floor and kind by what tenants are billed back', () => {
  const a = tenant({ id: 'A', floor: '1st', move_in_date: '2026-01-01', bills: [
    bill({ label: 'Electric Bill', amount: 3000, due: '2026-09-20' }),
    bill({ label: 'Water', amount: 900, due: '2026-09-20' })] });
  const b = tenant({ id: 'B', unit: '2', floor: '2nd', move_in_date: '2026-01-01', bills: [bill({ label: 'Utilities', amount: 400, due: '2026-09-20' })] });
  const ex = [
    { expense_date: '2026-09-05', category: 'electricity', amount: 2500, floor: '1st' },  // tenants billed more than cost: capped
    { expense_date: '2026-09-05', category: 'water', amount: 1000, floor: '1st' },
    { expense_date: '2026-09-06', category: 'electricity', amount: 1000, floor: '' },      // building-wide, not allocated
    { expense_date: '2026-09-07', category: 'maintenance', amount: 800, floor: '' }];
  const is = BC.computeIncomeStatement({ tenants: [a, b], expenses: ex, from: '2026-09', to: '2026-09' });
  assert.equal(is.columns['1st'].recovered.electricity, 2500);
  assert.equal(is.columns['1st'].recovered.water, 900);
  assert.equal(is.columns['1st'].expenses, 100);
  // 1st floor's leftover ₱500 electricity billing and 2nd floor's generic ₱400 offset the building-wide ₱1,000.
  assert.equal(is.unallocated.recovered, 900);
  assert.equal(is.total.expenses, 5300 - 3400 - 900);
  assert.equal(is.total.recovered.maintenance, 0);
  const sumMonth = is.perMonth.__total.reduce((s, m) => s + m.expenses, 0);
  assert.equal(sumMonth, is.total.expenses);
});

test('a category picked on a charge or bill overrides the label guess', () => {
  assert.equal(BC.billCategory({ label: 'Room + water' }), 'utilities');
  assert.equal(BC.billCategory({ label: 'Room + water', category: 'rent' }), 'rent');
  assert.equal(BC.billCategory({ label: 'Water refill', category: 'other' }), 'other');
  const t = tenant({ templates: [rentT({ category: 'rent', label: 'Room + water' })] });
  assert.equal(BC.makeTemplateBill(t.templates[0], '2026-09', '2026-09-01').category, 'rent');
});

test('allocation by occupied units counts distinct units, not tenant records', () => {
  const mk = (id, unit, floor) => tenant({ id, unit, floor, move_in_date: '2026-01-01', bills: [] });
  const is = BC.computeIncomeStatement({ tenants: [mk('a', '101', '1st'), mk('b', '101', '1st'), mk('c', '201', '2nd')],
    expenses: [{ expense_date: '2026-09-02', category: 'maintenance', amount: 1000, floor: '' }], from: '2026-09', to: '2026-09', allocation: 'units' });
  assert.equal(is.columns['1st'].shared.total, 500);
  assert.deepEqual(is.unitsByMonth['2026-09'], { '1st': 1, '2nd': 1 });
});

test('grace period: paid within it is on time; unpaid within it is not yet late', () => {
  const t = tenant({ bills: [
    bill({ due: '2026-08-01', status: 'paid', paidDate: '2026-08-04' }),
    bill({ due: '2026-09-25' })] });
  const strict = BC.paymentReliability([t], '2026-08', '2026-09', '2026-09-28');
  assert.equal(strict[0].late, 2);
  const g5 = BC.paymentReliability([t], '2026-08', '2026-09', '2026-09-28', 5);
  assert.equal(g5[0].n, 1);
  assert.equal(g5[0].late, 0);
});
