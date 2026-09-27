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
  assert.equal(plan.templates[0].postedThrough, undefined);
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
  assert.equal(acc.total.revenue.total, 6500);
  assert.equal(acc.total.expenses, 700);
  assert.equal(acc.total.net, 5800);
  assert.equal(acc.memo.__total.receivable, 500);
  assert.equal(acc.memo.__total.unearned, 6000);
  const cash = BC.computeIncomeStatement(Object.assign({ basis: 'cash' }, base));
  assert.equal(cash.total.revenue.total, 12000);
  assert.equal(cash.total.net, 11300);
});

test('income statement: per-floor with direct + shared allocation by headcount', () => {
  const a = tenant({ id: 'A', floor: '1st', move_in_date: '2026-01-01', bills: [bill({ due: '2026-09-01', status: 'paid', paidDate: '2026-09-01' })] });
  const b = tenant({ id: 'B', floor: '2nd', move_in_date: '2026-01-01', bills: [bill({ amount: 4000, due: '2026-09-01' })] });
  const c = tenant({ id: 'C', floor: '2nd', move_in_date: '2026-01-01', bills: [] });
  const ex = [
    { expense_date: '2026-09-02', category: 'electricity', amount: 900, floor: '' },   // shared
    { expense_date: '2026-09-03', category: 'maintenance', amount: 300, floor: '2nd' } // direct
  ];
  const is = BC.computeIncomeStatement({ tenants: [a, b, c], expenses: ex, from: '2026-09', to: '2026-09', basis: 'accrual', prorate: false, allocation: 'headcount' });
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
