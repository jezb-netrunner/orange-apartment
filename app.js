// ─────────────────────────────────────────────
// PAYMENT LOG MANAGEMENT (F-08)
// ─────────────────────────────────────────────
function openAddPayment(bi) {
  // Close any other open add-payment forms
  document.querySelectorAll('[id^="add-payment-form-"]').forEach(el=>{ el.style.display='none'; el.innerHTML=''; });
  const formEl = document.getElementById('add-payment-form-'+bi);
  if(!formEl) return;
  formEl.style.display = 'block';
  formEl.innerHTML = `<div class="payment-add-form">
    <div class="form-grid">
      <div class="field"><label>Amount Received (&#8369;)</label><input type="text" id="pf-amount-${bi}" placeholder="0" inputmode="decimal" pattern="[0-9.]*" autocomplete="off"></div>
      <div class="field"><label>Date</label><input type="date" id="pf-date-${bi}" value="${todayISO()}"></div>
      <div class="field full"><label>Note <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" id="pf-note-${bi}" placeholder="e.g. GCash ref #1234567"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;">
      <button class="btn-cancel" style="flex:1;padding:8px;" onclick="document.getElementById('add-payment-form-${bi}').style.display='none'">Cancel</button>
      <button class="btn-save" style="flex:2;padding:8px;" onclick="savePaymentEntry(${bi})">Save Payment</button>
    </div>
  </div>`;
}

async function savePaymentEntry(bi) {
  const amt  = normalizeAmount(document.getElementById('pf-amount-'+bi).value);
  const date = document.getElementById('pf-date-'+bi).value;
  const note = document.getElementById('pf-note-'+bi).value.trim();
  if(!amt||amt<=0){ showToast('Please enter a valid amount.',false); return; }
  if(!date){ showToast('Please select a date.',false); return; }
  if(!_futureDateOk(date)) return;
  // Overpayment guard: this form pays ONE bill, so make the admin confirm
  // an excess is intentional (typo catcher). Receive Payment is the flow
  // that spreads money across bills and future cycles.
  const _t = tenants.find(t=>t.id===editingId);
  const _b = _t && _t.bills[bi];
  if(_b){
    const rem = Math.max(0, billRemaining(_b));
    const _own = _recurringOwner(_t, _b);
    const _checker = !!(moveInOf(_t) && _own && tmplRate(_own) > 0);
    if(amt > rem && !confirm('This payment (₱'+amt.toLocaleString()+') is more than the remaining balance (₱'+rem.toLocaleString()+') for "'+_b.label+'".\n\n'
      + (_checker ? 'The excess stays on this bill as credit — the recurring checker on the tenant page can apply it to other bills or later cycles.'
                  : 'The excess stays on this bill as credit; it is NOT applied to other bills automatically.')
      + ' To spread a payment across bills or pay ahead, use Receive payment instead.\n\nRecord it here anyway?')) return;
  }
  const ok = await saveBills(editingId, bills=>{
    if(!bills[bi]) return;
    if(!bills[bi].payments) bills[bi].payments = [];
    bills[bi].payments.push({amount:amt, date, note});
    // Fully paid through logged payments → settled on this payment's date.
    if(bills[bi].status!=='paid' && Number(bills[bi].amount) > 0 && billRemaining(bills[bi]) <= 0.005){ bills[bi].status='paid'; bills[bi].paidDate=date; }
  }, 'Payment recorded.', _billListT);
  if(ok){ renderBillListItems(); rerenderAdmin(); }
}

async function deletePaymentEntry(bi, pi) {
  const _t = tenants.find(x=>x.id===editingId);
  const _p = _t && _t.bills[bi] && (_t.bills[bi].payments||[])[pi];
  if(!_p) return;
  if(_p.rid && await _offerUndoReceipt(_t, _p.rid)){ renderBillListItems(); return; }
  const _b0 = _t.bills[bi];
  const _implied0 = _b0.status==='paid' ? r2(Number(_b0.amount) - billTotalPaid(_b0)) : 0;
  let keepPaid = false;
  if(_implied0 > 0.005){
    // Marked paid beyond its entries: is the rest really still owed?
    keepPaid = !confirm('Remove this payment entry (₱'+fmtMoney(_p.amount)+(_p.date?' on '+formatDate(_p.date):'')+')?\n\nThis bill was marked Paid.\nOK: the money was not received — the bill reopens with ₱'+fmtMoney(_p.amount)+' owed.\nCancel: it was a duplicate entry — keep the bill paid.');
  } else if(!confirm('Remove this payment entry (₱'+fmtMoney(_p.amount)+(_p.date?' on '+formatDate(_p.date):'')+')?')) return;
  if(keepPaid){
    const ok0 = await saveBills(editingId, bills=>{ const b = bills[bi]; if(b && b.payments && b.payments[pi]) b.payments.splice(pi,1); }, 'Payment entry removed — bill stays paid.', _billListT);
    if(ok0){ renderBillListItems(); rerenderAdmin(); }
    return;
  }
  const ok = await saveBills(editingId, bills=>{
    const b = bills[bi];
    if(!b || !b.payments || !b.payments[pi]) return;
    // Marked paid beyond its logged payments: that implied balance was real
    // money on the paid date — log it first, so removing the mistaken entry
    // reopens the bill rather than moving the cash to the paid date.
    const implied = b.status==='paid' ? r2(Number(b.amount) - billTotalPaid(b)) : 0;
    b.payments.splice(pi,1);
    if(implied > 0.005) b.payments.push({ amount: implied, date: b.paidDate || '', note: 'Balance marked paid' });
    if(b.status==='paid' && billTotalPaid(b) < Number(b.amount) - 0.005){ b.status='unpaid'; b.paidDate=''; }
    if(/paid in advance/i.test(b.remark||'') && billTotalPaid(b) <= 0.005) b.remark='';
  }, 'Payment entry removed.', _billListT);
  if(ok){ renderBillListItems(); rerenderAdmin(); }
}


// ─────────────────────────────────────────────
// STATEMENT MODAL — customizable, with live preview
// ─────────────────────────────────────────────
let _stmtTenant = null;        // tenant object for statement
let _stmtPreset = '3m';        // '3m' | '6m' | 'ytd' | 'all' | 'custom'
let _stmtPreviewTimer = null;
let _stmtResizeHandler = null;

const STMT_PREFS_KEY = 'oa_stmt_prefs_v1';
// CSS pixel dimensions of each paper size at 96dpi (portrait)
const STMT_PAPER_PX = { a4:[794,1123], letter:[816,1056] };

function stmtDefaultPrefs() {
  return {
    preset:'3m', filter:'all',
    colDue:true, colStatus:true, colPaid:true, colPaidDate:true, colRemarks:false,
    payments:false, group:'none', breakdown:true, summary:true, sign:false, note:'',
    sort:'oldest', size:'normal', theme:'color', paper:'a4', orient:'portrait'
  };
}

function openStmtModalById(tid) {
  const t = tenants.find(t=>t.id===tid);
  if(t) openStmtModal(t);
}

function openStmtModal(tenantObj) {
  _stmtTenant = tenantObj || currentUser;
  if(!_stmtTenant) return;

  // Restore saved layout preferences (date range is always recomputed fresh).
  let prefs = stmtDefaultPrefs();
  try {
    const saved = JSON.parse(localStorage.getItem(STMT_PREFS_KEY));
    if(saved && typeof saved==='object') prefs = Object.assign(prefs, saved);
  } catch {}
  // Migrate: 'group' was a group-by-month boolean before it became a select.
  if(typeof prefs.group === 'boolean') prefs.group = prefs.group ? 'month' : 'none';
  const setChk = (id,v)=>{ document.getElementById(id).checked = !!v; };
  const setVal = (id,v)=>{ document.getElementById(id).value = v; };
  setVal('stmt-filter', prefs.filter);
  setChk('stmt-col-due', prefs.colDue);
  setChk('stmt-col-status', prefs.colStatus);
  setChk('stmt-col-paid', prefs.colPaid);
  setChk('stmt-col-paiddate', prefs.colPaidDate);
  setChk('stmt-col-remarks', prefs.colRemarks);
  setChk('stmt-payments', prefs.payments);
  setVal('stmt-group', prefs.group);
  setChk('stmt-breakdown', prefs.breakdown);
  setChk('stmt-summary', prefs.summary);
  setChk('stmt-sign', prefs.sign);
  setVal('stmt-note', prefs.note||'');
  setVal('stmt-sort', prefs.sort);
  setVal('stmt-size', prefs.size);
  setVal('stmt-theme', prefs.theme);
  setVal('stmt-paper', prefs.paper);
  setVal('stmt-orient', prefs.orient);

  document.getElementById('stmt-title').textContent = 'Statement — '+_stmtTenant.name;
  document.getElementById('stmt-sub').textContent = 'Unit '+_stmtTenant.unit+((_stmtTenant.floor||'').trim()?' · '+_stmtTenant.floor:'')+' · Adjust the options — the preview updates live.';

  // 'custom' can't be restored meaningfully across tenants; fall back to 3 months.
  setStmtPreset(prefs.preset==='custom' ? '3m' : prefs.preset, true);
  openModal('stmt-modal');

  if(!_stmtResizeHandler) {
    _stmtResizeHandler = ()=>fitStmtPreview();
    window.addEventListener('resize', _stmtResizeHandler);
  }
  // Render after the modal is laid out so the preview can measure its width.
  requestAnimationFrame(()=>renderStmtPreview());
}

function closeStmtModal() {
  closeModalEl('stmt-modal');
  _stmtTenant = null;
  if(_stmtResizeHandler) {
    window.removeEventListener('resize', _stmtResizeHandler);
    _stmtResizeHandler = null;
  }
}

function setStmtPreset(preset, skipRender) {
  _stmtPreset = preset;
  document.querySelectorAll('#stmt-presets .stmt-preset').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.preset===preset);
  });
  const fromEl = document.getElementById('stmt-from');
  const toEl   = document.getElementById('stmt-to');
  const ym = d => d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');
  const now = new Date();
  const allTime = preset==='all';
  fromEl.disabled = allTime;
  toEl.disabled   = allTime;
  if(!allTime) {
    const back = preset==='6m' ? 5 : 2;
    fromEl.value = preset==='ytd' ? now.getFullYear()+'-01' : ym(new Date(now.getFullYear(), now.getMonth()-back, 1));
    toEl.value = ym(now);
  }
  if(!skipRender) stmtOptsChanged();
}

function stmtRangeEdited() {
  _stmtPreset = 'custom';
  document.querySelectorAll('#stmt-presets .stmt-preset').forEach(btn=>btn.classList.remove('active'));
  stmtOptsChanged();
}

function getStmtOpts() {
  const chk = id => document.getElementById(id).checked;
  const val = id => document.getElementById(id).value;
  return {
    preset: _stmtPreset,
    from: val('stmt-from'), to: val('stmt-to'),
    filter: val('stmt-filter'),
    colDue: chk('stmt-col-due'), colStatus: chk('stmt-col-status'),
    colPaid: chk('stmt-col-paid'), colPaidDate: chk('stmt-col-paiddate'),
    colRemarks: chk('stmt-col-remarks'),
    payments: chk('stmt-payments'), group: val('stmt-group'),
    breakdown: chk('stmt-breakdown'),
    summary: chk('stmt-summary'), sign: chk('stmt-sign'),
    note: val('stmt-note'),
    sort: val('stmt-sort'), size: val('stmt-size'), theme: val('stmt-theme'),
    paper: val('stmt-paper'), orient: val('stmt-orient')
  };
}

function stmtOptsChanged() {
  const o = getStmtOpts();
  try {
    const {from, to, ...prefs} = o; // range is per-visit, everything else persists
    localStorage.setItem(STMT_PREFS_KEY, JSON.stringify(prefs));
  } catch {}
  clearTimeout(_stmtPreviewTimer);
  _stmtPreviewTimer = setTimeout(()=>renderStmtPreview(), 120);
}

// Which bills the current options select, in print order.
function stmtSelectBills(t, o) {
  let bills = t.bills.slice();
  if(o.preset!=='all' && o.from && o.to) {
    bills = bills.filter(b => {
      const ym = (b.due||b.paidDate||'').slice(0,7);
      // Undated UNPAID bills are open obligations — a period statement that
      // omits them would understate what the tenant owes. Undated paid bills
      // are historic noise and stay out of ranged periods.
      if(!ym) return b.status!=='paid';
      return ym >= o.from && ym <= o.to;
    });
  }
  if(o.filter==='unpaid') bills = bills.filter(b=>b.status!=='paid');
  if(o.filter==='paid')   bills = bills.filter(b=>b.status==='paid');
  const dir = o.sort==='newest' ? -1 : 1;
  bills.sort((a,b)=>{
    const da = a.due||a.paidDate||'', db = b.due||b.paidDate||'';
    if(!da && !db) return 0;
    if(!da) return 1;              // undated bills always sink to the bottom
    if(!db) return -1;
    return da.localeCompare(db)*dir;
  });
  return bills;
}

function buildStatementHTML(t, o) {
  const bills = stmtSelectBills(t, o);
  const bw = o.theme==='bw';

  const fmtM = ym => new Date(ym+'-02').toLocaleString('default',{month:'long',year:'numeric'});
  let rangeLabel = 'All time';
  if(o.preset!=='all' && o.from && o.to)
    rangeLabel = o.from===o.to ? fmtM(o.from) : fmtM(o.from)+' – '+fmtM(o.to);

  const peso = v => '&#8369;'+fmtMoney(v);
  // A bill marked paid is settled in full even if partial payments weren't logged.
  const paidOf = b => b.status==='paid' ? Number(b.amount||0) : Math.min(billTotalPaid(b), Math.max(0, Number(b.amount||0)));
  const balOf  = b => b.status==='paid' ? 0 : Math.max(0, billRemaining(b));

  const billedTotal = bills.reduce((s,b)=>s+Number(b.amount||0),0);
  const paidTotal   = bills.reduce((s,b)=>s+paidOf(b),0);
  const balTotal    = bills.reduce((s,b)=>s+balOf(b),0);
  // Money logged beyond a bill's amount — shown, never silently dropped.
  const creditTotal = bills.reduce((s,b)=>s+Math.max(0, billTotalPaid(b)-Number(b.amount||0)),0);
  const unpaidCount = bills.filter(b=>b.status!=='paid' && !billAwaitingAmount(b)).length;
  // True outstanding balance is over ALL bills, not just the selected subset.
  const outstandingAllTime = t.bills.filter(b=>b.status!=='paid').reduce((s,b)=>s+Math.max(0,billRemaining(b)),0);

  const dueStatusLabels = { paid:'Paid', overdue:'Overdue', 'due-today':'Due Today', 'due-soon':'Due Soon', grace:'In grace period', upcoming:'Upcoming', 'no-date':'Unscheduled', awaiting:'Amount to follow' };
  const dueStatusColors = { paid:'#1e8449', overdue:'#c0392b', 'due-today':'#c0392b', 'due-soon':'#b9770e', grace:'#b9770e', upcoming:'#5a6776', 'no-date':'#5a6776', awaiting:'#5a6776' };
  const statusCell = b => {
    const ds = getDueStatus(b);
    const label = dueStatusLabels[ds]||ds;
    if(bw) return esc(label);
    const c = dueStatusColors[ds]||'#5a6776';
    return '<span class="pill" style="color:'+c+';background:'+c+'14;">'+esc(label)+'</span>';
  };

  const cols = [
    { th:'Bill', td:b=>esc(b.label||''), cls:'c-bill' },
    o.colDue      && { th:'Due Date', td:b=>b.due?formatDate(b.due):'&mdash;' },
    { th:'Amount', td:b=>peso(b.amount), cls:'num' },
    o.colPaid     && { th:'Paid', td:b=>paidOf(b)?peso(paidOf(b)):'&mdash;', cls:'num' },
    o.colPaid     && { th:'Balance', td:b=>balOf(b)?peso(balOf(b)):(b.status==='paid'?peso(0):'&mdash;'), cls:'num' },
    o.colStatus   && { th:'Status', td:statusCell },
    o.colPaidDate && { th:'Paid Date', td:b=>b.paidDate?formatDate(b.paidDate):'&mdash;' },
    o.colRemarks  && { th:'Remarks', td:b=>esc(b.remark||''), cls:'c-remarks' }
  ].filter(Boolean);

  const rowHtml = b => {
    let h = '<tr>'+cols.map(c=>'<td class="'+(c.cls||'')+'">'+c.td(b)+'</td>').join('')+'</tr>';
    if(o.payments && b.payments && b.payments.length) {
      h += '<tr class="payrow"><td colspan="'+cols.length+'">'+
        b.payments.map(p=>'&#8627; '+(Number(p.amount)<0?'Refunded '+peso(-p.amount):peso(p.amount)+' received')+(p.date?' &middot; '+formatDate(p.date):'')+(p.note?' &middot; '+esc(p.note):'')).join('<br>')+
        '</td></tr>';
    }
    return h;
  };

  let bodyHtml = '';
  if(o.group!=='none' && bills.length) {
    const byCat = o.group==='category';
    const labelSpan = 1 + (o.colDue?1:0);
    const tailSpan  = (o.colStatus?1:0)+(o.colPaidDate?1:0)+(o.colRemarks?1:0);
    const keyOf = b => byCat ? billCategory(b) : ((b.due||b.paidDate||'').slice(0,7) || 'none');
    let keys = []; const groups = {};
    bills.forEach(b=>{
      const k = keyOf(b);
      if(!groups[k]){ groups[k]=[]; keys.push(k); }
      groups[k].push(b);
    });
    // Category groups always print rent first, then utilities, then other.
    if(byCat) keys = BILL_CATEGORIES.map(c=>c.key).filter(k=>groups[k]);
    const catLabels = {}; BILL_CATEGORIES.forEach(c=>catLabels[c.key]=c.label);
    bodyHtml = keys.map(k=>{
      const g = groups[k];
      const name = byCat ? catLabels[k] : (k==='none' ? 'No due date' : fmtM(k));
      const gBilled = g.reduce((s,b)=>s+Number(b.amount||0),0);
      const gPaid   = g.reduce((s,b)=>s+paidOf(b),0);
      const gBal    = g.reduce((s,b)=>s+balOf(b),0);
      return '<tr class="grouphead"><td colspan="'+cols.length+'">'+esc(name)+'</td></tr>'+
        g.map(rowHtml).join('')+
        '<tr class="subtotal"><td colspan="'+labelSpan+'">Subtotal</td><td class="num">'+peso(gBilled)+'</td>'+
        (o.colPaid ? '<td class="num">'+peso(gPaid)+'</td><td class="num">'+peso(gBal)+'</td>' : '')+
        (tailSpan ? '<td colspan="'+tailSpan+'"></td>' : '')+'</tr>';
    }).join('');
  } else {
    bodyHtml = bills.map(rowHtml).join('');
  }

  const tableHtml = bills.length
    ? '<table><thead><tr>'+cols.map(c=>'<th class="'+(c.cls||'')+'">'+c.th+'</th>').join('')+'</tr></thead><tbody>'+bodyHtml+'</tbody></table>'
    : '<div class="empty">No bills match the selected period and filters.</div>';

  const showAllTimeLine = balTotal !== outstandingAllTime;
  // Per-category share of the outstanding balance, rent first and emphasized.
  const catBal = { rent:0, utilities:0, other:0 };
  bills.forEach(b=>{ catBal[billCategory(b)] += balOf(b); });
  const catRows = (o.breakdown && balTotal)
    ? BILL_CATEGORIES.filter(c=>catBal[c.key]>0 || c.key==='rent').map(c=>
        '<tr class="catrow'+(c.key==='rent'?' rent':'')+'"><td>'+c.label+' outstanding</td><td class="num">'+peso(catBal[c.key])+'</td></tr>').join('')
    : '';
  const summaryHtml = o.summary ? '<div class="summary"><table class="sumtable">'+
      '<tr><td>Total billed ('+bills.length+' bill'+(bills.length!==1?'s':'')+')</td><td class="num">'+peso(billedTotal)+'</td></tr>'+
      '<tr><td>Total paid</td><td class="num">'+peso(paidTotal)+'</td></tr>'+
      (creditTotal > 0.005 ? '<tr><td>Credit on account (paid beyond these bills)</td><td class="num">'+peso(creditTotal)+'</td></tr>' : '')+
      catRows+
      '<tr class="bal"><td>Balance outstanding'+(o.preset!=='all'?' (this period)':'')+'</td><td class="num">'+peso(balTotal)+'</td></tr>'+
      (showAllTimeLine ? '<tr class="allnote"><td>Total outstanding, all time</td><td class="num">'+peso(outstandingAllTime)+'</td></tr>' : '')+
      '</table></div>' : '';

  const noteHtml = (o.note||'').trim()
    ? '<div class="notes"><div class="sec-label">Notes</div><div class="notes-body">'+esc(o.note.trim()).replace(/\n/g,'<br>')+'</div></div>'
    : '';

  const signHtml = o.sign
    ? '<div class="signs">'+
        '<div class="sign"><div class="sign-line"></div><div class="sign-label">Prepared by &middot; Date</div></div>'+
        '<div class="sign"><div class="sign-line"></div><div class="sign-label">Received by &middot; Date</div></div>'+
      '</div>'
    : '';

  const genDate = new Date().toLocaleDateString('en-PH',{month:'long',day:'numeric',year:'numeric'});
  const headBalance = bw
    ? '<div class="head-bal">'+(outstandingAllTime?peso(outstandingAllTime):'Settled')+'</div>'
    : '<div class="head-bal" style="color:'+(outstandingAllTime?'#c0392b':'#1e8449')+'">'+(outstandingAllTime?peso(outstandingAllTime):'Settled')+'</div>';

  const sizes = {
    compact:{ base:'10.5px', pad:'5px 8px',  h1:'19px', bal:'17px' },
    normal: { base:'12px',   pad:'7px 9px',  h1:'21px', bal:'19px' },
    large:  { base:'13.5px', pad:'9px 10px', h1:'23px', bal:'21px' }
  };
  const sz = sizes[o.size]||sizes.normal;
  const accent = bw ? '#111111' : '#e67e22';
  const headings = bw ? '#111111' : '#2c3e50';
  const theadBg = bw ? '#f2f2f2' : '#f1f5f9';
  const muted = bw ? '#444444' : '#5a6776';
  const pageSize = (o.paper==='letter'?'letter':'A4')+' '+(o.orient==='landscape'?'landscape':'portrait');

  const css =
    '*{margin:0;padding:0;box-sizing:border-box}'+
    'body{font-family:Inter,Arial,Helvetica,sans-serif;color:#111;font-size:'+sz.base+';line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}'+
    '.doc{padding:44px 48px;max-width:1040px;margin:0 auto}'+
    '.doc-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding-bottom:14px;border-bottom:2.5px solid '+headings+';margin-bottom:18px}'+
    '.brand{font-family:"Source Serif 4",Georgia,serif;font-size:'+sz.h1+';font-weight:700;color:'+headings+';display:flex;align-items:center;gap:9px}'+
    '.brand .dot{width:0.55em;height:0.55em;border-radius:50%;background:'+accent+';display:inline-block;flex-shrink:0}'+
    '.brand-sub{font-size:0.72em;font-weight:400;color:'+muted+';font-family:Inter,Arial,sans-serif;margin-top:3px;letter-spacing:0.02em}'+
    '.doc-type{text-align:right}'+
    '.doc-type-title{font-size:0.95em;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:'+headings+'}'+
    '.doc-type-gen{font-size:0.88em;color:'+muted+';margin-top:4px}'+
    '.doc-meta{display:flex;justify-content:space-between;gap:20px;margin-bottom:20px}'+
    '.meta-label{font-size:0.78em;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:'+muted+';margin-bottom:3px}'+
    '.meta-main{font-weight:600;color:#111}'+
    '.meta-sub{font-size:0.92em;color:'+muted+';margin-top:1px}'+
    '.meta-block.right{text-align:right}'+
    '.head-bal{font-family:"Source Serif 4",Georgia,serif;font-size:'+sz.bal+';font-weight:700}'+
    'table{width:100%;border-collapse:collapse}'+
    'thead{display:table-header-group}'+
    'th{background:'+theadBg+';padding:'+sz.pad+';text-align:left;font-size:0.82em;letter-spacing:0.08em;text-transform:uppercase;color:'+muted+';border-bottom:1.5px solid #d5d9e0}'+
    'td{padding:'+sz.pad+';border-bottom:1px solid #e8e8ed;vertical-align:top}'+
    'tr{page-break-inside:avoid}'+
    '.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}'+
    '.c-bill{font-weight:500}'+
    '.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:0.9em;font-weight:600;white-space:nowrap}'+
    '.payrow td{padding-top:2px;font-size:0.9em;color:'+muted+';border-bottom:1px solid #e8e8ed;padding-left:1.6em}'+
    '.grouphead td{background:'+(bw?'#fafafa':'#fbf7f2')+';font-family:"Source Serif 4",Georgia,serif;font-weight:600;color:'+headings+';border-bottom:1px solid #d5d9e0;padding-top:0.9em}'+
    '.subtotal td{font-weight:600;background:'+(bw?'#fafafa':'#fcfcfd')+';border-bottom:2px solid #d5d9e0;color:'+headings+'}'+
    '.summary{display:flex;justify-content:flex-end;margin-top:16px}'+
    '.sumtable{width:auto;min-width:46%}'+
    '.sumtable td{border-bottom:1px solid #e8e8ed;padding:'+sz.pad+'}'+
    '.sumtable td:first-child{color:'+muted+';padding-right:28px}'+
    '.sumtable .catrow td{font-size:0.95em}'+
    '.sumtable .catrow.rent td{color:#111;font-weight:600}'+
    '.sumtable .bal td{font-weight:700;color:#111;border-bottom:2px solid '+headings+'}'+
    '.sumtable .allnote td{font-size:0.9em;color:'+muted+';border-bottom:none}'+
    '.notes{margin-top:22px;padding:12px 16px;background:'+(bw?'#f7f7f7':'#f8f9fc')+';border-left:3px solid '+accent+';page-break-inside:avoid}'+
    '.sec-label{font-size:0.78em;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:'+muted+';margin-bottom:4px}'+
    '.notes-body{white-space:normal}'+
    '.signs{display:flex;gap:48px;margin-top:44px;page-break-inside:avoid}'+
    '.sign{flex:1;max-width:260px}'+
    '.sign-line{border-bottom:1.5px solid #111;height:2.2em}'+
    '.sign-label{font-size:0.85em;color:'+muted+';margin-top:5px}'+
    '.empty{padding:36px 0;text-align:center;color:'+muted+'}'+
    '.doc-foot{margin-top:28px;padding-top:10px;border-top:1px solid #e8e8ed;display:flex;justify-content:space-between;font-size:0.82em;color:'+muted+'}'+
    '@page{size:'+pageSize+';margin:14mm}'+
    '@media print{.doc{padding:0;max-width:none}}';

  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Statement — '+esc(t.name)+'</title>'+
    '<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,600;8..60,700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">'+
    '<style>'+css+'</style></head><body><div class="doc">'+
    '<div class="doc-head">'+
      '<div><div class="brand"><span class="dot"></span>'+esc(propertyName)+'</div><div class="brand-sub">'+esc(propertySubtitle)+'</div></div>'+
      '<div class="doc-type"><div class="doc-type-title">Statement of Account</div><div class="doc-type-gen">Generated '+genDate+'</div></div>'+
    '</div>'+
    '<div class="doc-meta">'+
      '<div class="meta-block"><div class="meta-label">Billed To</div><div class="meta-main">'+esc(t.name)+'</div><div class="meta-sub">Unit '+esc(t.unit)+((t.floor||'').trim()?' &middot; '+esc(t.floor):'')+'</div></div>'+
      '<div class="meta-block"><div class="meta-label">Period</div><div class="meta-main">'+rangeLabel+'</div><div class="meta-sub">'+bills.length+' bill'+(bills.length!==1?'s':'')+(unpaidCount?' &middot; '+unpaidCount+' unpaid':'')+'</div></div>'+
      '<div class="meta-block right"><div class="meta-label">Balance Due</div>'+headBalance+'</div>'+
    '</div>'+
    tableHtml + summaryHtml + noteHtml + signHtml +
    '<div class="doc-foot"><span>'+esc(propertyName)+' &middot; Statement of Account</span><span>'+esc(t.name)+' &middot; Unit '+esc(t.unit)+'</span></div>'+
    '</div></body></html>';
}

function renderStmtPreview() {
  if(!_stmtTenant) return;
  const iframe = document.getElementById('stmt-preview');
  if(!iframe) return;
  const o = getStmtOpts();
  const html = buildStatementHTML(_stmtTenant, o);
  const doc = iframe.contentDocument || iframe.contentWindow.document;
  doc.open(); doc.write(html); doc.close();

  // Footer hint mirrors the numbers on the statement.
  const bills = stmtSelectBills(_stmtTenant, o);
  const cat = outstandingByCategory(bills);
  const hint = document.getElementById('stmt-hint');
  if(hint) hint.innerHTML = bills.length+' bill'+(bills.length!==1?'s':'')+' on statement'+
    (cat.total ? ' &middot; &#8369;'+cat.total.toLocaleString()+' outstanding'+(cat.rent?' (&#8369;'+cat.rent.toLocaleString()+' rent)':'') : '');

  fitStmtPreview();
  // Re-fit once content (and web fonts) settle so the page height is right.
  setTimeout(fitStmtPreview, 120);
}

// Scale a paper-sized preview iframe down to fit its preview pane.
// Shared by the tenant statement and the income statement modals.
function _fitPaperPreview(frameId, scaleId, iframeId, paper, orient) {
  const frame = document.getElementById(frameId);
  const scaleDiv = document.getElementById(scaleId);
  const iframe = document.getElementById(iframeId);
  if(!frame || !scaleDiv || !iframe || !frame.clientWidth) return;
  let [w,h] = STMT_PAPER_PX[paper] || STMT_PAPER_PX.a4;
  if(orient==='landscape') [w,h] = [h,w];
  let contentH = h;
  try {
    const body = iframe.contentDocument && iframe.contentDocument.body;
    if(body) contentH = Math.max(h, body.scrollHeight);
  } catch {}
  const pad = 28; // preview frame padding
  const s = Math.min(1, (frame.clientWidth - pad) / w);
  iframe.style.width = w+'px';
  iframe.style.height = contentH+'px';
  scaleDiv.style.width = w+'px';
  scaleDiv.style.transform = 'scale('+s+')';
  scaleDiv.style.height = Math.ceil(contentH*s)+'px';
}

function fitStmtPreview() {
  const o = getStmtOpts();
  _fitPaperPreview('stmt-preview-frame', 'stmt-preview-scale', 'stmt-preview', o.paper, o.orient);
}

// Print the document currently rendered in a preview iframe; buildHtml is the
// fallback when iframe printing is blocked and a pop-up window is used instead.
function _printPaperDoc(iframeId, buildHtml) {
  const iframe = document.getElementById(iframeId);
  // Small delay so the freshly written document finishes layout first.
  setTimeout(()=>{
    try {
      iframe.contentWindow.focus();
      iframe.contentWindow.print();
    } catch(e) {
      // Fall back to a pop-up window if iframe printing is blocked.
      try {
        const win = window.open('','_blank');
        if(!win) throw new Error('blocked');
        win.document.write(buildHtml());
        win.document.close();
        setTimeout(()=>{ try { win.print(); } catch(err){} }, 400);
      } catch(err) {
        showToast('Could not open the print dialog — please allow pop-ups.', false);
      }
    }
  }, 250);
}

function printStatement() {
  if(!_stmtTenant) return;
  renderStmtPreview(); // make sure the printed document matches the options
  _printPaperDoc('stmt-preview', ()=>buildStatementHTML(_stmtTenant, getStmtOpts()));
}


// ─────────────────────────────────────────────
// INCOME STATEMENT — printable, with live preview.
// Accrual basis is the general rule: revenue is recognized in the billing
// cycle it pays for (optionally straight-line across that cycle's days),
// and rent paid ahead sits as unearned until its cycle arrives. Cash basis
// counts money when received. Scope: the whole building, one floor, all
// floors side by side, or one page per floor. Floor-tagged expenses are
// direct costs; untagged ones are shared and stay in the building total unless
// the admin chooses to split them by occupied units or revenue share. Numbers come from
// computeIncomeStatement (billing-core.js); this section only renders.
// ─────────────────────────────────────────────
let _incStmtPreset = '6m';       // 'this' | 'last' | '3m' | '6m' | 'ytd' | 'all' | 'custom'
let _incStmtPreviewTimer = null;
let _incStmtResizeHandler = null;
let _incStmtLastStats = null;    // set by buildIncomeStatementHTML; feeds the footer hint

const INCSTMT_PREFS_KEY = 'oa_incstmt_prefs_v2';

function incStmtDefaultPrefs() {
  return {
    preset:'6m', basis:'accrual', prorate:false, scope:'building', alloc:'none',
    incDetail:true, expDetail:true, monthly:true, memo:true,
    sign:false, note:'', size:'normal', theme:'color', paper:'a4', orient:'portrait'
  };
}

// Floors that appear anywhere in the books: tenant labels (archived
// tenants included) plus floor tags on expenses. '' = no floor, sorted last.
function reportFloors() {
  const canon = appFloorCanon();
  const set = new Set();
  allTenants().forEach(t => set.add(canon(t.floor)));
  expenses.forEach(x => { const f = canon(x.floor); if(f) set.add(f); });
  return Array.from(set).sort((a,b)=>{ if(!a) return 1; if(!b) return -1; return floorRank(a)-floorRank(b) || a.localeCompare(b); });
}
function _floorLabel(f) { return f ? f : 'No floor'; }

function _fillIncScopeOptions(selected) {
  const sel = document.getElementById('incstmt-scope');
  const floors = reportFloors();
  const hasFloors = floors.some(f => f);
  const opts = [['building','Whole building']];
  if(hasFloors) {
    opts.push(['floors-compare','All floors — side by side'], ['floors-pages','Each floor — separate pages']);
    floors.forEach(f => opts.push(['floor:'+f, _floorLabel(f)]));
  }
  sel.innerHTML = opts.map(([v,l]) => '<option value="'+esc(v)+'">'+esc(l)+'</option>').join('');
  sel.value = opts.some(x => x[0]===selected) ? selected : 'building';
  return hasFloors;
}

function openIncStmtModal(scope) {
  // A failed expenses load must not print as "₱0 expenses = all profit".
  if(_expensesLoadError) {
    showToast('Expenses could not be loaded — refresh the page before generating an income statement.', false);
    return;
  }
  let prefs = incStmtDefaultPrefs();
  try {
    const saved = JSON.parse(localStorage.getItem(INCSTMT_PREFS_KEY));
    if(saved && typeof saved==='object') {
      prefs = Object.assign(prefs, saved);
      // Spreading is opt-in; it is saved as `spread` so an old saved default (prorate) is ignored.
      prefs.prorate = typeof saved.spread === 'boolean' ? saved.spread : false;
      // Splitting building-wide costs is opt-in too (saved as `split`; an old saved default is ignored).
      prefs.alloc = ['units','revenue','none'].includes(saved.split) ? saved.split : 'none';
    }
  } catch {}
  if(scope) prefs.scope = scope;
  const hasFloors = _fillIncScopeOptions(prefs.scope);
  if(scope && scope!=='building' && !hasFloors) showToast('No floors yet — give tenants a floor/group label to compare floors.', false);
  else if(_archivedLoadError) showToast('Archived tenants could not be loaded, so former tenants\' income is missing from this statement. Refresh the page to retry.', false);
  const setChk = (id,v)=>{ document.getElementById(id).checked = !!v; };
  const setVal = (id,v)=>{ document.getElementById(id).value = v; };
  setVal('incstmt-basis', prefs.basis==='cash' ? 'cash' : 'accrual');
  setChk('incstmt-prorate', prefs.prorate);
  setVal('incstmt-alloc', ['units','revenue','none'].includes(prefs.alloc) ? prefs.alloc : 'none');
  setChk('incstmt-inc-detail', prefs.incDetail);
  setChk('incstmt-exp-detail', prefs.expDetail);
  setChk('incstmt-monthly', prefs.monthly);
  setChk('incstmt-memo', prefs.memo);
  setChk('incstmt-sign', prefs.sign);
  setVal('incstmt-note', prefs.note||'');
  setVal('incstmt-size', prefs.size);
  setVal('incstmt-theme', prefs.theme);
  setVal('incstmt-paper', prefs.paper);
  setVal('incstmt-orient', prefs.orient);
  _syncIncStmtControls();
  // 'custom' ranges are per-visit; reopen on the default preset instead.
  setIncStmtPreset(prefs.preset==='custom' ? '6m' : prefs.preset, true);
  openModal('incstmt-modal');
  if(!_incStmtResizeHandler) {
    _incStmtResizeHandler = ()=>fitIncStmtPreview();
    window.addEventListener('resize', _incStmtResizeHandler);
  }
  // Render after the modal is laid out so the preview can measure its width.
  requestAnimationFrame(()=>renderIncStmtPreview());
}

function closeIncStmtModal() {
  closeModalEl('incstmt-modal');
  if(_incStmtResizeHandler) {
    window.removeEventListener('resize', _incStmtResizeHandler);
    _incStmtResizeHandler = null;
  }
}

// Show only the options that apply: straight-line spreading is an accrual
// concept; the shared-cost split only matters when floors are involved.
function _syncIncStmtControls() {
  const accrual = document.getElementById('incstmt-basis').value !== 'cash';
  const scope = document.getElementById('incstmt-scope').value;
  document.getElementById('incstmt-prorate-wrap').style.display = accrual ? '' : 'none';
  document.getElementById('incstmt-alloc-wrap').style.display = scope==='building' ? 'none' : '';
}

function setIncStmtPreset(preset, skipRender) {
  _incStmtPreset = preset;
  document.querySelectorAll('#incstmt-presets .stmt-preset').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.preset===preset);
  });
  const fromEl = document.getElementById('incstmt-from');
  const toEl   = document.getElementById('incstmt-to');
  const now = new Date();
  const allTime = preset==='all';
  fromEl.disabled = allTime;
  toEl.disabled   = allTime;
  if(!allTime) {
    if(preset==='last') {
      const lm = _ymKey(new Date(now.getFullYear(), now.getMonth()-1, 1));
      fromEl.value = lm;
      toEl.value = lm;
    } else {
      const back = preset==='6m' ? 5 : preset==='3m' ? 2 : 0;
      fromEl.value = preset==='ytd' ? now.getFullYear()+'-01' : _ymKey(new Date(now.getFullYear(), now.getMonth()-back, 1));
      toEl.value = _ymKey(now);
    }
  }
  if(!skipRender) incStmtOptsChanged();
}

function incStmtRangeEdited() {
  _incStmtPreset = 'custom';
  document.querySelectorAll('#incstmt-presets .stmt-preset').forEach(btn=>btn.classList.remove('active'));
  incStmtOptsChanged();
}

function getIncStmtOpts() {
  const chk = id => document.getElementById(id).checked;
  const val = id => document.getElementById(id).value;
  return {
    preset: _incStmtPreset,
    from: val('incstmt-from'), to: val('incstmt-to'),
    basis: val('incstmt-basis')==='cash' ? 'cash' : 'accrual',
    prorate: chk('incstmt-prorate'),
    scope: val('incstmt-scope') || 'building',
    alloc: val('incstmt-alloc'),
    incDetail: chk('incstmt-inc-detail'), expDetail: chk('incstmt-exp-detail'),
    monthly: chk('incstmt-monthly'), memo: chk('incstmt-memo'),
    sign: chk('incstmt-sign'), note: val('incstmt-note'),
    size: val('incstmt-size'), theme: val('incstmt-theme'),
    paper: val('incstmt-paper'), orient: val('incstmt-orient')
  };
}

function incStmtOptsChanged() {
  _syncIncStmtControls();
  const o = getIncStmtOpts();
  try {
    const {from, to, prorate, alloc, ...prefs} = o; // range is per-visit, everything else persists
    prefs.spread = prorate;
    prefs.split = alloc;
    localStorage.setItem(INCSTMT_PREFS_KEY, JSON.stringify(prefs));
  } catch {}
  clearTimeout(_incStmtPreviewTimer);
  _incStmtPreviewTimer = setTimeout(()=>renderIncStmtPreview(), 120);
}

function _ymKey(d) { return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0'); }

// First and last month with any financial activity (archived tenants
// included). The end extends past the current month only for future-dated
// cash, cycles or expenses. Years before 2000 are treated as typos so one
// bad date can't stretch the doc by decades.
function _incStmtAllTimeRange(basis) {
  let min = null, max = null;
  const valid = s => { const ym = String(s||'').slice(0,7); return (/^\d{4}-\d{2}$/.test(ym) && ym >= '2000-01') ? ym : ''; };
  const spanMin = s => { const ym = valid(s); if(ym && (!min || ym < min)) min = ym; };
  const spanBoth = s => { const ym = valid(s); if(!ym) return; if(!min || ym < min) min = ym; if(!max || ym > max) max = ym; };
  allTenants().forEach(t => (t.bills||[]).forEach(b => {
    // Cycles posted or paid ahead must not pull future months in as
    // "earned" — bill periods only extend the start of the range.
    spanMin(billPeriod(b));
    spanBoth(b.paidDate);
    (b.payments||[]).forEach(p => spanBoth(p.date));
  }));
  expenses.forEach(x => spanBoth(x.expense_date));
  const cur = _currentYM();
  // Accrual: nothing after this month is earned yet (it sits in the memo as
  // unearned). Cash: future-dated receipts/expenses still extend the range.
  const to = basis === 'cash' ? ((max && max > cur) ? max : cur) : cur;
  return { from: min || cur, to };
}

// Occupied units per floor in the last month, so a units split is checkable.
function _unitsNote(R) {
  if(!R.unitsByMonth || !R.months.length) return '';
  const m = R.months[R.months.length-1], u = R.unitsByMonth[m] || {};
  const parts = R.floors.filter(f => u[f]).map(f => esc(_floorLabel(f))+' '+u[f]);
  return parts.length ? ' Occupied units in '+fmtYM(m,'short')+': '+parts.join(', ')+'.' : '';
}
const _ALLOC_TEXT = {
  units: 'split by the number of occupied units on each floor each month',
  revenue: 'split by each floor’s share of revenue',
  none: 'not allocated to floors — shown in the building total only'
};

function buildIncomeStatementHTML(o) {
  const bw = o.theme==='bw';
  // Accounting document: every amount carries centavos so columns align.
  const peso = v => '&#8369;'+fmtMoney(v, true);
  const signedPeso = v => (v<0?'&minus;':'')+'&#8369;'+fmtMoney(Math.abs(Number(v)||0), true);
  const fmtM = ym => new Date(ym+'-02').toLocaleString('default',{month:'long',year:'numeric'});
  const fmtMShort = ym => new Date(ym+'-02').toLocaleString('default',{month:'short',year:'numeric'});

  const allTime = o.preset==='all';
  let from = o.from, to = o.to;
  if(allTime) { const r = _incStmtAllTimeRange(o.basis); from = r.from; to = r.to; }
  if(!/^\d{4}-\d{2}$/.test(from||'')) from = _currentYM();
  if(!/^\d{4}-\d{2}$/.test(to||''))   to = _currentYM();
  // Expenses figures are only trustworthy when the ledger exists; a load
  // error is blocked in openIncStmtModal before we ever get here.
  const hasExpenses = expensesAvailable && !_expensesLoadError;
  const accrual = o.basis !== 'cash';
  const R = computeIncomeStatement({
    tenants: allTenants(), expenses, from, to, allTime,
    basis: o.basis, prorate: o.prorate, allocation: o.alloc, hasExpenses, floorRank, floorCanon: appFloorCanon()
  });
  const months = R.months;
  const rFrom = R.from, rTo = R.to;
  const rangeLabel = allTime ? 'All time' : (rFrom===rTo ? fmtM(rFrom) : fmtM(rFrom)+' &ndash; '+fmtM(rTo));
  const endLabel = formatDate(lastDayOf(rTo));
  const basisLabel = accrual ? 'Accrual basis' : 'Cash basis';
  const revHead = accrual ? 'Revenue &mdash; earned' : 'Revenue &mdash; payments collected';
  const floorsInScope = R.floors;
  const genDate = new Date().toLocaleDateString('en-PH',{month:'long',day:'numeric',year:'numeric'});

  const docHead = (title, sub, metaLabel, metaMain, metaSub, headLabel, headVal) => {
    const headColor = bw ? '#111111' : (headVal < 0 ? '#c0392b' : '#1e8449');
    return '<div class="doc-head">'
      + '<div><div class="brand"><span class="dot"></span>'+esc(propertyName)+'</div><div class="brand-sub">'+esc(propertySubtitle)+'</div></div>'
      + '<div class="doc-type"><div class="doc-type-title">'+title+'</div><div class="doc-type-gen">'+sub+' &middot; Generated '+genDate+'</div></div>'
      + '</div>'
      + '<div class="doc-meta">'
      + '<div class="meta-block"><div class="meta-label">'+metaLabel+'</div><div class="meta-main">'+metaMain+'</div><div class="meta-sub">'+metaSub+'</div></div>'
      + '<div class="meta-block"><div class="meta-label">Period</div><div class="meta-main">'+rangeLabel+'</div><div class="meta-sub">'+months.length+' month'+(months.length!==1?'s':'')+'</div></div>'
      + '<div class="meta-block right"><div class="meta-label">'+headLabel+'</div><div class="head-bal" style="color:'+headColor+'">'+signedPeso(headVal)+'</div></div>'
      + '</div>';
  };
  const noteHtml = (o.note||'').trim()
    ? '<div class="notes"><div class="sec-label">Notes</div><div class="notes-body">'+esc(o.note.trim()).replace(/\n/g,'<br>')+'</div></div>' : '';
  const signHtml = o.sign
    ? '<div class="signs"><div class="sign"><div class="sign-line"></div><div class="sign-label">Prepared by &middot; Date</div></div>'
      + '<div class="sign"><div class="sign-line"></div><div class="sign-label">Noted by &middot; Date</div></div></div>' : '';
  const expNote = (!hasExpenses
    ? '<div class="warn-note">The expenses ledger is not set up yet, so this statement shows income only. Run supabase-migration-2.sql in the Supabase SQL Editor, then log expenses to get a full income statement.</div>' : '')
    + (_archivedLoadError ? '<div class="warn-note">Archived tenants could not be loaded, so income from former tenants is missing. Refresh the page before relying on these figures.</div>' : '');
  const basisNote = (accrual
    ? (o.prorate
        ? 'Accrual basis: rent and fixed recurring charges are spread straight-line over the billing cycle they pay for (from the move-in day; without a move-in date, over the bill\'s own month); one-off charges are recognized in their billing month.'
        : 'Accrual basis: each charge is recognized in the billing month it belongs to.')
      + ' Payments made ahead are held as unearned revenue until they are earned.'
    : 'Cash basis: revenue is counted when payment is received, whatever period it pays for.')
    + ' Utilities billed back to tenants are pass-through (collected for the provider) and are not revenue.';

  // One self-contained statement for the building ('__total') or one floor.
  const singleDoc = (key, pageBreak) => {
    const isTotal = key==='__total';
    const c = isTotal ? R.total : R.columns[key];
    const memo = R.memo[key];
    const undated = R.undated[key] || { total:0 };
    const perMonth = R.perMonth[key] || [];
    if(!c) return '';
    const rows = [];
    rows.push('<tr class="grouphead"><td colspan="2">'+revHead+'</td></tr>');
    if(o.incDetail) {
      rows.push('<tr class="catrow rent"><td>Rent</td><td class="num">'+peso(c.revenue.rent)+'</td></tr>');
      if(c.revenue.other)     rows.push('<tr class="catrow"><td>Other charges</td><td class="num">'+peso(c.revenue.other)+'</td></tr>');
    }
    rows.push('<tr class="subtotal"><td>Total revenue</td><td class="num">'+peso(c.revenue.total)+'</td></tr>');
    let expTotal = 0;
    if(hasExpenses) {
      rows.push('<tr class="grouphead"><td colspan="2">Operating expenses</td></tr>');
      const catLines = (obj, indent) => EXPENSE_CATEGORIES.filter(k=>obj[k.key]>0)
        .map(k=>'<tr class="catrow'+(indent?' sub':'')+'"><td>'+k.label+'</td><td class="num">'+peso(obj[k.key])+'</td></tr>');
      if(isTotal) {
        const combined = {};
        EXPENSE_CATEGORIES.forEach(k=>{ combined[k.key] = r2(c.direct[k.key] + c.shared[k.key]); });
        expTotal = c.expenses;
        if(o.expDetail) {
          const lines = catLines(combined, false);
          rows.push(...(lines.length ? lines : ['<tr class="catrow"><td colspan="2" class="nodata">No expenses recorded in this period.</td></tr>']));
        }
      } else {
        expTotal = c.expenses;
        if(o.expDetail) {
          if(c.direct.total > 0) { rows.push('<tr class="catrow lbl"><td colspan="2">Direct floor costs</td></tr>'); rows.push(...catLines(c.direct, true)); }
          if(c.shared.total > 0) { rows.push('<tr class="catrow lbl"><td colspan="2">Share of building costs</td></tr>'); rows.push(...catLines(c.shared, true)); }
          if(!c.direct.total && !c.shared.total) rows.push('<tr class="catrow"><td colspan="2" class="nodata">No expenses charged to this floor.</td></tr>');
        }
      }
      if(c.recovered && c.recovered.total > 0.005)
        rows.push('<tr class="catrow"><td>Less: utilities '+(accrual?'billed back to':'paid back by')+' tenants</td><td class="num">&minus;'+peso(c.recovered.total)+'</td></tr>');
      rows.push('<tr class="subtotal"><td>Total expenses</td><td class="num">'+peso(expTotal)+'</td></tr>');
      const net = r2(c.revenue.total - expTotal);
      rows.push('<tr class="netline'+(net<0?' neg':' pos')+'"><td>'+(net<0?'Net loss':'Net income')+'</td><td class="num">'+signedPeso(net)+'</td></tr>');
    }
    const net = r2(c.revenue.total - expTotal);
    let tableNotes = '';
    const ptc = c.passThrough || { billed:0, settled:0, outstanding:0 };
    const passHtml = (ptc.billed > 0.005 || ptc.settled > 0.005)
      ? '<div class="sec"><div class="sec-label">Utilities billed back to tenants &middot; pass-through, not revenue</div><table class="ptable"><tbody>'
        + '<tr><td>Billed to tenants</td><td class="num">'+peso(ptc.billed)+'</td></tr>'
        + '<tr><td>Settled in period</td><td class="num">'+peso(ptc.settled)+'</td></tr>'
        + '<tr><td>Still unpaid</td><td class="num">'+peso(ptc.outstanding)+'</td></tr>'
        + (ptc.offset > 0.005 ? '<tr><td>Offset against utility costs</td><td class="num">'+peso(ptc.offset)+'</td></tr>' : '')
        + '</tbody></table><div class="tbl-note">Collected on behalf of the utility provider (IFRS 15: the property acts as agent), so excluded from revenue; the matching utility costs are reduced by the same amount, so only the part tenants don\'t pay back is an expense.</div></div>'
      : '';
    if(undated.total>0) tableNotes += '<div class="tbl-note">Includes '+peso(undated.total)+(accrual?' billed with no due date.':' received with no recorded payment date.')+'</div>';
    if(!isTotal && hasExpenses) {
      const sharedAll = R.total.shared.total;
      if(sharedAll>0) tableNotes += '<div class="tbl-note">Building-wide costs of '+peso(sharedAll)+' are '+_ALLOC_TEXT[o.alloc]+(o.alloc==='none'?'':'; this floor’s share is '+peso(c.shared.total))+'.'+_unitsNote(R)+'</div>';
    } else if(isTotal && hasExpenses && R.unallocated.total>0 && o.scope!=='building') {
      tableNotes += '<div class="tbl-note">'+peso(R.unallocated.total)+' of shared costs '+(o.alloc==='none'
        ? 'are not allocated to floors (building total only).'
        : o.alloc==='revenue' ? 'could not be allocated because no floor had revenue that month.'
        : 'could not be allocated because no units were occupied that month.')+'</div>';
    }

    // Month-by-month (per-year rows on very long ranges)
    let periodHtml = '';
    if(o.monthly && perMonth.length > 1) {
      const byYear = perMonth.length > 24;
      let prows;
      if(byYear) {
        const m2 = new Map();
        perMonth.forEach(m => { const y = m.ym.slice(0,4); const r = m2.get(y) || { label:y, revenue:0, exp:0 }; r.revenue += m.revenue; r.exp += m.expenses; m2.set(y, r); });
        prows = Array.from(m2.values());
      } else prows = perMonth.map(m => ({ label: fmtMShort(m.ym), revenue: m.revenue, exp: m.expenses }));
      prows = prows.filter(r => r.revenue>0 || r.exp>0);
      if(prows.length) {
        const dRev = r2(prows.reduce((s,r)=>s+r.revenue,0)), dExp = r2(prows.reduce((s,r)=>s+r.exp,0));
        periodHtml = '<div class="sec"><div class="sec-label">'+(byYear?'By year':'By month')+'</div>'
          + '<table class="ptable"><thead><tr><th>'+(byYear?'Year':'Month')+'</th><th class="num">Revenue</th>'
          + (hasExpenses ? '<th class="num">Expenses</th><th class="num">Net</th>' : '')+'</tr></thead><tbody>'
          + prows.map(r => { const n = r2(r.revenue - r.exp);
              return '<tr><td>'+r.label+'</td><td class="num">'+peso(r.revenue)+'</td>'
                + (hasExpenses ? '<td class="num">'+peso(r.exp)+'</td><td class="num'+(n<0?' neg':'')+'">'+signedPeso(n)+'</td>' : '')+'</tr>'; }).join('')
          + '<tr class="subtotal"><td>Total</td><td class="num">'+peso(dRev)+'</td>'
          + (hasExpenses ? '<td class="num">'+peso(dExp)+'</td><td class="num'+(dRev-dExp<0?' neg':'')+'">'+signedPeso(r2(dRev-dExp))+'</td>' : '')+'</tr></tbody></table>'
          + (undated.total>0 ? '<div class="tbl-note">Undated items ('+peso(undated.total)+') belong to no month and are not in this table.</div>' : '')
          + '</div>';
      }
    }

    // Memo: balance-sheet items (accrual) or collections (cash).
    let memoHtml = '';
    if(o.memo && memo) {
      memoHtml = accrual
        ? '<div class="sec"><div class="sec-label">Balance sheet items &middot; as of '+endLabel+'</div>'
          + '<table class="ptable memo-table"><tbody>'
          + '<tr><td>Accounts receivable &mdash; billed, not yet collected</td><td class="num">'+peso(memo.receivable)+'</td></tr>'
          + '<tr><td>Unearned revenue &mdash; collected in advance</td><td class="num">'+peso(memo.unearned)+'</td></tr>'
          + (memo.billedAhead>0 ? '<tr><td>Billed ahead &mdash; not yet earned (included in receivables)</td><td class="num">'+peso(memo.billedAhead)+'</td></tr>' : '')
          + (memo.credits>0 ? '<tr><td>Tenant credit balances &mdash; overpayments</td><td class="num">'+peso(memo.credits)+'</td></tr>' : '')
          + '<tr><td>Cash collected in period (for reference)</td><td class="num">'+peso(memo.collected)+'</td></tr>'
          + '</tbody></table></div>'
        : '<div class="sec"><div class="sec-label">Collections memo</div>'
          + '<table class="ptable memo-table"><tbody>'
          + '<tr><td>Billed to tenants in period</td><td class="num">'+peso(memo.billed)+'</td></tr>'
          + '<tr><td>Collected in period</td><td class="num">'+peso(memo.collected)+'</td></tr>'
          + (memo.rate!==null ? '<tr><td>Collection rate</td><td class="num">'+memo.rate+'%</td></tr>' : '')
          + '<tr><td>Still unpaid on bills '+(allTime?'to date':'for this period')+'</td><td class="num">'+peso(memo.outstanding)+'</td></tr>'
          + '</tbody></table>'
          + '<div class="tbl-note">&ldquo;Collected&rdquo; counts every payment received in the period, including payments settling earlier bills and advances'
          + (memo.rate!==null && memo.rate>100 ? ' &mdash; that is why the rate can exceed 100%' : '')+'.</div></div>';
    }

    const scopeName = isTotal ? esc(propertyName) : esc(_floorLabel(key));
    const headVal = hasExpenses ? net : c.revenue.total;
    const headLabel = hasExpenses ? (net<0 ? 'Net Loss' : 'Net Income') : 'Total Revenue';
    return '<div class="doc'+(pageBreak?' pb':'')+'">'
      + docHead('Income Statement'+(isTotal?'':' &middot; Floor'), basisLabel, isTotal?'Property':'Floor', scopeName, isTotal?esc(propertySubtitle):esc(propertyName), headLabel, headVal)
      + '<table>'+rows.join('')+'</table>' + tableNotes + expNote + periodHtml + memoHtml + passHtml
      + '<div class="tbl-note basis-note">'+basisNote+'</div>'
      + noteHtml + signHtml
      + '<div class="doc-foot"><span>'+esc(propertyName)+' &middot; Income Statement'+(isTotal?'':' &middot; '+esc(_floorLabel(key)))+'</span><span>'+rangeLabel+'</span></div>'
      + '</div>';
  };

  // All floors side by side.
  const compareDoc = () => {
    const keys = floorsInScope;
    const cols = keys.map(k => R.columns[k]);
    const T = R.total;
    const th = '<tr><th></th>'+keys.map(k=>'<th class="num">'+esc(_floorLabel(k))+'</th>').join('')+'<th class="num tot">Total</th></tr>';
    const line = (label, fn, cls, totalVal) => '<tr class="'+(cls||'')+'"><td>'+label+'</td>'
      + cols.map(c => '<td class="num">'+fn(c)+'</td>').join('')
      + '<td class="num tot">'+(totalVal!==undefined ? totalVal : fn(T))+'</td></tr>';
    const rows = [];
    rows.push('<tr class="grouphead"><td colspan="'+(keys.length+2)+'">'+revHead+'</td></tr>');
    if(o.incDetail) {
      rows.push(line('Rent', c=>peso(c.revenue.rent), 'catrow rent'));
      if(T.revenue.other) rows.push(line('Other charges', c=>peso(c.revenue.other), 'catrow'));
    }
    rows.push(line('Total revenue', c=>peso(c.revenue.total), 'subtotal'));
    if(hasExpenses) {
      rows.push('<tr class="grouphead"><td colspan="'+(keys.length+2)+'">Operating expenses</td></tr>');
      if(o.expDetail) {
        EXPENSE_CATEGORIES.forEach(k => {
          const tot = r2(T.direct[k.key] + T.shared[k.key]);
          if(tot<=0) return;
          rows.push(line(k.label, c=>peso(r2(c.direct[k.key] + c.shared[k.key])), 'catrow', peso(tot)));
        });
      }
      rows.push(line('of which shared, allocated', c=>peso(c.shared.total), 'catrow muted', peso(r2(T.shared.total - R.unallocated.total))));
      if(R.unallocated.total>0) rows.push(line('Shared, unallocated', ()=>'&mdash;', 'catrow muted', peso(R.unallocated.total)));
      if(T.recovered.total > 0.005) rows.push(line('Less: utilities '+(accrual?'billed back':'paid back'), c=>c.recovered.total>0.005?'&minus;'+peso(c.recovered.total):'&mdash;', 'catrow', '&minus;'+peso(T.recovered.total)));
      rows.push(line('Total expenses', c=>peso(c.expenses), 'subtotal', peso(T.expenses)));
      rows.push(line('Net income', c=>signedPeso(c.net), 'netline', signedPeso(T.net)));
      rows.push(line('Margin', c=>c.revenue.total>0 ? Math.round(c.net/c.revenue.total*100)+'%' : '&mdash;', 'catrow muted', T.revenue.total>0 ? Math.round(T.net/T.revenue.total*100)+'%' : '&mdash;'));
    }
    let memoRows = '';
    if(o.memo) {
      const M = R.memo;
      const ml = (label, fn) => '<tr><td>'+label+'</td>'+keys.map(k=>'<td class="num">'+fn(M[k])+'</td>').join('')+'<td class="num tot">'+fn(M.__total)+'</td></tr>';
      memoRows = '<div class="sec"><div class="sec-label">'+(accrual?'Balance sheet items &middot; as of '+endLabel:'Collections memo')+'</div><table class="ptable cmp">'
        + '<thead>'+th+'</thead><tbody>'
        + (accrual
            ? ml('Accounts receivable (billed)', m=>peso(m.receivable)) + ml('Unearned revenue (collected ahead)', m=>peso(m.unearned))
              + (M.__total.billedAhead>0 ? ml('Billed ahead, not yet earned', m=>peso(m.billedAhead)) : '')
              + (M.__total.credits>0 ? ml('Tenant credit balances', m=>peso(m.credits)) : '')
              + ml('Cash collected in period', m=>peso(m.collected))
            : ml('Billed in period', m=>peso(m.billed)) + ml('Collected in period', m=>peso(m.collected)) + ml('Collection rate', m=>m.rate===null?'&mdash;':m.rate+'%') + ml('Still unpaid', m=>peso(m.outstanding)))
        + '</tbody></table></div>';
    }
    const headVal = hasExpenses ? T.net : T.revenue.total;
    const PT = T.passThrough || { billed:0, settled:0, outstanding:0 };
    const pl = (label, k) => '<tr><td>'+label+'</td>'+cols.map(c=>'<td class="num">'+peso((c.passThrough||{})[k]||0)+'</td>').join('')+'<td class="num tot">'+peso(PT[k])+'</td></tr>';
    const passRows = (PT.billed > 0.005 || PT.settled > 0.005)
      ? '<div class="sec"><div class="sec-label">Utilities billed back to tenants &middot; pass-through, not revenue</div><table class="ptable cmp"><thead>'+th+'</thead><tbody>'
        + pl('Billed to tenants','billed') + pl('Settled in period','settled') + pl('Still unpaid','outstanding') + (PT.offset > 0.005 ? pl('Offset against utility costs','offset') : '') + '</tbody></table></div>'
      : '';
    return '<div class="doc">'
      + docHead('Income Statement &middot; By Floor', basisLabel, 'Property', esc(propertyName), keys.length+' floor'+(keys.length!==1?'s':''), hasExpenses?(headVal<0?'Net Loss':'Net Income'):'Total Revenue', headVal)
      + '<table class="cmp"><thead>'+th+'</thead><tbody>'+rows.join('')+'</tbody></table>'
      + (hasExpenses && T.shared.total>0 ? '<div class="tbl-note">Building-wide costs of '+peso(T.shared.total)+' are '+_ALLOC_TEXT[o.alloc]+'. Floor-tagged expenses are charged to their floor directly.'+_unitsNote(R)+'</div>' : '')
      + expNote + memoRows + passRows
      + '<div class="tbl-note basis-note">'+basisNote+'</div>'
      + noteHtml + signHtml
      + '<div class="doc-foot"><span>'+esc(propertyName)+' &middot; Income Statement by Floor</span><span>'+rangeLabel+'</span></div>'
      + '</div>';
  };

  let body;
  if(o.scope==='floors-compare') body = compareDoc();
  else if(o.scope==='floors-pages') body = floorsInScope.map((f,i)=>singleDoc(f, i>0)).join('') + singleDoc('__total', true);
  else if(o.scope.startsWith('floor:') && R.columns[o.scope.slice(6)]) body = singleDoc(o.scope.slice(6), false);
  else body = singleDoc('__total', false);

  const T = R.total;
  // Footer hint mirrors the headline of what's shown: one floor, or the building.
  const hk = (o.scope||'').startsWith('floor:') && R.columns[o.scope.slice(6)] ? o.scope.slice(6) : null;
  const HC = hk !== null ? R.columns[hk] : T;
  _incStmtLastStats = { incTotal: HC.revenue.total, expTotal: HC.expenses, net: HC.net, hasExpenses, basis: accrual ? 'accrual' : 'cash', scope: hk !== null ? _floorLabel(hk) : '' };

  const sizes = {
    compact:{ base:'10.5px', pad:'5px 8px',  h1:'19px', bal:'17px' },
    normal: { base:'12px',   pad:'7px 9px',  h1:'21px', bal:'19px' },
    large:  { base:'13.5px', pad:'9px 10px', h1:'23px', bal:'21px' }
  };
  const sz = sizes[o.size]||sizes.normal;
  const accent = bw ? '#111111' : '#e67e22';
  const headings = bw ? '#111111' : '#2c3e50';
  const theadBg = bw ? '#f2f2f2' : '#f1f5f9';
  const muted = bw ? '#444444' : '#5a6776';
  const green = bw ? '#111111' : '#1e8449';
  const red   = bw ? '#111111' : '#c0392b';
  const pageSize = (o.paper==='letter'?'letter':'A4')+' '+(o.orient==='landscape'?'landscape':'portrait');

  const css =
    '*{margin:0;padding:0;box-sizing:border-box}'+
    'body{font-family:Inter,Arial,Helvetica,sans-serif;color:#111;font-size:'+sz.base+';line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}'+
    '.doc{padding:44px 48px;max-width:1040px;margin:0 auto}'+
    '.doc.pb{page-break-before:always;break-before:page;border-top:1px dashed #d5d9e0}'+
    '.doc-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding-bottom:14px;border-bottom:2.5px solid '+headings+';margin-bottom:18px}'+
    '.brand{font-family:"Source Serif 4",Georgia,serif;font-size:'+sz.h1+';font-weight:700;color:'+headings+';display:flex;align-items:center;gap:9px}'+
    '.brand .dot{width:0.55em;height:0.55em;border-radius:50%;background:'+accent+';display:inline-block;flex-shrink:0}'+
    '.brand-sub{font-size:0.72em;font-weight:400;color:'+muted+';font-family:Inter,Arial,sans-serif;margin-top:3px;letter-spacing:0.02em}'+
    '.doc-type{text-align:right}'+
    '.doc-type-title{font-size:0.95em;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:'+headings+'}'+
    '.doc-type-gen{font-size:0.88em;color:'+muted+';margin-top:4px}'+
    '.doc-meta{display:flex;justify-content:space-between;gap:20px;margin-bottom:20px}'+
    '.meta-label{font-size:0.78em;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:'+muted+';margin-bottom:3px}'+
    '.meta-main{font-weight:600;color:#111}'+
    '.meta-sub{font-size:0.92em;color:'+muted+';margin-top:1px}'+
    '.meta-block.right{text-align:right}'+
    '.head-bal{font-family:"Source Serif 4",Georgia,serif;font-size:'+sz.bal+';font-weight:700}'+
    'table{width:100%;border-collapse:collapse}'+
    'thead{display:table-header-group}'+
    'th{background:'+theadBg+';padding:'+sz.pad+';text-align:left;font-size:0.82em;letter-spacing:0.08em;text-transform:uppercase;color:'+muted+';border-bottom:1.5px solid #d5d9e0}'+
    'td{padding:'+sz.pad+';border-bottom:1px solid #e8e8ed;vertical-align:top}'+
    'tr{page-break-inside:avoid}'+
    '.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}'+
    '.grouphead td{background:'+(bw?'#fafafa':'#fbf7f2')+';font-family:"Source Serif 4",Georgia,serif;font-weight:600;color:'+headings+';border-bottom:1px solid #d5d9e0;padding-top:0.9em}'+
    '.catrow td:first-child{color:'+muted+';padding-left:1.6em}'+
    '.catrow.sub td:first-child{padding-left:2.6em}'+
    '.catrow.lbl td{color:'+headings+';font-weight:600;font-size:0.92em;padding-left:1.6em;border-bottom:none}'+
    '.catrow.rent td{color:#111;font-weight:600}'+
    '.catrow.muted td{color:'+muted+';font-size:0.92em}'+
    '.catrow .nodata{color:'+muted+';font-style:italic}'+
    '.subtotal td{font-weight:700;background:'+(bw?'#fafafa':'#fcfcfd')+';border-bottom:2px solid #d5d9e0;color:'+headings+'}'+
    '.netline td{font-family:"Source Serif 4",Georgia,serif;font-weight:700;font-size:1.12em;border-bottom:3px double '+headings+';padding-top:0.85em}'+
    '.netline.pos td.num{color:'+green+'}'+
    '.netline.neg td.num{color:'+red+'}'+
    '.cmp th.num,.cmp td.num{min-width:6.5em}'+
    '.cmp td.tot,.cmp th.tot{font-weight:700;background:'+(bw?'#f7f7f7':'#f8f9fc')+'}'+
    '.sec{margin-top:24px;page-break-inside:avoid}'+
    '.sec-label{font-size:0.78em;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:'+muted+';margin-bottom:6px}'+
    '.ptable td.neg,.ptable td.num.neg{color:'+red+';font-weight:600}'+
    '.memo-table td:first-child{color:'+muted+'}'+
    '.tbl-note{font-size:0.88em;color:'+muted+';margin-top:6px;line-height:1.55}'+
    '.basis-note{margin-top:18px;font-style:italic}'+
    '.warn-note{margin-top:16px;padding:12px 16px;background:'+(bw?'#f7f7f7':'#fffbeb')+';border-left:3px solid '+accent+';font-size:0.95em;line-height:1.6;color:#111;page-break-inside:avoid}'+
    '.notes{margin-top:22px;padding:12px 16px;background:'+(bw?'#f7f7f7':'#f8f9fc')+';border-left:3px solid '+accent+';page-break-inside:avoid}'+
    '.notes-body{white-space:normal}'+
    '.signs{display:flex;gap:48px;margin-top:44px;page-break-inside:avoid}'+
    '.sign{flex:1;max-width:260px}'+
    '.sign-line{border-bottom:1.5px solid #111;height:2.2em}'+
    '.sign-label{font-size:0.85em;color:'+muted+';margin-top:5px}'+
    '.doc-foot{margin-top:28px;padding-top:10px;border-top:1px solid #e8e8ed;display:flex;justify-content:space-between;font-size:0.82em;color:'+muted+'}'+
    '@page{size:'+pageSize+';margin:14mm}'+
    '@media print{.doc{padding:0;max-width:none}.doc.pb{border-top:none}}';

  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Income Statement — '+esc(propertyName)+'</title>'+
    '<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,600;8..60,700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">'+
    '<style>'+css+'</style></head><body>'+body+'</body></html>';
}

function renderIncStmtPreview() {
  const iframe = document.getElementById('incstmt-preview');
  if(!iframe) return;
  const o = getIncStmtOpts();
  const html = buildIncomeStatementHTML(o);
  const doc = iframe.contentDocument || iframe.contentWindow.document;
  doc.open(); doc.write(html); doc.close();

  // Footer hint mirrors the headline numbers on the statement.
  const s = _incStmtLastStats;
  const hint = document.getElementById('incstmt-hint');
  if(hint && s) {
    const p = v => '&#8369;'+Math.abs(v).toLocaleString();
    hint.innerHTML = (s.basis==='accrual'?'Accrual':'Cash')+(s.scope?' &middot; '+esc(s.scope):'')+' &middot; '+(s.hasExpenses
      ? p(s.incTotal)+' revenue &middot; '+p(s.expTotal)+' expenses &middot; net '+(s.net<0?'&minus;':'')+p(s.net)
      : p(s.incTotal)+' revenue &middot; expenses ledger not set up');
  }
  fitIncStmtPreview();
  // Re-fit once content (and web fonts) settle so the page height is right.
  setTimeout(fitIncStmtPreview, 120);
}

function fitIncStmtPreview() {
  const o = getIncStmtOpts();
  _fitPaperPreview('incstmt-preview-frame', 'incstmt-preview-scale', 'incstmt-preview', o.paper, o.orient);
}

function printIncomeStatement() {
  renderIncStmtPreview(); // make sure the printed document matches the options
  _printPaperDoc('incstmt-preview', ()=>buildIncomeStatementHTML(getIncStmtOpts()));
}


// ── SUPABASE CONFIG ──
const SB_URL = 'https://bxzfqjspoyvwosmpgeof.supabase.co';
const SB_KEY = 'sb_publishable_FgSrHN3LoB9XQ4ZQHCeoQQ_AXg54YkP';

// Admin "keep me signed in": the session (refresh token included) lands in
// localStorage ONLY when the admin ticks the box — the flag below gates every
// write. Unticked, sessions live in memory and die with the tab, exactly like
// the old persistSession:false behavior. The flag is read on every storage
// call (not captured at client creation) so login can flip it just in time.
const ADMIN_REMEMBER_KEY = 'oa_admin_remember';
const ADMIN_SESSION_KEY  = 'oa_admin_session'; // storageKey below + supabase-js suffixes
function _adminRememberOn() {
  try { return localStorage.getItem(ADMIN_REMEMBER_KEY) === '1'; } catch { return false; }
}
const _memAuthStore = {};
const _authStorage = {
  getItem(k) {
    if(_adminRememberOn()) {
      try { const v = localStorage.getItem(k); if(v != null) return v; } catch {}
    }
    return (k in _memAuthStore) ? _memAuthStore[k] : null;
  },
  setItem(k, v) {
    _memAuthStore[k] = v;
    if(_adminRememberOn()) { try { localStorage.setItem(k, v); } catch {} }
  },
  removeItem(k) {
    delete _memAuthStore[k];
    try { localStorage.removeItem(k); } catch {}
  }
};
// Drop the remembered-session opt-in AND any session already persisted under
// it. supabase-js suffixes its storageKey, so sweep matching keys.
function _forgetPersistedAdminSession() {
  try {
    localStorage.removeItem(ADMIN_REMEMBER_KEY);
    for(let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if(k && k.startsWith(ADMIN_SESSION_KEY)) localStorage.removeItem(k);
    }
  } catch {}
}

const _sbClient = supabase.createClient(SB_URL, SB_KEY, {
  auth: {
    // Sessions always persist to _authStorage; whether that reaches
    // localStorage (survives the tab) is gated by the remember-me flag above.
    persistSession: true,
    storage: _authStorage,
    storageKey: ADMIN_SESSION_KEY,
    // Keep the admin session alive for the life of the tab. Without this the
    // JWT expired after ~an hour and writes silently fell back to the anon
    // key — RLS filtered them to zero rows and the UI showed success.
    autoRefreshToken: true,
    detectSessionInUrl: false
  }
});

const SESSION_EXPIRED_MSG = 'Your session has expired — please sign out and sign in again.';

async function _getAuthHeaders() {
  const { data: { session } } = await _sbClient.auth.getSession();
  // An admin with no live session must NEVER fall back to the anon key:
  // anon writes match zero rows under RLS and would be mistaken for success.
  if(!session && currentUser === 'admin') throw new Error(SESSION_EXPIRED_MSG);
  const token = session ? session.access_token : SB_KEY;
  return { 'apikey': SB_KEY, 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Prefer': 'return=representation' };
}

async function sbFetch(path, options={}) {
  const headers = await _getAuthHeaders();
  if(options.headers_extra) { Object.assign(headers, options.headers_extra); delete options.headers_extra; }
  const res = await fetch(SB_URL + '/rest/v1/' + path, { headers, ...options });
  if (!res.ok) {
    // Surface the PostgREST message text, not the raw JSON body — these
    // strings end up in user-facing toasts.
    const body = await res.text();
    let msg = body;
    try {
      const j = JSON.parse(body);
      msg = j.message || j.error_description || j.msg || j.hint || body;
    } catch {}
    if(res.status === 401 && currentUser === 'admin') msg = SESSION_EXPIRED_MSG;
    if(!msg) msg = 'Request failed (HTTP ' + res.status + '). Please check your connection and try again.';
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  const txt = await res.text();
  return txt ? JSON.parse(txt) : null;
}
// Legacy rows (or rows created outside the app) can have null bills/templates;
// normalize once at load so render code never has to null-check arrays.
function _normalizeTenant(t) {
  if(!t) return t;
  if(!Array.isArray(t.bills)) t.bills = [];
  if(!Array.isArray(t.templates)) t.templates = [];
  return t;
}
async function dbGetAll()       { const rows = await sbFetch('tenants?select=*&order=name&archived_at=is.null'); (rows||[]).forEach(_normalizeTenant); return rows; }
async function dbGetArchived()  { const rows = await sbFetch('tenants?select=*&order=name&archived_at=not.is.null'); (rows||[]).forEach(_normalizeTenant); return rows; }
async function dbInsert(t)      { return await sbFetch('tenants', { method:'POST', body: JSON.stringify(t) }); }
async function dbUpdate(id, t)  { return await sbFetch('tenants?id=eq.' + id, { method:'PATCH', body: JSON.stringify(t) }); }
async function dbDelete(id)     { return await sbFetch('tenants?id=eq.' + id, { method:'DELETE' }); }

// Optimistic-concurrency write for tenant bills/templates (uses the rev
// column from supabase-migration-2.sql; degrades to a plain PATCH when the
// column doesn't exist). Two admin tabs PATCHing the whole jsonb array used
// to silently overwrite each other — last write won and payments vanished.
// Now a stale write matches zero rows; we reload the fresh row and throw a
// conflict error so the caller can tell the admin to redo the change.
// Writes only ever target an ACTIVE row (archived_at is null): a tab that
// still lists a tenant archived or deleted on another device can't write
// onto it — the tenant is dropped from its list instead (err.gone).
async function dbUpdateTenantGuarded(t, patch) {
  const base = 'tenants?id=eq.' + t.id + '&archived_at=is.null';
  let rows;
  if(t.rev == null) rows = await sbFetch(base, { method:'PATCH', body: JSON.stringify(patch) });
  else {
    const nextRev = Number(t.rev) + 1;
    rows = await sbFetch(base + '&rev=eq.' + t.rev, { method:'PATCH', body: JSON.stringify({ ...patch, rev: nextRev }) });
    if(rows && rows.length) { t.rev = nextRev; return; }
  }
  if(t.rev == null && rows && rows.length) return;
  let fresh = null, fetched = false;
  try { fresh = await sbFetch('tenants?id=eq.' + t.id + '&select=*'); fetched = true; } catch {}
  const row = fresh && fresh[0] ? _normalizeTenant(fresh[0]) : null;
  if(fetched && (!row || row.archived_at)) {
    tenants = tenants.filter(x => x.id !== t.id);
    archivedTenants = archivedTenants.filter(x => x.id !== t.id).concat(row ? [row] : []);
    const gone = new Error('This tenant was ' + (row ? 'archived' : 'deleted') + ' on another device, so the change was not saved. Their row has been removed from this list.');
    gone.conflict = true; gone.gone = true;
    throw gone;
  }
  if(row) tenants = tenants.map(x => x.id === t.id ? row : x);
  const err = new Error('This tenant was just updated from another tab or device. The latest data has been reloaded — please redo your change.');
  err.conflict = true;
  throw err;
}

// Bring the in-memory tenant lists up to date: another device may have
// added, edited, archived, restored or deleted tenants since this tab
// signed in. Unchanged rows keep their object (open forms stay valid).
// Postgres jsonb doesn't keep object key order, so compare by rev when the
// column exists, else structurally with keys sorted.
function _stableJSON(v) {
  if(Array.isArray(v)) return '[' + v.map(_stableJSON).join(',') + ']';
  if(v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + _stableJSON(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
function _sameRow(a, b) {
  if(b.rev != null && a.rev != null) return String(a.rev) === String(b.rev);
  return Object.keys(b).every(k => _stableJSON(a[k]) === _stableJSON(b[k]));
}
async function _refreshTenantLists() {
  const [rows, arch] = await Promise.all([dbGetAll(), dbGetArchived().catch(() => null)]);
  const byId = new Map(tenants.map(t => [t.id, t]));
  tenants = (rows || []).map(r => { const old = byId.get(r.id); return old && _sameRow(old, r) ? old : r; });
  if(arch) { archivedTenants = arch; _archivedLoadError = false; }
}

// ── EXPENSES (admin-only; table added in supabase-migration-2.sql) ──
async function dbGetExpenses()      { return await sbFetch('expenses?select=*&order=expense_date.desc,created_at.desc'); }
async function dbInsertExpense(x)   { return await sbFetch('expenses', { method:'POST', body: JSON.stringify(x) }); }
async function dbUpdateExpense(id,x){ return await sbFetch('expenses?id=eq.' + encodeURIComponent(id), { method:'PATCH', body: JSON.stringify(x) }); }
async function dbDeleteExpense(id)  { return await sbFetch('expenses?id=eq.' + encodeURIComponent(id), { method:'DELETE' }); }

let paymentInstructions = ''; // loaded from Supabase settings table
let announcements       = ''; // notice board shown on every tenant portal
// Branding defaults match the historical hardcoded strings, so an instance
// that never runs migration 2 or sets a name looks exactly the same as before.
let propertyName        = 'Orange Apartment';
let propertySubtitle    = 'Tenant Billing Portal · Baguio';

// Tenant-visible settings, batched. Falls back to per-key read_setting calls
// when the read_portal_settings RPC (migration 2) isn't installed yet.
async function loadPortalSettings() {
  let s = null;
  let anyLoaded = false;
  try { s = await sbFetch('rpc/read_portal_settings', { method:'POST', body:'{}' }); anyLoaded = true; } catch {}
  if(!s || typeof s !== 'object') {
    s = {};
    const keys = ['payment_instructions','announcements','property_name','property_subtitle'];
    await Promise.all(keys.map(async k => {
      try { s[k] = await sbFetch('rpc/read_setting', { method:'POST', body: JSON.stringify({ setting_key: k }) }); anyLoaded = true; } catch {}
    }));
  }
  // Total failure (e.g. offline at page load): clear the cached promise so
  // the next tenant login retries instead of serving the failure all session.
  if(!anyLoaded) _portalSettingsPromise = null;
  paymentInstructions = (typeof s.payment_instructions === 'string') ? s.payment_instructions : '';
  announcements       = (typeof s.announcements === 'string') ? s.announcements : '';
  if(typeof s.property_name === 'string' && s.property_name.trim()) propertyName = s.property_name.trim();
  if(typeof s.property_subtitle === 'string' && s.property_subtitle.trim()) propertySubtitle = s.property_subtitle.trim();
  try { localStorage.setItem('oa_branding', JSON.stringify({ name: propertyName, sub: propertySubtitle })); } catch {}
  applyBranding();
}

// Admin-side settings load: one query instead of one per key.
let _settingsLoadFailed = false;
// Floors the admin maintains (Settings › Floors), stored as a JSON list in
// the settings table. The floor pickers offer these plus any floor already
// used by a tenant or an expense.
let managedFloors = [];
// Days after the due date before a bill counts as overdue/late (admin setting).
let graceDays = 0;
function allFloors() {
  const canon = floorCanon(managedFloors.concat(allTenants().map(t => t.floor), expenses.map(x => x.floor)));
  const set = new Set();
  managedFloors.concat(allTenants().map(t => t.floor), expenses.map(x => x.floor)).forEach(f => { const c = canon(f); if(c) set.add(c); });
  return Array.from(set).sort((a,b)=>floorRank(a)-floorRank(b) || a.localeCompare(b));
}
async function _saveManagedFloors(list) {
  await dbSetSetting('floors', JSON.stringify(list));
  managedFloors = list;
}
function _parseAutoBilling(map) {
  const lead = Number(map.auto_billing_lead_days);
  return {
    enabled: map.auto_billing !== 'off',
    leadDays: (map.auto_billing_lead_days != null && isFinite(lead)) ? Math.min(27, Math.max(0, Math.round(lead))) : 7
  };
}
// Another device may have changed these since sign-in; background runs
// and the Settings page re-read them. false = couldn't read.
async function _reloadAutoBillSettings() {
  try {
    const rows = await sbFetch('settings?select=key,value&key=in.(auto_billing,auto_billing_lead_days)');
    const map = {}; (rows||[]).forEach(r=>{ map[r.key]=r.value; });
    autoBilling = _parseAutoBilling(map);
    return true;
  } catch { return false; }
}
async function loadAdminSettings() {
  _settingsLoadFailed = false;
  try {
    const rows = await sbFetch('settings?select=key,value&key=in.(payment_instructions,announcements,property_name,property_subtitle,auto_billing,auto_billing_lead_days,floors,grace_days)');
    const map = {}; (rows||[]).forEach(r=>{ map[r.key]=r.value; });
    paymentInstructions = map.payment_instructions || '';
    announcements       = map.announcements || '';
    if((map.property_name||'').trim()) propertyName = map.property_name.trim();
    if((map.property_subtitle||'').trim()) propertySubtitle = map.property_subtitle.trim();
    // Automatic billing is on unless explicitly turned off (admin-only keys:
    // read_setting's anon allowlist never exposes them).
    autoBilling = _parseAutoBilling(map);
    { const g = Number(map.grace_days); graceDays = isFinite(g) ? Math.min(30, Math.max(0, Math.round(g))) : 0; }
    try { const fl = JSON.parse(map.floors || '[]'); managedFloors = Array.isArray(fl) ? fl.filter(x => typeof x === 'string' && x.trim()) : []; } catch { managedFloors = []; }
  } catch {
    // A transient failure must not masquerade as "Not set" — editing on top
    // of that would overwrite the real values with blanks.
    _settingsLoadFailed = true;
    showToast('Could not load portal settings — shown values may be stale. Refresh before editing them.', false);
  }
  try { localStorage.setItem('oa_branding', JSON.stringify({ name: propertyName, sub: propertySubtitle })); } catch {}
  applyBranding();
}

// Stamp the property name onto the static chrome (tab title, wordmarks).
function applyBranding() {
  document.title = propertyName;
  const login = document.querySelector('.login-wordmark');
  if(login) login.textContent = propertyName;
  const initial = (propertyName || 'O').trim().charAt(0).toUpperCase() || 'O';
  const nav = document.querySelector('.nav-wordmark');
  if(nav) nav.innerHTML = '<span class="nav-dot" aria-hidden="true">' + esc(initial) + '</span><span class="nav-name">' + esc(propertyName) + '<small>' + (currentUser && currentUser !== 'admin' ? 'Tenant portal' : 'Property admin') + '</small></span>';
  const logo = document.querySelector('.login-logo');
  if(logo) logo.textContent = initial;
}

async function dbSetSetting(key, value) {
  await sbFetch('settings', {
    method: 'POST',
    body: JSON.stringify({key, value}),
    headers_extra: { 'Prefer': 'resolution=merge-duplicates,return=representation' }
  });
}
let currentUser = null;
let _adminEmail = ''; // the signed-in admin's email (sidebar account card)
let tenants = [];
let editingId = null;
// Expenses ledger (admin-only). `expensesAvailable` flips false when the
// expenses table doesn't exist yet (migration 2 not run) so the dashboard
// can show setup instructions instead of a broken panel.
let expenses = [];
let expensesAvailable = true;
let _expensesLoadError = false; // true = fetch failed for a non-schema reason
let expenseMonth = '';      // '' = current month, else 'YYYY-MM'
let _editingExpenseId = null;
// Browsers without a month picker get a visible YYYY-MM box for "Jump to a month".
const _hasMonthInput = (() => { try { const i = document.createElement('input'); i.setAttribute('type', 'month'); return i.type === 'month'; } catch { return true; } })();
// Migration 3 adds expenses.floor. null = not probed yet.
let expensesFloorAvailable = null;
// Archived tenants — loaded with the dashboard because reports and insights
// need their history (a tenant who moved out still earned and paid here).
let archivedTenants = [];
let _archivedLoadError = false;
// localStorage key for the remembered tenant access code. The code is a
// bearer credential for a READ-ONLY view of the tenant's own bills; storing
// it on the tenant's device is an accepted trade-off for one-tap access.
const PORTAL_CODE_KEY = 'oa_tenant_code';
let filterTenantId = '';   // '' = all
let filterMonth    = '';   // '' = all, else 'YYYY-MM'
let filterFloor    = '';   // '' = all, '__none__' = tenants without a floor, else exact floor label
let filterSearch   = '';   // free-text search on tenant name / unit / code
let sortOrder      = 'unit-asc'; // key of SORT_LABELS
let tableSortCol   = 'due';      // column to sort table by
let tableSortDir   = 'asc';      // 'asc' | 'desc'
let portalMonth    = 'current'; // 'all' | 'YYYY-MM' | 'current'
let billForms = [];

const SORT_LABELS = {
  'unit-asc':     'Unit ↑',
  'unit-desc':    'Unit ↓',
  'floor-asc':    'Floor ↑',
  'name-asc':     'Name A–Z',
  'balance-desc': 'Balance high → low',
  'balance-asc':  'Balance low → high',
  'urgency':      'Most urgent first'
};

// Tenant-list grouping. 'auto' keeps the historical behavior (floor headers
// when floor labels exist and the list is unit-sorted). 'unit' groups the
// tenants of one physical unit under a shared header with a combined
// balance — the natural view when several per-head all-inclusive tenants
// share a unit.
let groupMode = 'auto'; // 'auto' | 'floor' | 'unit' | 'none'
const GROUP_LABELS = {
  auto:  'Auto',
  floor: 'By floor',
  unit:  'By unit',
  none:  'No grouping'
};

function setLoading(on, msg='Loading…') {
  let el = document.getElementById('loading-overlay');
  if (!el) {
    el = document.createElement('div');
    el.id = 'loading-overlay';
    el.style.cssText = 'position:fixed;inset:0;background:rgba(249,249,250,0.85);backdrop-filter:blur(4px);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;';
    el.innerHTML = '<div class="spinner"></div><div style="font-family:Inter,sans-serif;font-size:13px;color:var(--muted);font-weight:500;" id="loading-msg"></div>';
    document.body.appendChild(el);
    const style = document.createElement('style');
    style.textContent = '.spinner{width:28px;height:28px;border:2.5px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin 0.7s linear infinite;}';
    document.head.appendChild(style);
  }
  el.style.display = on ? 'flex' : 'none';
  if (on) document.getElementById('loading-msg').textContent = msg;
}

// Open a modal by id and focus its first focusable input/textarea/select.
// Restores focus to the previously-focused element on close via openModal.return().
function openModal(id) {
  const el = document.getElementById(id);
  if(!el) return;
  const previouslyFocused = document.activeElement;
  el.classList.add('open');
  // Defer focus to the next frame so layout is settled.
  // First visible field; a panel without fields (Bills, Recurring) gets its tab or first button.
  requestAnimationFrame(() => {
    const vis = x => x.offsetParent !== null;
    const q = sel => Array.from(el.querySelectorAll(sel)).find(vis);
    const target = q('input:not([disabled]):not([type=hidden]), textarea:not([disabled]), select:not([disabled])')
      || q('.modal-tab.active, button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])');
    if(target) target.focus();
  });
  el._restoreFocus = previouslyFocused;
}
function closeModalEl(id) {
  const el = document.getElementById(id);
  if(!el) return;
  el.classList.remove('open');
  if(el._restoreFocus && typeof el._restoreFocus.focus === 'function') {
    try { el._restoreFocus.focus(); } catch {}
    el._restoreFocus = null;
  }
}

function showToast(msg, ok=true) {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(12px);padding:10px 20px;border-radius:8px;font-family:Inter,sans-serif;font-size:13px;font-weight:500;z-index:9999;opacity:0;transition:all 0.3s;pointer-events:none;max-width:90vw;white-space:normal;text-align:center;';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.background = ok ? 'var(--navy)' : 'var(--rust)';
  el.style.color = 'white';
  el.style.opacity = '1';
  el.style.transform = 'translateX(-50%) translateY(0)';
  clearTimeout(el._t);
  // Longer messages (errors, conflict explanations) stay up long enough to read.
  const hold = Math.min(7000, 2500 + Math.max(0, msg.length - 40) * 35);
  el._t = setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateX(-50%) translateY(12px)'; }, hold);
}

function switchTab(tab) {
  const admin = tab === 'admin';
  document.querySelectorAll('.login-tab').forEach(t => { const on = t.dataset.tab === tab; t.classList.toggle('active', on); t.setAttribute('aria-pressed', String(on)); });
  document.getElementById('admin-form').style.display  = admin ? 'block' : 'none';
  document.getElementById('tenant-form').style.display = admin ? 'none' : 'block';
  document.getElementById('login-heading').textContent = admin ? 'Admin sign in' : 'Sign in';
  document.getElementById('login-sub').textContent = admin ? 'Manage tenants, bills and payments.' : 'Enter the access code the building admin gave you.';
  document.getElementById('login-kicker').textContent = admin ? 'Property admin' : 'Tenant portal';
  document.getElementById('login-note').hidden = admin;
  document.getElementById('login-lost').hidden = admin;
  _loginMsgReset();
  document.getElementById('login-error').textContent = '';
}
// The sign-in message line: drop a lingering success colour before any new text.
function _loginMsgReset() {
  const el = document.getElementById('login-error');
  if(el) { clearTimeout(el._okT); el.style.color = ''; }
}
async function adminLogin() {
  _loginMsgReset();
  const email    = document.getElementById('admin-email').value.trim();
  const password = document.getElementById('admin-pw').value;
  if(!email||!password){ document.getElementById('login-error').textContent='Please enter your email and password.'; return; }
  const rememberEl = document.getElementById('admin-remember');
  const remember = !!(rememberEl && rememberEl.checked);
  // The flag must be set BEFORE sign-in so the session write it triggers is
  // persisted; an unticked box also clears any session remembered previously.
  if(remember) { try { localStorage.setItem(ADMIN_REMEMBER_KEY, '1'); } catch {} }
  else _forgetPersistedAdminSession();
  setLoading(true, 'Signing in…');
  const { data, error } = await _sbClient.auth.signInWithPassword({ email, password });
  setLoading(false);
  if(error){
    if(remember) _forgetPersistedAdminSession(); // don't leave a dangling opt-in
    document.getElementById('login-error').textContent = 'Incorrect email or password.';
    return;
  }
  currentUser = 'admin';
  _adminEmail = (data && data.user && data.user.email) || email;
  showApp();
}
async function sendPasswordReset() {
  _loginMsgReset();
  const email = document.getElementById('admin-email').value.trim();
  if(!email) { document.getElementById('login-error').textContent = 'Please enter your email first.'; return; }
  setLoading(true, 'Sending reset link…');
  const { error } = await _sbClient.auth.resetPasswordForEmail(email, {
    redirectTo: window.location.origin + window.location.pathname
  });
  setLoading(false);
  if(error) { document.getElementById('login-error').textContent = error.message; return; }
  const le = document.getElementById('login-error');
  le.style.color = 'var(--green)';
  le.textContent = 'Password reset link sent. Check your email.';
  le._okT = setTimeout(()=>{ le.style.color = ''; }, 5000);
}
const _loginAttempts = { count: 0, lockedUntil: 0 };
async function tenantLogin() {
  _loginMsgReset();
  const now = Date.now();
  if(_loginAttempts.lockedUntil > now) {
    const secs = Math.ceil((_loginAttempts.lockedUntil - now) / 1000);
    document.getElementById('login-error').textContent = 'Too many attempts. Wait ' + secs + ' seconds.';
    return;
  }
  const code = document.getElementById('tenant-code').value.trim().toUpperCase();
  document.getElementById('login-error').textContent = '';
  if(!code){ document.getElementById('login-error').textContent = 'Please enter your access code.'; return; }
  setLoading(true,'Verifying code…');
  try {
    const rows = await sbFetch('rpc/login_tenant', { method:'POST', body: JSON.stringify({ access_code: code }) });
    setLoading(false);
    if(rows && rows.length) {
      _loginAttempts.count = 0;
      currentUser=_normalizeTenant(rows[0]); tenants=rows;
      const rememberEl = document.getElementById('tenant-remember');
      try {
        if(!rememberEl || rememberEl.checked) localStorage.setItem(PORTAL_CODE_KEY, code);
        else localStorage.removeItem(PORTAL_CODE_KEY);
      } catch {}
      showApp();
    }
    else {
      // Count only FAILED attempts; lock after the 5th failure. (The server
      // enforces the real rate limit — this just gives fast local feedback.)
      _loginAttempts.count++;
      if(_loginAttempts.count >= 5) {
        _loginAttempts.lockedUntil = now + 60000;
        _loginAttempts.count = 0;
        document.getElementById('login-error').textContent = 'Too many failed attempts. Please wait 1 minute.';
        return;
      }
      document.getElementById('login-error').textContent = 'That access code was not found.';
    }
  } catch(e) {
    setLoading(false);
    const msg = (e.message && e.message.includes('Too many')) ? 'Too many attempts. Please wait and try again.' : 'Connection error. Please try again.';
    document.getElementById('login-error').textContent = msg;
  }
}

// Overdue is DERIVED from the due date at render time (see getDueStatus), so the
// stored status only distinguishes 'paid' vs everything else. Legacy rows that
// still say 'overdue' are treated exactly like 'unpaid'; no sync writes needed.

async function showApp() {
  // The sign-in screen opens on the form this device last used.
  try { localStorage.setItem('oa_login_tab', currentUser === 'admin' ? 'admin' : 'tenant'); } catch {}
  document.getElementById('login-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  document.body.classList.toggle('is-admin', currentUser==='admin');
  if (currentUser==='admin') {
    document.getElementById('header-info').textContent='Admin';
    setLoading(true,'Loading tenants…');
    try {
      const [rows] = await Promise.all([
        dbGetAll(),
        loadAdminSettings(),
        dbGetExpenses().then(x=>{ expenses = x||[]; expensesAvailable = true; _expensesLoadError = false; })
          .catch(e=>{
            expenses = [];
            // "Table missing" means migration 2 hasn't run — show setup help.
            // Anything else (network, auth) is a load error, NOT missing setup.
            const missing = _EXP_MISSING.test(e.message||'');
            expensesAvailable = !missing;
            _expensesLoadError = !missing;
          }),
        dbGetArchived().then(x=>{ archivedTenants = x||[]; _archivedLoadError = false; })
          .catch(()=>{ archivedTenants = []; _archivedLoadError = true; }),
        // Migration 3 probe: does expenses.floor exist?
        sbFetch('expenses?select=floor&limit=1').then(()=>{ expensesFloorAvailable = true; })
          .catch(e=>{ expensesFloorAvailable = _EXP_FLOOR_MISSING.test(e.message||'') ? false : null; })
      ]);
      tenants = rows || [];
    } catch(e) {
      setLoading(false);
      document.getElementById('main-content').innerHTML = '<div style="padding:48px 24px;text-align:center;"><div style="font-size:32px;margin-bottom:16px;">⚠</div><div style="font-family:Inter,sans-serif;font-size:16px;font-weight:600;color:var(--ink);margin-bottom:8px;">Could not connect to database</div><div style="font-size:13px;color:var(--muted);margin-bottom:24px;">'+esc(e.message)+'</div><div class="load-err-actions"><button class="btn-primary" style="width:auto;padding:10px 24px;" onclick="location.reload()">Retry</button><button type="button" class="btn-sec" onclick="logout()">Sign out</button></div></div>';
      tenants=[];
      return;
    }
    setLoading(false);
    _readAdminRoute();
    renderAdmin();
    _autoBillDay = todayISO();
    runAutoBilling({ fresh: true });
  } else {
    document.getElementById('header-info').innerHTML = '<span class="hi-text"><span class="hi-name">' + esc(currentUser.name) + '</span><span class="hi-unit">Unit ' + esc(currentUser.unit) + ((currentUser.floor || '').trim() ? ' · ' + esc(currentUser.floor) : '') + '</span></span>' + avatar(currentUser.name, 40);
    applyBranding();
    // Reuse the page-load settings fetch instead of firing a second one.
    await (_portalSettingsPromise || loadPortalSettings().catch(()=>{}));
    renderTenant();
  }
}

// Silent login from a ?code=XXXX portal link, a remembered admin session, or
// a remembered tenant code. Runs once on page load; any failure falls back to
// the normal login screen.
async function tryAutoLogin() {
  // The password-recovery flow owns the URL hash; admin module routes (#/…) don't.
  if(/access_token=|type=recovery/.test(window.location.hash)) return;
  let code = '';
  let fromLink = false;
  try {
    const params = new URLSearchParams(window.location.search);
    code = (params.get('code')||'').trim().toUpperCase();
  } catch {}
  if(code) {
    fromLink = true;
    // Strip the code from the address bar FIRST — every path below (tenant
    // login, admin auto-login, plain login screen) must leave no access code
    // in plain sight or in browser history.
    history.replaceState(null, '', window.location.pathname);
  }
  // Admin "keep me signed in": a persisted session logs straight in — unless
  // an explicit portal link was opened. Explicit intent wins over ambient
  // state: an admin testing a tenant's link expects the tenant portal, and a
  // tenant handed a link on a shared device must not land in the dashboard.
  if(!fromLink && _adminRememberOn()) {
    setLoading(true, 'Signing you in…');
    try {
      // getSession refreshes an expired JWT via the stored refresh token.
      const { data: { session } } = await _sbClient.auth.getSession();
      if(session) {
        currentUser = 'admin';
        _adminEmail = (session.user && session.user.email) || '';
        setLoading(false);
        showApp();
        return;
      }
    } catch {}
    setLoading(false);
    // No usable session (revoked, or refresh failed offline): fall through to
    // the login screen with the box pre-ticked to match the saved preference.
    const rememberEl = document.getElementById('admin-remember');
    if(rememberEl) rememberEl.checked = true;
    switchTab('admin');
  }
  if(!code) {
    try { code = (localStorage.getItem(PORTAL_CODE_KEY)||'').trim().toUpperCase(); } catch {}
  }
  if(!code) return;
  setLoading(true, 'Signing you in…');
  try {
    const rows = await sbFetch('rpc/login_tenant', { method:'POST', body: JSON.stringify({ access_code: code }) });
    if(rows && rows.length) {
      currentUser = _normalizeTenant(rows[0]); tenants = rows;
      // Deep-link visits deliberately do NOT persist the code: the link may
      // have been opened on a shared or borrowed device. Staying signed in
      // is the remember-me checkbox's job on the manual login form.
      setLoading(false);
      showApp();
      return;
    }
    // Code no longer valid (tenant archived / code regenerated): forget it.
    try { localStorage.removeItem(PORTAL_CODE_KEY); } catch {}
    switchTab('tenant');
    document.getElementById('tenant-code').value = code;
    if(fromLink) document.getElementById('login-error').textContent = 'That link is no longer valid — please check your access code.';
  } catch(e) {
    // Offline or rate-limited. The URL code was already stripped from the
    // address bar, so hand it back via the form — otherwise the tenant is
    // stranded with no code and no explanation.
    switchTab('tenant');
    document.getElementById('tenant-code').value = code;
    document.getElementById('login-error').textContent = 'Connection problem — tap "Open my portal" to try again.';
  }
  setLoading(false);
}
async function logout() {
  const wasAdmin = currentUser === 'admin';
  if(currentUser==='admin') {
    // Explicit sign-out always forgets the device, opt-in or not.
    _forgetPersistedAdminSession();
    try { await _sbClient.auth.signOut(); } catch {}
  }
  else { try { localStorage.removeItem(PORTAL_CODE_KEY); } catch {} }
  // Reset every piece of session state so a subsequent login starts clean.
  currentUser = null;
  _adminEmail = '';
  tenants = [];
  editingId = null;
  paymentInstructions = '';
  announcements = '';
  _portalSettingsPromise = null; // next tenant login refetches fresh settings
  expenses = [];
  expensesAvailable = true;
  _expensesLoadError = false;
  expensesFloorAvailable = null;
  archivedTenants = [];
  managedFloors = [];
  graceDays = 0;
  _archivedLoadError = false;
  expenseMonth = '';
  _editingExpenseId = null;
  filterTenantId = '';
  filterMonth    = '';
  filterFloor    = '';
  filterSearch   = '';
  billView       = 'open';
  _billingTab    = 'bills';
  tSearch = ''; tFloor = ''; tStatus = '';
  sortOrder      = 'unit-asc';
  groupMode      = 'auto';
  tableSortCol   = 'due';
  tableSortDir   = 'asc';
  tableRowLimit  = 50;
  portalMonth    = 'current';
  portalView = 'home'; portalTab = 'bills'; _portalAllPays = false;
  billForms      = [];
  _showAllMonths = false;
  autoBilling    = { enabled: true, leadDays: 7 };
  _autoBillLast  = null;
  _autoBillDay   = '';
  _adminModule   = 'home';
  _tenantDetailId = null;
  chartRange = 12; chaseTab = 'action'; tdBillTab = 'open'; insightWindow = '12m';
  billSelection.clear(); _billFiltersOpen = false; _justPaid = []; _setEdit = ''; _setEditFocus = false; _setReturn = '';
  closeMenu();
  document.body.classList.remove('is-admin');
  if(window.location.hash) history.replaceState(null, '', window.location.pathname);
  document.getElementById('login-screen').style.display='flex';
  document.getElementById('app').style.display='none';
  switchTab(wasAdmin ? 'admin' : 'tenant');
  document.getElementById('admin-email').value='';
  document.getElementById('admin-pw').value='';
  const _adminRememberEl = document.getElementById('admin-remember');
  if(_adminRememberEl) _adminRememberEl.checked = false;
  document.getElementById('tenant-code').value='';
  document.getElementById('login-error').textContent='';
  document.getElementById('main-content').innerHTML='';
  // Modals, pickers and print previews still hold the previous session's
  // data in the DOM. Close and blank them, then reload so the next person
  // on this device starts from a clean page.
  document.querySelectorAll('.open[role="dialog"], .modal-overlay.open').forEach(el => el.classList.remove('open'));
  ['pay-tenant','qb-tenant','gen-preview-body','tmpl-list','bill-list-items','pay-preview','bill-forms'].forEach(id => { const el = document.getElementById(id); if(el) el.innerHTML = ''; });
  ['stmt-preview','incstmt-preview'].forEach(id => { const f = document.getElementById(id); try { const d = f && (f.contentDocument || f.contentWindow.document); if(d){ d.open(); d.write(''); d.close(); } } catch {} });
  try { window.location.replace(window.location.pathname); } catch {}
}

// ═════════════════════════════════════════════
// ADMIN SHELL — modules, navigation, routing
// Each admin function lives in its own module (hash-routed so the phone's
// back gesture and a page refresh keep your place). Desktop shows a tab
// row under the header; phones get a bottom bar with the four daily
// modules and a "More" sheet for the rest.
// ═════════════════════════════════════════════
// Reports and Insights are two routes under one nav item (tabs on the page).
const ADMIN_MODULES = [
  { key:'home',     label:'Dashboard', short:'Home', icon:'grid' },
  { key:'tenants',  label:'Tenants',  icon:'users'   },
  { key:'billing',  label:'Billing',  icon:'receipt' },
  { key:'expenses', label:'Expenses', icon:'wallet'  },
  { key:'insights', label:'Reports & insights', icon:'chart', also:['reports'] },
  { key:'reports',  label:'Reports',  icon:'doc', hidden:true },
  { key:'settings', label:'Settings', icon:'sliders' }
];
const MOBILE_PRIMARY = ['home','tenants','billing','expenses'];

// Stroke icons (24×24, currentColor) — one consistent set instead of emoji.
const ICON_PATHS = {
  home:     'M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  users:    'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  receipt:  'M5 3h14v18l-3-2-2 2-2-2-2 2-2-2-3 2zM9 8h6M9 12h6M9 16h4',
  wallet:   'M3 7a2 2 0 0 1 2-2h13v4M3 7v10a2 2 0 0 0 2 2h15V9H5a2 2 0 0 1-2-2zM16 14h.01',
  doc:      'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8M8 17h5',
  chart:    'M3 3v18h18M7 15l4-4 3 3 5-6',
  sliders:  'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4',
  more:     'M5 12h.01M12 12h.01M19 12h.01',
  kebab:    'M12 5h.01M12 12h.01M12 19h.01',
  plus:     'M12 5v14M5 12h14',
  cash:     'M2 7h20v10H2zM12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM6 12h.01M18 12h.01',
  check:    'M5 12l5 5 9-10',
  back:     'M15 18l-6-6 6-6',
  next:     'M9 6l6 6-6 6',
  repeat:   'M17 2l4 4-4 4M3 11V9a3 3 0 0 1 3-3h15M7 22l-4-4 4-4M21 13v2a3 3 0 0 1-3 3H3',
  mail:     'M3 5h18v14H3zM3 7l9 6 9-6',
  link:     'M10 13a5 5 0 0 0 7.07 0l3-3a5 5 0 0 0-7.07-7.07l-1.5 1.5M14 11a5 5 0 0 0-7.07 0l-3 3a5 5 0 0 0 7.07 7.07l1.5-1.5',
  edit:     'M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  archive:  'M3 4h18v4H3zM5 8v12h14V8M10 12h4',
  download: 'M12 3v12M7 10l5 5 5-5M5 21h14',
  print:    'M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z',
  calendar: 'M3 5h18v16H3zM3 10h18M8 3v4M16 3v4',
  building: 'M4 21V3h11v18M15 9h5v12M8 7h3M8 11h3M8 15h3M2 21h20',
  alert:    'M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  trash:    'M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15',
  undo:     'M9 14L4 9l5-5M4 9h11a5 5 0 0 1 0 10h-3',
  search:   'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  bell:     'M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0',
  clock:    'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2',
  logout:   'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  trend:    'M3 17l6-6 4 4 8-8M14 7h7v7',
  arrowUp:  'M12 19V5M5 12l7-7 7 7',
  arrowDown:'M12 5v14M19 12l-7 7-7-7',
  userPlus: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM19 8v6M22 11h-6',
  chat:     'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z',
  grid:     'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
  chevDown: 'M6 9l6 6 6-6',
  close:    'M18 6L6 18M6 6l12 12',
  megaphone:'M3 11v2a1 1 0 0 0 1 1h2l5 4V6L6 10H4a1 1 0 0 0-1 1zM15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13',
  bank:     'M3 21h18M5 21V10M19 21V10M9 21V10M15 21V10M12 3l9 5H3z'
};
function icon(name, cls) {
  const d = ICON_PATHS[name];
  return d ? '<svg class="ico'+(cls?' '+cls:'')+'" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="'+d+'"/></svg>' : '';
}

let _adminModule = 'home';
let _tenantDetailId = null;

function _readAdminRoute() {
  const m = /^#\/([a-z]+)(?:\/([^/?#]*))?/.exec(window.location.hash || '');
  _adminModule = (m && ADMIN_MODULES.some(x => x.key === m[1])) ? m[1] : 'home';
  let sub = null;
  if(_adminModule === 'tenants' && m && m[2]) { try { sub = decodeURIComponent(m[2]); } catch { sub = null; } }
  // Another tenant opens on their open bills, not the last tab used.
  if(sub !== _tenantDetailId) tdBillTab = 'open';
  _tenantDetailId = sub;
  _billingTab = _adminModule === 'billing' && m && m[2] === 'recurring' ? 'recurring' : 'bills';
}
// Navigate between modules. Same-route calls just re-render.
function go(mod, sub) {
  const h = '#/' + mod + (sub ? '/' + encodeURIComponent(sub) : '');
  if(window.location.hash === h) { renderAdmin(); window.scrollTo(0, 0); return; }
  window.location.hash = h; // → hashchange → render
}
window.addEventListener('hashchange', () => {
  if(currentUser !== 'admin') return;
  closeMenu();
  _closeBell(false);
  const prevMod = _adminModule;
  _readAdminRoute();
  // "Paid · just now" rows and an open Settings editor belong to the page.
  if(_adminModule !== prevMod) _justPaid = [];
  if(_adminModule !== 'settings') { _setEdit = ''; _setEditFocus = false; }
  renderAdmin();
  window.scrollTo(0, 0);
  // Settings show the automatic-billing switches as they are now, not as
  // they were when this tab signed in.
  if(_adminModule === 'settings') {
    const before = JSON.stringify(autoBilling);
    _reloadAutoBillSettings().then(ok => { if(ok && _adminModule === 'settings' && JSON.stringify(autoBilling) !== before) _safeRerender(); });
  }
});
function openTenant(tid) { go('tenants', tid); }

// Per-render caches: tenant summaries (balances + reconciliation) are used
// by several widgets on one screen; compute each once per render.
let _sumCache = new Map();
let _postRender = [];

function renderAdmin() {
  if(currentUser !== 'admin') return;
  _rerenderPending = false;
  document.querySelectorAll('.td-amt-input').forEach(el => { el.dataset.cancel = '1'; });
  _sumCache = new Map();
  _postRender = [];
  renderAdminNav();
  const renderers = {
    home: renderHome, tenants: renderTenantsModule, billing: renderBillingModule,
    expenses: renderExpensesModule, reports: renderReportsModule,
    insights: renderInsightsModule, settings: renderSettingsModule
  };
  const html = (renderers[_adminModule] || renderHome)();
  document.getElementById('main-content').innerHTML = '<div class="module module-' + _adminModule + '">' + html + '</div>';
  _postRender.forEach(fn => fn());
}

// Re-render the current module without losing the scroll position — used
// after quick actions (mark paid, undo, inline edits).
function rerenderAdmin() {
  if(currentUser !== 'admin') return;
  const y = window.scrollY;
  const a = document.activeElement;
  const main = document.getElementById('main-content');
  const inMain = a && main && main.contains(a);
  const focusId = inMain && a.id ? a.id : '';
  // Id-less controls (tabs, range toggles) are matched by their onclick.
  const focusKey = inMain && !focusId ? a.getAttribute('onclick') || '' : '';
  renderAdmin();
  requestAnimationFrame(() => {
    window.scrollTo(0, y);
    const el = (focusId && document.getElementById(focusId))
      || (focusKey && main && [...main.querySelectorAll('[onclick]')].find(e => e.getAttribute('onclick') === focusKey));
    if(el) { try { el.focus({ preventScroll: true }); } catch {} }
  });
}

function renderAdminNav() {
  const tabs = document.getElementById('admin-tabs');
  const bottom = document.getElementById('bottom-nav');
  if(!tabs || !bottom) return;
  let overdueN = 0;
  tenants.forEach(t => t.bills.forEach(b => { if(billOpen(b) > 0.005 && getDueStatus(b) === 'overdue') overdueN++; }));
  const badge = k => (k === 'billing' && overdueN) ? '<span class="nav-badge" aria-label="' + overdueN + ' overdue">' + overdueN + '</span>' : '';
  const on = m => m.key === _adminModule || (m.also || []).includes(_adminModule);
  const item = (m, cls, short) => '<a href="#/' + m.key + '" class="' + cls + (on(m) ? ' active' : '') + '"'
    + (on(m) ? ' aria-current="page"' : '') + '>' + icon(m.icon) + '<span>' + esc(short && m.short || m.label) + '</span>' + badge(m.key) + '</a>';
  // Desktop sidebar (2026 redesign): brand, Receive payment, grouped menu, account.
  const sbItem = m => item(m, 'admin-tab').replace(/<\/span><\/a>$/, '</span>' + (m.key === 'tenants' && tenants.length ? '<span class="nav-count">' + tenants.length + '</span>' : '') + '</a>');
  const grp = keys => ADMIN_MODULES.filter(m => keys.includes(m.key)).map(sbItem).join('');
  const pName = (propertyName || 'Orange Apartment').trim() || 'Orange Apartment';
  tabs.innerHTML = '<div class="sb-brand"><span class="sb-mark" aria-hidden="true">' + esc(pName.charAt(0).toUpperCase()) + '</span><div><div class="sb-name">' + esc(pName) + '</div><div class="sb-sub">Property admin</div></div></div>'
    + '<button type="button" class="sb-cta" onclick="openPayModal()">' + icon('cash') + '<span>Receive payment</span></button>'
    + '<div class="admin-tabs-inner"><div class="sb-label">Menu</div>' + grp(MOBILE_PRIMARY)
    + '<div class="sb-label">Analyze</div>' + grp(ADMIN_MODULES.filter(m => !m.hidden && !MOBILE_PRIMARY.includes(m.key)).map(m => m.key)) + '</div>'
    + '<div class="sb-foot"><div class="sb-user"><span class="sb-av" aria-hidden="true">' + esc((_adminEmail.charAt(0) || 'A').toUpperCase()) + '</span><div class="sb-user-text"><span class="sb-user-name">Owner</span><span class="sb-user-sub"' + (_adminEmail ? ' title="' + esc(_adminEmail) + '"' : '') + '>' + esc(_adminEmail || 'Signed in') + '</span></div>'
    + '<button type="button" class="sb-logout" onclick="logout()" aria-label="Sign out" title="Sign out">' + icon('logout') + '</button></div><div class="sb-powered">Powered by JEZ</div></div>';
  const moreActive = !MOBILE_PRIMARY.includes(_adminModule);
  bottom.innerHTML = ADMIN_MODULES.filter(m => MOBILE_PRIMARY.includes(m.key)).map(m => item(m, 'bn-item', true)).join('')
    + '<button type="button" class="bn-item' + (moreActive ? ' active' : '') + '" onclick="openMoreMenu(this)" aria-haspopup="menu">' + icon('more') + '<span>More</span></button>';
  renderHeaderTools();
}
function openMoreMenu(anchor) {
  openMenu(anchor, [
    { label:'Reports & insights', icon:'chart', fn:()=>go('insights') },
    { label:'Settings', icon:'sliders', fn:()=>go('settings') },
    { label:'Sign out', icon:'back',    fn:()=>logout() }
  ], 'More');
}

// Module page header: eyebrow, title, optional subtitle + action buttons.
function pageHead(title, sub, actions, back) {
  return '<div class="page-head"><div class="page-head-text">'
    + (back ? '<button type="button" class="back-link" onclick="' + back.onclick + '">' + icon('back') + esc(back.label) + '</button>' : '')
    + '<h1 class="page-title">' + title + '</h1>'
    + (sub ? '<div class="page-sub">' + sub + '</div>' : '') + '</div>'
    + (actions ? '<div class="page-actions">' + actions + '</div>' : '') + '</div>';
}
function btn(label, onclick, opts) {
  opts = opts || {};
  return '<button type="button" class="' + (opts.primary ? 'btn-pri' : 'btn-sec') + (opts.cls ? ' ' + opts.cls : '') + '"'
    + (opts.title ? ' title="' + esc(opts.title) + '"' : '') + (opts.attrs || '') + ' onclick="' + onclick + '">'
    + (opts.icon ? icon(opts.icon) : '') + '<span>' + label + '</span></button>';
}
function chip(tone, text) { return '<span class="chip chip-' + tone + '">' + text + '</span>'; }
// ── 2026 redesign UI helpers: avatars, status pills, segmented tabs ──
// Initials avatar; its color comes from a hash of the name (6 tones).
function avatar(name, size) {
  let h = 0;
  for(const c of String(name || '?')) h = (h * 31 + c.charCodeAt(0)) % 1009;
  return '<span class="oa-av oa-av-' + (size || 38) + ' oa-av-t' + (h % 6) + '" aria-hidden="true">' + esc(_initials(name)) + '</span>';
}
// Status pill with a dot. tone: late | due | paid | ahead | neutral
function oaPill(tone, text) { return '<span class="oa-pill oa-pill-' + tone + '">' + text + '</span>'; }
// A bill's status as a pill ("Overdue · 27 days", "Due today", "Due in 2 days"…).
function billPill(b, justPaid) {
  if(justPaid) return oaPill('paid', 'Paid · just now');
  const ds = getDueStatus(b);
  if(ds === 'overdue') { if(!b.due) return oaPill('late', 'Overdue'); const n = daysOverdue(b); return oaPill('late', 'Overdue · ' + n + ' day' + (n !== 1 ? 's' : '')); }
  if(ds === 'grace') return oaPill('due', 'Grace period');
  if(ds === 'due-today') return oaPill('due', 'Due today');
  if(ds === 'due-soon' || ds === 'upcoming') {
    const d = diffDays(todayISO(), b.due);
    return d <= 6 ? oaPill('due', d === 1 ? 'Due tomorrow' : 'Due in ' + d + ' days') : oaPill('neutral', 'Due ' + shortDate(b.due));
  }
  if(ds === 'awaiting') return oaPill('due', 'Needs amount');
  if(ds === 'paid') return oaPill('paid', 'Paid');
  return oaPill('neutral', 'No due date');
}
// Segmented control: [{ label, count?, active, onclick }]
function segTabs(items, cls, label) {
  return '<div class="oa-seg' + (cls ? ' ' + cls : '') + '" role="group"' + (label ? ' aria-label="' + esc(label) + '"' : '') + '>'
    + items.map(x => '<button type="button" class="oa-seg-btn' + (x.active ? ' active' : '') + '" aria-pressed="' + !!x.active + '" onclick="' + x.onclick + '">'
      + '<span>' + x.label + '</span>' + (x.count != null ? '<span class="oa-seg-n">' + x.count + '</span>' : '') + '</button>').join('') + '</div>';
}
// "6.5K" / "500" for small chart labels.
function _kShort(v) {
  const a = Math.abs(v);
  if(a >= 999500) return (a / 1e6).toFixed(a >= 9.95e6 ? 0 : 1).replace(/\.0$/, '') + 'M';
  return a >= 1000 ? (a / 1000).toFixed(a >= 10000 ? 0 : 1).replace(/\.0$/, '') + 'K' : String(Math.round(a));
}
// "Oct 1, 2026"
function medDate(d) { const iso = isoOrEmpty(d); return iso ? shortDate(iso) + ', ' + iso.slice(0, 4) : ''; }
function _monthName(ym, style) { return /^\d{4}-\d{2}$/.test(ym || '') ? new Date(ym + '-02').toLocaleString('default', { month: style || 'long' }) : ''; }

// Bills marked paid from a list (Dashboard, a Billing tab) stay in that
// list as "Paid · just now" with an Undo, until another page is opened.
let _justPaid = []; // [{ tid, bi, label, due, amount, period, paidDate, open, view }]
function _jpSame(j, b) { return !!b && b.label === j.label && b.due === j.due && Number(b.amount) === Number(j.amount) && (b.period || '') === (j.period || ''); }
function _noteJustPaid(tid, bi) {
  const t = tenants.find(x => x.id === tid), b = t && t.bills[bi];
  if(!b || b.status !== 'paid') return;
  _justPaid = _justPaid.filter(j => !(j.tid === tid && j.bi === bi));
  // open: the balance this cleared (mark-paid logs no payment).
  _justPaid.push({ tid, bi, label: b.label, due: b.due, amount: b.amount, period: b.period || '', paidDate: b.paidDate || '',
    open: r2(Math.max(0, (Number(b.amount) || 0) - billTotalPaid(b))), view: _adminModule === 'billing' ? billView : _adminModule });
}
function _justPaidEntry(tid, bi) {
  if(!_justPaid.length) return null;
  const t = tenants.find(x => x.id === tid), b = t && t.bills[bi];
  return _justPaid.find(j => j.tid === tid && j.bi === bi && _jpSame(j, b) && b.status === 'paid' && (b.paidDate || '') === j.paidDate) || null;
}
// Undo a "Mark paid" from this session: exactly reverses confirmPaid().
async function undoJustPaid(tid, bi) {
  const j = _justPaidEntry(tid, bi);
  if(!j) { showToast('That bill changed since — open it to make changes.', false); rerenderAdmin(); return; }
  const ok = await saveBills(tid, bills => {
    const x = bills[bi];
    if(x && _jpSame(j, x) && x.status === 'paid') { x.status = 'unpaid'; x.paidDate = ''; }
  }, 'Moved back to unpaid.');
  if(ok === true) _justPaid = _justPaid.filter(e => e !== j);
  if(ok) rerenderAdmin();
}
// Money as text: whole pesos stay whole ("6,000"), anything with centavos
// always shows two decimals ("1,234.50", never "1,234.5"). `fixed` forces
// two decimals for printed accounting documents.
function fmtMoney(v, fixed) {
  const n = Math.round((Number(v) || 0) * 100) / 100;
  const frac = fixed || Math.abs(n - Math.trunc(n)) > 0.004;
  return n.toLocaleString('en-PH', { minimumFractionDigits: frac ? 2 : 0, maximumFractionDigits: 2 });
}
function peso(v) { return '&#8369;' + fmtMoney(v); }
const _ymFmt = {};
function fmtYM(ym, style) {
  if(!/^\d{4}-\d{2}$/.test(ym || '')) return '';
  const k = style || 'long';
  const f = _ymFmt[k] || (_ymFmt[k] = new Intl.DateTimeFormat('default', { month: k, year: 'numeric' }));
  return f.format(new Date(ym + '-02'));
}

// ─────────────────────────────────────────────
// SHARED DATA HELPERS
// ─────────────────────────────────────────────
// Financial history includes archived tenants: a tenant who moved out
// still earned and paid in the months they lived here.
function allTenants() { return tenants.concat(archivedTenants); }
// Money collected / billed for the property itself. Utilities billed back
// to tenants are pass-through (collected for the provider, IFRS 15 agent)
// and are counted apart with passThrough=true.
function cashInMonth(list, ym, passThrough) {
  let s = 0;
  list.forEach(t => (t.bills || []).forEach(b => { if(!!passThrough !== isPassThrough(b)) return; billCashEvents(b).forEach(e => { if(ymOf(e.date) === ym) s += e.amount; }); }));
  return r2(s);
}
function billedInMonth(list, ym, passThrough) {
  let s = 0;
  list.forEach(t => (t.bills || []).forEach(b => { if(!!passThrough !== isPassThrough(b)) return; if(billPeriod(b) === ym) s += Number(b.amount) || 0; }));
  return r2(s);
}
function _moneyToday() { return todayISO(); }

// Balances + reconciliation for one tenant, cached per render.
function tenantSummary(t) {
  let s = _sumCache.get(t.id);
  if(s) return s;
  let open = 0, overdue = 0, overdueCount = 0, openCount = 0, nextDue = '', awaiting = 0;
  t.bills.forEach(b => {
    if(billAwaitingAmount(b)) { awaiting++; return; }
    const o = billOpen(b);
    if(o <= 0.005) return;
    open += o; openCount++;
    if(getDueStatus(b) === 'overdue') { overdue += o; overdueCount++; }
    else if(b.due && (!nextDue || b.due < nextDue)) nextDue = b.due;
  });
  const recon = reconcileTenant(t, { today: _moneyToday(), leadDays: autoBilling.leadDays });
  const primary = recon.enabled ? (recon.charges.find(c => c.tmplId === recon.primaryId) || null) : null;
  const issues = recon.enabled ? recon.charges.reduce((n, c) => n + c.missing.length + (_creditApplicable(t, c) ? 1 : 0), 0) : 0;
  s = { open: r2(open), overdue: r2(overdue), overdueCount, openCount, nextDue, awaiting, recon, primary, issues };
  _sumCache.set(t.id, s);
  return s;
}
function tenantBalance(t) { return tenantSummary(t).open; }
// Short date, with the year when it isn't this year ("Oct 14" / "Oct 14, 2024").
function shortDateY(d) {
  const iso = isoOrEmpty(d);
  if(!iso) return '';
  return iso.slice(0, 4) === todayISO().slice(0, 4) ? shortDate(iso) : shortDate(iso) + ', ' + iso.slice(0, 4);
}

// Recurring charges whose CURRENT cycle should be billed by now but isn't
// (due date passed, or within the posting lead) — for tenants without a
// move-in date, whom the reconciliation checker can't cover. Waived cycles
// don't count.
function unpostedCurrent(t) {
  if(moveInOf(t)) return [];
  const ym = _currentYM(), today = todayISO();
  return activeTemplates(t).filter(tm => normLabel(tm.label)).map(tm => {
    const due = templateDueDate(t, tm, ym);
    if(diffDays(today, due) > autoBilling.leadDays) return null;
    if(Array.isArray(tm.skip) && tm.skip.includes(ym)) return null;
    if(templateBillExists(t, tm, ym)) return null;
    return { tmpl: tm, period: ym, due };
  }).filter(Boolean);
}
async function postCurrentCycle(tid, tmplId, period) {
  const ok = await saveTenantData(tid, x => backfillCycles(x, tmplId, [period]), 'Bill posted.');
  if(ok) rerenderAdmin();
}


// ─────────────────────────────────────────────
// HOME
// ─────────────────────────────────────────────
// Dashboard state
let chartRange = 12;       // Income vs expenses: 6 | 12 months
let chaseTab = 'action';   // Bills to chase: 'action' | 'former' | 'all'
let _dashChart = null;     // rows behind the chart's hover tooltip

function renderHome() {
  const cur = _currentYM(), today = todayISO();
  const hasExp = expensesAvailable && !_expensesLoadError;
  const all = allTenants();
  const head = pageHead(_greeting(), new Date().toLocaleDateString('en-PH', { weekday: 'long', month: 'long', day: 'numeric' }) + ' · here’s how ' + esc(propertyName || 'the building') + ' is doing');
  if(!all.length) {
    return head + '<div class="empty-state"><div class="icon">&#127962;</div><p>No tenants yet. Add your first tenant to get started.</p>' + btn('Add tenant', 'openAddModal()', { primary: true, icon: 'plus' }) + '</div>';
  }
  // One accrual series for the page — the same figures as Insights and the income statement.
  const inc = computeIncomeStatement({ tenants: all, expenses, hasExpenses: hasExp, floorRank, floorCanon: appFloorCanon(), allocation: 'none',
    from: addYM(cur, -11), to: cur, basis: 'accrual', prorate: _incStmtProrate() });
  const rows = inc.perMonth.__total;
  return head
    + '<div class="dash-row">' + _dashNetCard(rows, hasExp) + _dashDueCard(today) + _dashQuickCard() + '</div>'
    + _dashChartCard(rows, hasExp)
    + (_archivedLoadError ? '<div class="hint-note">' + icon('alert') + ' Archived tenants could not be loaded — former tenants\' history is missing from these figures. Refresh to retry.</div>' : '')
    + _dashChaseCard(today);
}

// Net income for the last full month, its change, and a 6-month sparkline.
function _dashNetCard(rows, hasExp) {
  const val = r => hasExp ? r.net : r.revenue;
  const n = rows.length, last = rows[n - 2], prev = rows[n - 3], now = rows[n - 1];
  const v = val(last), pv = val(prev);
  const pct = pv ? Math.round((v - pv) / Math.abs(pv) * 1000) / 10 : null;
  const delta = pct === null ? '<span class="dash-note">No figures for ' + _monthName(prev.ym) + '</span>'
    : '<span class="dash-note"><span class="oa-delta ' + (pct >= 0 ? 'up' : 'down') + '">' + icon(pct >= 0 ? 'arrowUp' : 'arrowDown') + (pct > 0 ? '+' : pct < 0 ? '−' : '') + Math.abs(pct) + '%</span>vs ' + _monthName(prev.ym) + '</span>';
  const sp = rows.slice(-7, -1).map(val);
  const lo = Math.min(...sp), hi = Math.max(...sp), span = (hi - lo) || 1;
  const pts = sp.map((x, i) => [i * 150 / (sp.length - 1), 50 - (x - lo) / span * 44]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const end = pts[pts.length - 1];
  const spark = '<svg class="dash-spark" viewBox="0 0 150 56" width="150" height="56" aria-hidden="true" focusable="false"><path class="sp-fill" d="' + line + ' L150 56 L0 56 Z"/><path class="sp-line" d="' + line + '"/>'
    + '<circle class="sp-dot" cx="' + end[0].toFixed(1) + '" cy="' + end[1].toFixed(1) + '" r="4.5"/></svg>';
  const money = x => (x < 0 ? '&minus;' : '') + peso(Math.abs(x));
  const stat = (l, x) => '<div class="dash-stat"><span>' + l + '</span><strong>' + x + '</strong></div>';
  return '<section class="card dash-card">'
    + '<div class="dash-card-head"><span class="dash-ic accent">' + icon('trend') + '</span><span class="dash-card-title">' + (hasExp ? 'Net income' : 'Revenue earned') + '<span class="dash-title-mo"> · ' + _monthName(last.ym, 'short') + '</span></span>'
    +   '<span class="oa-tag">' + _monthName(last.ym) + '</span></div>'
    + '<div class="dash-fig-row"><div class="dash-fig-col"><span class="dash-fig' + (v < 0 ? ' neg' : '') + '">' + money(v) + '</span>' + delta + '</div>' + spark + '</div>'
    + '<div class="dash-foot dash-foot-3">' + stat('Income', peso(last.revenue)) + stat('Expenses', hasExp ? peso(last.expenses) : '&mdash;')
    +   stat(_monthName(now.ym) + ' so far', money(val(now))) + '</div>'
    + '</section>';
}

// Open bills falling due today through six days from now, with a day strip.
function _dashDueCard(today) {
  const days = [];
  for(let i = 0; i < 7; i++) days.push({ iso: addDaysISO(today, i), total: 0, n: 0 });
  const items = [];
  tenants.forEach(t => t.bills.forEach(b => {
    if(!b.due || billAwaitingAmount(b)) return;
    const o = billOpen(b);
    if(o <= 0.005) return;
    const d = diffDays(today, b.due);
    if(d < 0 || d > 6) return;
    days[d].total = r2(days[d].total + o); days[d].n++;
    items.push({ t, b, o, d });
  }));
  items.sort((a, b) => a.d - b.d || a.t.name.localeCompare(b.t.name));
  const total = r2(items.reduce((s, x) => s + x.o, 0));
  const wd = iso => new Date(iso + 'T00:00:00').toLocaleDateString('en-PH', { weekday: 'short' });
  const f = items[0];
  const first = f ? 'First one ' + (f.d === 0 ? 'today' : f.d === 1 ? 'tomorrow' : 'on ' + wd(f.b.due)) + ': ' + esc(f.t.name) + ', ' + esc(f.b.label) + ' ' + peso(f.o) : 'Nothing falls due this week.';
  const max = Math.max(1, ...days.map(x => x.total));
  const strip = days.map((x, i) => {
    const lbl = i === 0 ? 'Today' : wd(x.iso);
    const tip = new Date(x.iso + 'T00:00:00').toLocaleDateString('en-PH', { weekday: 'short', month: 'short', day: 'numeric' }) + (x.n ? ' · ' + x.n + ' bill' + (x.n !== 1 ? 's' : '') + ', ₱' + fmtMoney(x.total) : ' · nothing due');
    return '<div class="ds-day' + (i === 0 ? ' today' : '') + (x.n ? ' has' : '') + '" title="' + esc(tip) + '">'
      + (x.n ? '<span class="ds-amt">' + _kShort(x.total) + '</span><span class="ds-bar" style="height:' + Math.max(7, Math.round(x.total / max * 40)) + 'px"></span>' : '<span class="ds-stub"></span>')
      + '<span class="ds-lbl">' + lbl + '</span></div>';
  }).join('');
  return '<section class="card dash-card">'
    + '<div class="dash-card-head"><span class="dash-ic warn">' + icon('calendar') + '</span><span class="dash-card-title">Due in the next 7 days</span>'
    +   '<span class="oa-tag">' + items.length + ' bill' + (items.length !== 1 ? 's' : '') + '</span></div>'
    + '<div class="dash-fig-col"><span class="dash-fig">' + peso(total) + '</span><span class="dash-note">' + first + '</span></div>'
    + '<div class="dash-foot dash-strip" role="img" aria-label="Bills due each day for the next 7 days">' + strip + '</div>'
    + '</section>';
}

function _dashQuickCard() {
  const qa = (ic, label, fn) => '<button type="button" class="dash-qa" onclick="' + fn + '"><span class="dash-qa-ic">' + icon(ic) + '</span><span class="dash-qa-label">' + label + '</span>' + icon('next', 'dash-qa-chev') + '</button>';
  return '<section class="card dash-card dash-quick"><h2 class="dash-quick-title">Quick actions</h2>'
    + qa('receipt', 'Add a bill', 'openQuickBill()') + qa('userPlus', 'Add a tenant', 'openAddModal()') + qa('wallet', 'Log an expense', 'logExpenseShortcut()')
    + _autoBillChip() + '</section>';
}
// Automatic billing at a glance; opens the recurring checker.
function _autoBillChip() {
  let review = 0;
  tenants.forEach(t => {
    review += unpostedCurrent(t).length;
    const s = tenantSummary(t);
    if(s.recon.enabled) s.recon.charges.forEach(c => { review += c.missing.length + (_creditApplicable(t, c) ? 1 : 0); });
  });
  const last = _autoBillLast;
  const when = d => d === todayISO() ? 'today' : 'on ' + shortDate(d);
  let tone = 'good', text;
  if(!autoBilling.enabled) { tone = 'neutral'; text = 'Auto-billing off · post recurring bills from Billing'; }
  else if(!last) text = 'Auto-billing on · checking recurring bills…';
  else if(last.failed) { tone = 'warn'; text = 'Auto-billing: ' + last.failed + ' bill' + (last.failed !== 1 ? 's' : '') + ' could not be saved · open the checker'; }
  else if(last.noRev) { tone = 'warn'; text = 'Auto-billing paused for ' + last.noRev + ' tenant' + (last.noRev !== 1 ? 's' : '') + ' · run migration 2 (Settings)'; }
  else text = 'Auto-billing on · ' + (last.posted.length ? last.posted.length + ' bill' + (last.posted.length !== 1 ? 's' : '') + ' posted ' + when(last.day) : 'nothing new to post ' + when(last.day));
  if(review && tone === 'good') { tone = 'warn'; text += ' · ' + review + ' to review'; }
  const to = last && last.noRev && !last.failed ? 'go(\'settings\')' : 'go(\'billing\',\'recurring\')';
  return '<button type="button" class="dash-auto ' + tone + '" onclick="' + to + '">' + icon('repeat') + '<span>' + text + '</span></button>';
}

// Income vs expenses, grouped bars; hover/focus picks a month.
function _dashChartCard(rows, hasExp) {
  const R = _isPhone() ? 6 : (chartRange === 6 ? 6 : 12);
  const rr = rows.slice(-R);
  _dashChart = { rows: rr, hasExp };
  const sum = k => r2(rr.reduce((s, r) => s + r[k], 0));
  const inc = sum('revenue'), exp = hasExp ? sum('expenses') : 0, net = r2(inc - exp);
  // No figures at all: a ₱0–20K scale rather than a "₱1" axis.
  const max = Math.max(0, ...rr.map(r => Math.max(r.revenue, hasExp ? r.expenses : 0))) || 20000;
  const step = _niceStep(max / 4), top = Math.ceil(max / step) * step, nT = Math.round(top / step);
  const pct = v => Math.max(0, v / top * 100).toFixed(2) + '%';
  let yAxis = '', grid = '';
  for(let k = 0; k <= nT; k++) {
    const b = (k / nT * 100).toFixed(2) + '%';
    yAxis += '<span style="bottom:' + b + '">' + _compactPeso(k * step).replace('k', 'K') + '</span>';
    if(k) grid += '<i style="bottom:' + b + '"></i>';
  }
  const sel = R - 2;
  const cols = rr.map((r, i) => '<div class="ch-col' + (i === sel ? ' sel' : '') + (i === R - 1 ? ' partial' : '') + '" role="img" tabindex="0" data-i="' + i + '" onmouseenter="dashChartSel(' + i + ')" onfocus="dashChartSel(' + i + ')"'
      + ' aria-label="' + esc(fmtYM(r.ym) + (i === R - 1 ? ' so far' : '') + ': income ₱' + fmtMoney(r.revenue) + (hasExp ? ', expenses ₱' + fmtMoney(r.expenses) : '')) + '">'
      + '<span class="ch-bar inc" style="height:' + pct(r.revenue) + '"></span>' + (hasExp ? '<span class="ch-bar exp" style="height:' + pct(r.expenses) + '"></span>' : '') + '</div>').join('');
  const labels = rr.map((r, i) => '<span class="' + (i === sel ? 'sel' : '') + '">' + _monthName(r.ym, 'short') + '</span>').join('');
  const toggle = segTabs([6, 12].map(n => ({ label: n + ' months', active: n === R, onclick: 'chartRange=' + n + ';rerenderAdmin()' })), 'sm ch-range', 'Chart range');
  _postRender.push(() => dashChartSel(sel));
  return '<section class="card dash-chart">'
    + '<div class="ch-head"><div class="ch-titles"><h2 class="card-title">Income' + (hasExp ? ' vs expenses' : '') + '</h2>'
    +   '<span class="ch-sub">Last ' + R + ' months' + (hasExp ? ' · net income <b>' + (net < 0 ? '&minus;' : '') + peso(Math.abs(net)) + '</b>' : '') + '</span></div>'
    +   '<div class="ch-side"><div class="ch-legend"><span class="ch-key"><i class="k-inc"></i>Income</span><strong>' + peso(inc) + '</strong></div>'
    +   (hasExp ? '<div class="ch-legend"><span class="ch-key"><i class="k-exp"></i>Expenses</span><strong>' + peso(exp) + '</strong></div>' : '') + toggle + '</div></div>'
    + '<div class="ch-body"><div class="ch-y" aria-hidden="true">' + yAxis + '</div>'
    +   '<div class="ch-plot r' + R + '" onmouseleave="dashChartSel(' + sel + ')"><div class="ch-grid" aria-hidden="true">' + grid + '</div>'
    +     '<div class="ch-tip" id="ch-tip" aria-live="polite"></div><div class="ch-cols">' + cols + '</div></div>'
    +   '<span></span><div class="ch-x r' + R + '" aria-hidden="true">' + labels + '</div></div>'
    + '</section>';
}
function dashChartSel(i) {
  const D = _dashChart, tip = document.getElementById('ch-tip');
  if(!D || !tip || !D.rows[i]) return;
  const r = D.rows[i], R = D.rows.length, partial = i === R - 1;
  document.querySelectorAll('.ch-col').forEach((c, k) => c.classList.toggle('sel', k === i));
  document.querySelectorAll('.ch-x span').forEach((c, k) => c.classList.toggle('sel', k === i));
  const net = r2(r.revenue - (D.hasExp ? r.expenses : 0));
  tip.innerHTML = '<b>' + fmtYM(r.ym, 'short') + (partial ? ' · so far' : '') + '</b><span><i class="k-inc"></i>Income ' + peso(r.revenue) + '</span>'
    + (D.hasExp ? '<span><i class="k-exp"></i>Expenses ' + peso(r.expenses) + '</span><span class="ch-tip-net">Net <b>' + (net < 0 ? '&minus;' : '') + peso(Math.abs(net)) + '</b></span>' : '');
  const w = 100 / R, edge = R === 12 ? 3 : 1;
  tip.style.left = tip.style.right = ''; tip.className = 'ch-tip';
  if(i <= edge) tip.style.left = (i * w).toFixed(2) + '%';
  else if(i >= R - 1 - edge) tip.style.right = ((R - 1 - i) * w).toFixed(2) + '%';
  else { tip.style.left = ((i + 0.5) * w).toFixed(2) + '%'; tip.classList.add('mid'); }
  // Never past the plot's edges (narrow plots, long figures).
  const pr = tip.parentElement.getBoundingClientRect(), tr = tip.getBoundingClientRect();
  if(pr.width && tr.width && (tr.left < pr.left - 0.5 || tr.right > pr.right + 0.5) && !_isPhone()) {
    const x = Math.max(0, Math.min(pr.width - tr.width, tr.left - pr.left));
    tip.classList.remove('mid'); tip.style.right = ''; tip.style.left = x.toFixed(1) + 'px';
  }
}

// Bills to chase: overdue and due within 7 days, plus former tenants' balances.
function _dashChaseCard(today) {
  const action = [], former = [], open = [];
  tenants.forEach(t => t.bills.forEach((b, bi) => {
    const jp = _justPaidEntry(t.id, bi);
    if(jp && jp.view === 'home') {
      // Only in the tabs whose criteria the bill met when it was paid.
      const it = { t, b, bi, o: jp.open, paid: true };
      open.push(it);
      if(b.due && diffDays(today, b.due) <= 6) action.push(it);
      return;
    }
    if(billAwaitingAmount(b)) return;
    const o = billOpen(b);
    if(o <= 0.005) return;
    const it = { t, b, bi, o };
    open.push(it);
    const ds = getDueStatus(b);
    if(ds === 'overdue' || ds === 'grace' || (b.due && diffDays(today, b.due) <= 6)) action.push(it);
  }));
  archivedTenants.forEach(t => (t.bills || []).forEach((b, bi) => {
    const o = billOpen(b);
    if(o <= 0.005 || billAwaitingAmount(b)) return;
    const it = { t, b, bi, o, former: true };
    former.push(it); open.push(it);
  }));
  const byDue = (a, b) => (a.b.due || '9999').localeCompare(b.b.due || '9999') || a.t.name.localeCompare(b.t.name);
  [action, former, open].forEach(l => l.sort(byDue));
  const lists = { action, former, all: open };
  if(!lists[chaseTab]) chaseTab = 'action';
  const list = lists[chaseTab];
  const live = list.filter(x => !x.paid);
  const tabs = segTabs([['action', 'Needs action'], ['former', 'Former tenants'], ['all', 'All open']].map(([k, l]) => ({
    label: l, count: lists[k].filter(x => !x.paid).length, active: k === chaseTab, onclick: 'chaseTab=\'' + k + '\';rerenderAdmin()' })), '', 'Which bills');
  // The 8-row cap counts unpaid rows only; just-paid rows ride along.
  const keep = new Set(live.slice(0, 8));
  const shown = list.filter(x => x.paid || keep.has(x));
  const row = it => {
    const t = it.t, b = it.b;
    const where = 'Unit ' + esc(t.unit) + (it.former ? ' · moved out' : t.floor ? ' · ' + esc(t.floor) : '');
    const name = it.former ? '<span class="oa-name">' + esc(t.name) + '</span>' : '<a class="oa-name" href="#/tenants/' + encodeURIComponent(t.id) + '">' + esc(t.name) + '</a>';
    const acts = it.former ? '<span class="oa-muted-sm" title="Restore the tenant (Tenants › Archived) to settle this bill">Moved out</span>'
      : '<button type="button" class="oa-icon-btn" title="Copy payment reminder" aria-label="Copy payment reminder for ' + esc(t.name) + '" onclick="copyReminder(this.closest(\'[data-tid]\').dataset.tid)">' + icon('chat') + '</button>'
        + (it.paid ? '<button type="button" class="oa-btn-undo" onclick="const r=this.closest(\'[data-tid]\');undoJustPaid(r.dataset.tid,+r.dataset.bi)">Undo</button>'
          : '<button type="button" class="oa-btn-paid" onclick="const r=this.closest(\'[data-tid]\');quickMarkPaid(r.dataset.tid,+r.dataset.bi)">Mark paid</button>');
    return '<div class="oa-tr' + (it.paid ? ' is-paid' : '') + '" role="row" data-tid="' + esc(t.id) + '" data-bi="' + it.bi + '">'
      + '<div class="oa-who" role="cell">' + avatar(t.name, 38) + '<div class="oa-who-text">' + name + '<span class="oa-sub">' + where + '</span></div></div>'
      + '<span class="oa-cell-bill" role="cell">' + esc(b.label || 'Bill') + '</span>'
      + '<span class="oa-cell-due" role="cell">' + (b.due ? shortDate(b.due) : '&mdash;') + '</span>'
      + '<span class="oa-cell-status" role="cell">' + billPill(b, it.paid) + '</span>'
      + '<span class="oa-cell-amt" role="cell">' + peso(it.o) + '</span>'
      + '<div class="oa-cell-act" role="cell">' + acts + '</div></div>';
  };
  const archFail = chaseTab === 'former' && _archivedLoadError;
  const empty = archFail ? 'Former tenants could not be loaded — refresh to retry.'
    : { action: 'Nothing overdue or due in the next 7 days.', former: 'Former tenants owe nothing.', all: 'No open bills — everyone is settled.' }[chaseTab];
  const awaitingN = tenants.reduce((n, t) => n + t.bills.filter(b => getDueStatus(b) === 'awaiting').length, 0);
  return '<section class="card oa-table-card dash-chase">'
    + '<div class="oa-card-head"><div><h2 class="card-title">Bills to chase</h2><span class="oa-card-sub">Overdue, and due in the next 7 days</span></div>' + tabs + '</div>'
    + (shown.length
      ? '<div class="oa-table t-chase" role="table" aria-label="Bills to chase"><div class="oa-thead" role="row"><span role="columnheader">Tenant</span><span role="columnheader">Bill</span><span role="columnheader">Due</span><span role="columnheader">Status</span><span class="r" role="columnheader">Amount</span><span role="columnheader"><span class="sr-only">Actions</span></span></div>' + shown.map(row).join('') + '</div>'
      : '<div class="oa-empty">' + icon(archFail ? 'alert' : 'check') + ' ' + empty + '</div>')
    + (awaitingN ? '<div class="oa-hint">' + icon('alert') + ' ' + awaitingN + ' bill' + (awaitingN !== 1 ? 's are' : ' is') + ' waiting for an amount (e.g. a meter reading). <button type="button" class="link-btn inline" onclick="goBills(\'awaiting\')">Enter amounts</button></div>' : '')
    + '<div class="oa-card-foot"><span>' + live.length + ' open · ' + peso(r2(live.reduce((s, x) => s + x.o, 0))) + (live.length > keep.size ? ' · showing ' + keep.size : '') + '</span>'
    +   '<button type="button" class="link-btn oa-more" onclick="goBills(\'open\')">All open bills' + icon('next') + '</button></div>'
    + '</section>';
}
function goBills(view) {
  billView = BILL_VIEWS[view] ? view : 'open';
  tableSortCol = 'due'; tableSortDir = 'asc';
  filterTenantId = ''; filterMonth = ''; filterFloor = ''; filterSearch = '';
  _billingTab = 'bills';
  tableRowLimit = 50;
  go('billing');
}


// ─────────────────────────────────────────────
// TENANTS MODULE
// ─────────────────────────────────────────────
let tSearch = '', tFloor = '', tStatus = '';
const T_STATUS = { '':'All tenants', owing:'Has a balance', overdue:'Overdue', awaiting:'Needs an amount', settled:'Settled', advance:'Paid ahead', behind:'Behind on cycles', issues:'Needs reconciling', nomovein:'No move-in date' };
const T_TABS = [['', 'All'], ['owing', 'Owing'], ['overdue', 'Overdue'], ['advance', 'Paid ahead']];

function renderTenantsModule() {
  if(_tenantDetailId) {
    const t = tenants.find(x => x.id === _tenantDetailId);
    if(t) return renderTenantDetail(t);
    const a = archivedTenants.find(x => x.id === _tenantDetailId);
    return pageHead('Tenant not found', a ? esc(a.name) + ' is archived.' : 'This tenant may have been archived or deleted.', '', { label: 'Tenants', onclick: 'go(\'tenants\')' });
  }
  const floorsN = new Set(tenants.map(t => floorNorm(t.floor)).filter(Boolean)).size;
  const owed = r2(tenants.reduce((s, t) => s + tenantBalance(t), 0));
  const sub = tenants.length + ' active' + (floorsN ? ' across ' + floorsN + ' floor' + (floorsN !== 1 ? 's' : '') : '') + ' · ' + (owed ? peso(owed) + ' owed' : 'nothing owed');
  const tabs = segTabs(T_TABS.map(([k, l]) => ({ label: l, count: _tenantStatusList(k).length, active: tStatus === k, onclick: 'tStatus=\'' + k + '\';rerenderAdmin()' })), 'on-bg tn-tabs', 'Show tenants');
  const extra = tStatus && !T_TABS.some(x => x[0] === tStatus)
    ? '<button type="button" class="oa-filter-chip" onclick="tStatus=\'\';rerenderAdmin()" aria-label="Clear filter: ' + esc(T_STATUS[tStatus]) + '">' + esc(T_STATUS[tStatus]) + icon('close') + '</button>' : '';
  const floors = floorList();
  const floorLbl = !tFloor ? 'All floors' : tFloor === '__none__' ? 'No floor set' : tFloor;
  const floorBtn = floors.length ? '<button type="button" class="oa-dd" onclick="openFloorFilterMenu(this)" aria-haspopup="menu" aria-label="Floor: ' + esc(floorLbl) + '"><span>' + esc(floorLbl) + '</span>' + icon('chevDown') + '</button>' : '';
  _postRender.push(renderTenantList);
  return pageHead('Tenants', sub, '<button type="button" class="oa-round-add" onclick="openAddModal()" aria-label="Add tenant">' + icon('plus') + '</button>')
    + '<div class="oa-toolbar tn-toolbar">' + tabs + extra
    +   '<label class="oa-search">' + icon('search') + '<input type="search" id="tenant-search" placeholder="Name, unit or access code" value="' + esc(tSearch) + '" oninput="tSearch=this.value;renderTenantList()" aria-label="Search tenants"></label>'
    +   floorBtn
    +   '<button type="button" class="oa-icon-btn lg" onclick="openViewMenu(this)" aria-haspopup="menu" aria-label="Sort, group and more filters" title="Sort, group and more filters">' + icon('sliders') + '</button>'
    +   '<span class="oa-toolbar-gap"></span>' + btn('Add tenant', 'openAddModal()', { primary: true, icon: 'plus', cls: 'tn-add' })
    + '</div>'
    + '<section class="card oa-table-card tn-card" id="tenant-list"></section>'
    + '<details class="archived-section" id="archived-section" ontoggle="if(this.open)loadArchivedTenants()"><summary>Archived tenants</summary><div id="archived-tenants-wrap" class="archived-wrap"></div></details>';
}
function openViewMenu(anchor) {
  const items = Object.entries(SORT_LABELS).map(([k, l]) => ({ label: (sortOrder === k ? '✓ ' : '') + l, fn: () => { sortOrder = k; rerenderAdmin(); } }));
  Object.entries(GROUP_LABELS).forEach(([k, l]) => items.push({ label: (groupMode === k ? '✓ ' : '') + 'Group: ' + l, fn: () => { groupMode = k; rerenderAdmin(); } }));
  Object.entries(T_STATUS).filter(([k]) => k && !T_TABS.some(x => x[0] === k)).forEach(([k, l]) => items.push({ label: (tStatus === k ? '✓ ' : '') + 'Show: ' + l, fn: () => { tStatus = tStatus === k ? '' : k; rerenderAdmin(); } }));
  openMenu(anchor, items, 'Sort, group & filter');
}
function openFloorFilterMenu(anchor) {
  const opts = [['', 'All floors']].concat(floorList().map(f => [f, f]));
  if(tenants.some(t => !floorKey(t))) opts.push(['__none__', 'No floor set']);
  openMenu(anchor, opts.map(([k, l]) => ({ label: (tFloor === k ? '✓ ' : '') + l, fn: () => { tFloor = k; rerenderAdmin(); } })), 'Floor');
}
function openArchivedSection() {
  const d = document.getElementById('archived-section');
  if(!d) return;
  d.open = true;
  d.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Tenants matching a status filter (before floor/search) — also the tab counts.
function _tenantStatusList(st) {
  if(!st) return tenants;
  return tenants.filter(t => {
    const s = tenantSummary(t);
    switch(st) {
      case 'owing':    return s.open > 0;
      case 'awaiting': return s.awaiting > 0;
      case 'overdue':  return s.overdue > 0;
      case 'settled':  return s.open <= 0 && !s.awaiting;
      case 'advance':  return !!(s.primary && s.primary.status === 'advance');
      case 'behind':   return !!(s.primary && s.primary.status === 'behind');
      case 'issues':   return s.issues > 0;
      case 'nomovein': return !moveInOf(t);
    }
    return true;
  });
}
function tenantsForList() {
  let list = _tenantStatusList(tStatus).slice();
  if(tFloor) { const want = floorNorm(tFloor === '__none__' ? '' : tFloor); list = list.filter(t => floorNorm(t.floor) === want); }
  const q = tSearch.trim().toLowerCase();
  if(q) list = list.filter(t => [t.name, t.unit, t.floor, t.code, t.phone, t.email].some(v => String(v || '').toLowerCase().includes(q)));
  const urg = t => t.bills.filter(x => billOpen(x) > 0.005).reduce((m, x) => Math.min(m, getDueUrgencyScore(x)), 10000);
  return list.sort((a, b) => {
    let r = 0;
    if(sortOrder === 'unit-asc')          r = unitRank(a.unit) - unitRank(b.unit);
    else if(sortOrder === 'unit-desc')    r = unitRank(b.unit) - unitRank(a.unit);
    else if(sortOrder === 'floor-asc')    r = floorRank(floorKey(a) || 'zz') - floorRank(floorKey(b) || 'zz');
    else if(sortOrder === 'name-asc')     r = a.name.localeCompare(b.name);
    else if(sortOrder === 'balance-desc') r = tenantBalance(b) - tenantBalance(a);
    else if(sortOrder === 'balance-asc')  r = tenantBalance(a) - tenantBalance(b);
    else if(sortOrder === 'urgency')      r = urg(a) - urg(b);
    return r || unitRank(a.unit) - unitRank(b.unit) || a.name.localeCompare(b.name);
  });
}

// The main rent's most recent cycles (n), ending at the furthest cycle paid
// ahead: paid | ahead | due | late | waived — for the cycle squares.
function rentCycles(t, n) {
  const c = tenantSummary(t).primary;
  if(!c || c.variable || !c.cyclesStarted || !c.startYM) return [];
  const tmpl = (t.templates || []).find(x => x.id === c.tmplId) || {};
  const skip = new Set(Array.isArray(tmpl.skip) ? tmpl.skip : []);
  const today = todayISO(), mi = moveInOf(t);
  const end = Math.max(c.cyclesStarted, c.covered) - 1;
  const out = [];
  for(let k = Math.max(0, end - n + 1); k <= end; k++) {
    const ym = addYM(c.startYM, k);
    let st;
    if(skip.has(ym) && !templateBillExists(t, tmpl, ym)) st = 'waived';
    else if(k < c.covered) st = k < c.cyclesStarted ? 'paid' : 'ahead';
    else st = diffDays((c.dues && c.dues[ym]) || templateDueDate(t, tmpl, ym), today) > graceDays ? 'late' : 'due';
    const w = cycleWindow(mi, ym);
    const word = { paid: 'paid', ahead: 'paid ahead', due: 'due', late: 'late', waived: 'waived' }[st];
    out.push({ ym, st, title: fmtYM(ym, 'short') + ' cycle (' + shortDate(w.start) + ' – ' + shortDate(addDaysISO(w.end, -1)) + '): ' + word });
  }
  return out;
}
function cycleSquares(t, n, cls) {
  const cy = rentCycles(t, n);
  return cy.length ? '<span class="oa-cy' + (cls ? ' ' + cls : '') + '" role="img" aria-label="Last ' + cy.length + ' rent cycles: ' + cy.map(x => x.st).join(', ') + '">'
    + cy.map(x => '<i class="q-' + x.st + '" title="' + esc(x.title) + '"></i>').join('') + '</span>' : '';
}
// Tenant status as a pill: Overdue · Due today · Due Oct 4 · Paid ahead · Settled.
function tenantPill(t) {
  const s = tenantSummary(t);
  if(s.overdue > 0) return oaPill('late', 'Overdue');
  if(s.open > 0) return oaPill('due', s.nextDue === todayISO() ? 'Due today' : s.nextDue ? 'Due ' + shortDate(s.nextDue) : 'Owing');
  if(s.awaiting) return oaPill('due', 'Needs amount');
  if(s.primary && s.primary.status === 'advance') return oaPill('ahead', 'Paid ahead');
  return oaPill('neutral', 'Settled');
}
// Monthly rate of the main recurring charge (all-inclusive: the flat rate).
function tenantRate(t) {
  const p = primaryTemplate(t);
  return p ? tmplRate(p) : (Number(t.flat_rate) || 0);
}

function tenantRowHtml(t) {
  const s = tenantSummary(t);
  const rate = tenantRate(t);
  const p = s.primary;
  const thru = p && !p.variable ? (p.paidThrough ? shortDateY(p.paidThrough) : 'Not yet') : '';
  const phoneSub = 'Unit ' + esc(t.unit) + (thru && thru !== 'Not yet' ? ' · Paid to ' + thru : '');
  return '<div class="oa-tr tn-row" role="link" tabindex="0" data-tid="' + esc(t.id) + '" onclick="openTenant(this.dataset.tid)" onkeydown="if(event.key===\'Enter\'&&event.target===this)openTenant(this.dataset.tid)">'
    + '<div class="oa-who">' + avatar(t.name, 40) + '<div class="oa-who-text"><span class="oa-name">' + esc(t.name) + '</span>'
    +   '<span class="oa-sub dt-only">' + (t.phone ? esc(t.phone) : t.email ? esc(t.email) : '&nbsp;') + '</span><span class="oa-sub ph-only">' + phoneSub + '</span></div></div>'
    + '<div class="tn-two"><strong>Unit ' + esc(t.unit) + '</strong><span>' + (floorKey(t) ? esc(t.floor) : '&mdash;') + '</span></div>'
    + '<div class="tn-two tn-billing"><strong>' + (rate ? peso(rate) + ' / month' : '&mdash;') + '</strong><span>' + (t.billing_model === 'inclusive' ? 'All-inclusive' : 'Itemized') + '</span></div>'
    + '<div class="tn-thru">' + (thru ? '<span>' + thru + '</span>' + cycleSquares(t, 6) : '<span class="oa-muted-sm">' + (moveInOf(t) ? 'No recurring rent' : 'No move-in date') + '</span>') + '</div>'
    + '<div class="tn-status">' + tenantPill(t) + (s.issues ? '<span class="tn-issue">' + s.issues + ' to reconcile</span>' : '') + '</div>'
    + '<div class="oa-cell-amt tn-bal' + (s.overdue > 0 ? ' bad' : '') + (s.open ? '' : ' zero') + '">' + (s.open ? peso(s.open) : '&mdash;') + '</div>'
    + '<span class="tn-chev" aria-hidden="true">' + icon('next') + '</span>'
    + '</div>';
}

function renderTenantList() {
  const c = document.getElementById('tenant-list');
  if(!c) return;
  if(!tenants.length) { c.innerHTML = '<div class="empty-state"><div class="icon">&#127962;</div><p>No tenants yet. Add your first tenant to get started.</p>' + btn('Add tenant', 'openAddModal()', { primary: true, icon: 'plus' }) + '</div>'; return; }
  const list = tenantsForList();
  const head = '<div class="oa-thead tn-row" role="row"><span>Tenant</span><span>Unit</span><span class="tn-billing">Billing</span><span>Paid through · last 6 cycles</span><span>Status</span><span class="r">Balance</span><span></span></div>';
  const legend = '<span class="oa-cy-legend"><span><i class="q-paid"></i>Paid</span><span><i class="q-ahead"></i>Ahead</span><span><i class="q-due"></i>Due</span><span><i class="q-late"></i>Late</span><span><i class="q-waived"></i>Waived</span></span>';
  const arch = archivedTenants.length;
  const foot = '<div class="oa-card-foot"><span class="tn-foot-left"><span>Showing ' + list.length + ' of ' + tenants.length + '</span>' + legend + '</span>'
    + (arch ? '<button type="button" class="link-btn" onclick="openArchivedSection()">Archived tenants (' + arch + ')</button>' : '<button type="button" class="link-btn" onclick="openArchivedSection()">Archived tenants</button>') + '</div>';
  if(!list.length) {
    c.innerHTML = '<div class="oa-empty tn-empty">No tenants match. Try another filter or search. <button type="button" class="link-btn" onclick="tSearch=\'\';tFloor=\'\';tStatus=\'\';rerenderAdmin()">Clear filters</button></div>' + foot;
    return;
  }
  // Grouping: floor headers (auto when floor labels exist and the list is
  // unit/floor-sorted), or one header per unit for shared per-head units.
  let keyOf = null, labelOf = null, rankOf = null;
  if(groupMode === 'floor' || (groupMode === 'auto' && ['unit-asc', 'unit-desc', 'floor-asc'].includes(sortOrder) && list.some(t => floorKey(t)))) {
    const canon = appFloorCanon();
    keyOf = t => canon(t.floor); labelOf = k => k ? esc(k) : 'Unassigned'; rankOf = floorRank;
  } else if(groupMode === 'unit') {
    keyOf = t => (t.unit || '').trim(); labelOf = k => k ? 'Unit ' + esc(k) : 'No unit'; rankOf = unitRank;
  }
  let body;
  if(!keyOf) body = list.map(tenantRowHtml).join('');
  else {
    const keys = [], map = {};
    list.forEach(t => { const k = keyOf(t); if(!(k in map)) { map[k] = []; keys.push(k); } map[k].push(t); });
    keys.sort((a, b) => { if(!a) return 1; if(!b) return -1; const r = rankOf(a) - rankOf(b); return (sortOrder === 'unit-desc' ? -r : r) || a.localeCompare(b); });
    body = keys.map(k => {
      const g = map[k];
      const out = g.reduce((s, t) => s + tenantBalance(t), 0);
      const aw = g.reduce((s, t) => s + tenantSummary(t).awaiting, 0);
      const allInc = groupMode === 'unit' && g.every(t => t.billing_model === 'inclusive');
      return '<div class="oa-group"><span class="oa-group-name">' + labelOf(k) + '</span><span class="oa-group-meta">' + g.length + ' tenant' + (g.length !== 1 ? 's' : '')
        + (allInc ? ' · all-inclusive' : '') + ' · ' + (out ? peso(out) + ' owed' : aw ? '' : 'nothing owed')
        + (aw ? (out ? ' · ' : '') + aw + ' bill' + (aw !== 1 ? 's need' : ' needs') + ' an amount' : '') + '</span></div>'
        + g.map(tenantRowHtml).join('');
    }).join('');
  }
  c.innerHTML = '<div class="oa-table">' + head + body + '</div>' + foot;
}

function openTenantMenu(anchor, tid) {
  const t = tenants.find(x => x.id === tid);
  if(!t) return;
  const items = [
    { label:'Receive payment', icon:'cash', fn:()=>openPayModal(tid) },
    { label:'Add bill', icon:'plus', fn:()=>openQuickBill(tid) },
    { label:'Statement of account', icon:'print', fn:()=>openStmtModalById(tid) }
  ];
  if(tenantSummary(t).open > 0) items.push({ label:'Copy payment reminder', icon:'mail', fn:()=>copyReminder(tid) });
  items.push(
    { label:'Copy portal link', icon:'link', fn:()=>copyPortalLink(tid) },
    { label:'Edit details', icon:'edit', fn:()=>openEditModal(tid) },
    { label:'Archive tenant', icon:'archive', danger:true, fn:()=>deleteTenant(tid) }
  );
  openMenu(anchor, items, t.name);
}

// ── Tenant detail ──
let tdBillTab = 'open'; // Bills card: 'open' | 'paid' | 'all'
function _ordinal(n) { const s = ['th', 'st', 'nd', 'rd'], v = n % 100; return n + (s[(v - 20) % 10] || s[v] || s[0]); }
function renderTenantDetail(t) {
  const s = tenantSummary(t);
  const tidA = ' data-tid="' + esc(t.id) + '"';
  const inclusive = t.billing_model === 'inclusive';
  const mi = moveInOf(t);
  const p = s.primary;
  const sub = ['Unit ' + esc(t.unit), floorKey(t) ? esc(t.floor) : '', mi ? 'tenant since ' + new Date(mi + 'T00:00:00').toLocaleDateString('en-PH', { month: 'long', year: 'numeric' }) : ''].filter(Boolean).join(' · ');

  // Summary: balance + actions, then four stats.
  const rate = tenantRate(t);
  const rel = paymentReliability([t], addYM(_currentYM(), -11), _currentYM(), todayISO(), graceDays)[0];
  const stat = (label, value, note) => '<div class="td-stat"><span class="td-stat-label">' + label + '</span><strong>' + value + '</strong><span class="td-stat-note">' + note + '</span></div>';
  const openNote = s.overdueCount ? s.overdueCount + ' overdue' + (s.nextDue ? ' · next due ' + shortDate(s.nextDue) : '')
    : s.nextDue ? 'Next due ' + shortDate(s.nextDue) : s.awaiting ? s.awaiting + ' need' + (s.awaiting === 1 ? 's' : '') + ' an amount' : 'Nothing open';
  const summary = '<section class="card td-summary"' + tidA + '>'
    + '<div class="td-sum-top"><div class="td-bal">' + avatar(t.name, 60)
    +   '<div class="td-bal-fig"><span>Balance</span><strong' + (s.overdue > 0 ? ' class="bad"' : '') + '>' + peso(s.open) + '</strong></div>' + tenantPill(t) + '</div>'
    +   '<div class="td-actions">'
    +     btn('Receive payment', 'openPayModal(this.closest(\'[data-tid]\').dataset.tid)', { primary: true, icon: 'cash' })
    +     btn('Add bill', 'openQuickBill(this.closest(\'[data-tid]\').dataset.tid)', { icon: 'plus' })
    +     btn('Statement', 'openStmtModalById(this.closest(\'[data-tid]\').dataset.tid)', { icon: 'print' })
    +     '<button type="button" class="oa-icon-btn lg" aria-label="More actions for ' + esc(t.name) + '" aria-haspopup="menu" onclick="openTenantMenu(this,this.closest(\'[data-tid]\').dataset.tid)">' + icon('kebab') + '</button>'
    +   '</div></div>'
    + '<div class="td-stats">'
    +   stat(inclusive ? 'Monthly rate' : 'Rent', rate ? peso(rate) + ' / month' : '&mdash;', inclusive ? 'Utilities included' : rate ? 'Itemized utilities' : 'No recurring rent')
    +   stat('Paid through', p && !p.variable ? (p.paidThrough ? medDate(p.paidThrough) : 'Not yet') : '&mdash;',
          mi ? 'Cycle starts on the ' + _ordinal(Number(mi.slice(8, 10))) : 'Set a move-in date')
    +   stat('Open bills', s.openCount ? s.openCount + ' · ' + peso(s.open) : 'None', openNote)
    +   stat('On-time payments', rel ? (rel.n - rel.late) + ' of ' + rel.n : '&mdash;', rel ? 'Last 12 months' : 'No bills due yet')
    + '</div></section>';

  // Bills: Open / Paid / All.
  const all = t.bills.map((b, bi) => ({ b, bi }));
  const isOpenB = x => billOpen(x.b) > 0.005 || billAwaitingAmount(x.b);
  const lists = {
    open: all.filter(isOpenB).sort((a, b) => getDueUrgencyScore(a.b) - getDueUrgencyScore(b.b)),
    paid: all.filter(x => !isOpenB(x)).sort((a, b) => (b.b.due || '').localeCompare(a.b.due || '')),
    all: all.slice().sort((a, b) => (b.b.due || '').localeCompare(a.b.due || ''))
  };
  if(!lists[tdBillTab]) tdBillTab = 'open';
  const list = lists[tdBillTab], shown = list.slice(0, 12);
  const tabs = segTabs([['open', 'Open'], ['paid', 'Paid'], ['all', 'All']].map(([k, l]) => ({ label: l, count: lists[k].length, active: tdBillTab === k, onclick: 'tdBillTab=\'' + k + '\';rerenderAdmin()' })), 'sm', 'Which bills');
  const billSub = b => {
    const bits = [];
    const per = billPeriod(b);
    if(mi && per && p && b.tmplId === p.tmplId) { const w = cycleWindow(mi, per); bits.push(shortDate(w.start) + ' – ' + shortDate(addDaysISO(w.end, -1))); }
    else if(per) bits.push('For ' + fmtYM(per, 'short'));
    const got = billTotalPaid(b);
    if(b.status !== 'paid' && got > 0.005) bits.push(peso(got) + ' received');
    if(b.remark) bits.push(esc(b.remark));
    return bits.join(' · ');
  };
  const billRow = x => {
    const b = x.b, aw = billAwaitingAmount(b);
    return '<div class="oa-tr td-bill' + (aw ? ' is-awaiting' : '') + '"' + tidA + ' data-bi="' + x.bi + '">'
      + '<div class="td-bill-main"><span class="td-bill-label">' + esc(b.label || 'Bill') + '</span>' + (billSub(b) ? '<span class="oa-sub">' + billSub(b) + '</span>' : '') + '</div>'
      + '<span class="oa-cell-due">' + (b.due ? shortDate(b.due) : '&mdash;') + '</span>'
      + '<span class="oa-cell-status">' + billPill(b, !!_justPaidEntry(t.id, x.bi)) + '</span>'
      + '<span class="oa-cell-amt">' + (aw ? '<button type="button" class="link-btn" onclick="const r=this.closest(\'[data-tid]\');openEditBillFromTable(r.dataset.tid,+r.dataset.bi)">Enter amount</button>' : peso(b.amount)) + '</span>'
      + '<span class="oa-cell-due td-paidon">' + (b.status === 'paid' && b.paidDate ? shortDate(b.paidDate) : '&mdash;') + '</span>'
      + '<button type="button" class="oa-icon-btn ghost sm" aria-label="Actions for ' + esc(b.label || 'bill') + '" aria-haspopup="menu" onclick="const r=this.closest(\'[data-tid]\');openBillMenu(this,r.dataset.tid,+r.dataset.bi)">' + icon('kebab') + '</button>'
      + '</div>';
  };
  const billsCard = '<section class="card oa-table-card td-bills">'
    + '<div class="oa-card-head"><h2 class="card-title">Bills</h2>' + tabs + '</div>'
    + (shown.length ? '<div class="oa-table"><div class="oa-thead td-bill" role="row"><span>Bill</span><span>Due</span><span>Status</span><span class="r">Amount</span><span class="td-paidon">Paid on</span><span></span></div>' + shown.map(billRow).join('') + '</div>'
        : '<div class="oa-empty">' + icon('check') + ' ' + ({ open: 'No open bills.', paid: 'No paid bills yet.' }[tdBillTab] || 'No bills yet.') + '</div>')
    + '<div class="oa-card-foot"><span>' + (list.length > shown.length ? 'Showing ' + shown.length + ' of ' + list.length : list.length + ' bill' + (list.length !== 1 ? 's' : '')) + '</span>'
    +   '<button type="button" class="link-btn oa-more"' + tidA + ' onclick="openEditModal(this.dataset.tid,\'bills\')">Manage bills' + icon('next') + '</button></div>'
    + '</section>';

  // Payments received: every receipt, newest first (Undo for a Receive-payment receipt).
  const receipts = tenantReceipts(t);
  const appliedTo = receiptAppliedTo;
  const payRow = x => '<div class="oa-tr td-pay">'
    + '<span class="oa-cell-due">' + (x.dates && x.dates.size > 1 ? Array.from(x.dates).filter(Boolean).sort().map(d => shortDate(d)).join(', ') : x.date ? shortDateY(x.date) : 'No date') + '</span>'
    + '<span class="td-pay-note">' + (x.note ? esc(x.note) : '<span class="oa-muted-sm">&mdash;</span>')
    +   (x.rid ? ' <button type="button" class="link-btn inline"' + tidA + ' data-rid="' + esc(x.rid) + '" onclick="undoPayment(this.dataset.tid,this.dataset.rid)">Undo</button>' : '') + '</span>'
    + '<span class="oa-cell-bill td-applied">' + appliedTo(x) + '</span>'
    + '<span class="oa-cell-amt">' + (x.amount < 0 ? '&minus;' + peso(-x.amount) : peso(x.amount)) + '</span></div>';
  const payCard = '<section class="card oa-table-card td-pays">'
    + '<div class="oa-card-head"><h2 class="card-title">Payments</h2><span class="oa-muted-sm">Applied to the oldest bills first</span></div>'
    + (receipts.length ? '<div class="oa-table"><div class="oa-thead td-pay" role="row"><span>Date</span><span>Note</span><span>Applied to</span><span class="r">Amount</span></div>' + receipts.slice(0, 8).map(payRow).join('') + '</div>'
        : '<div class="oa-empty">No payments recorded yet.</div>')
    + (receipts.length > 8 ? '<div class="oa-card-foot"><span>Showing 8 of ' + receipts.length + '</span><button type="button" class="link-btn oa-more"' + tidA + ' onclick="openEditModal(this.dataset.tid,\'bills\')">All bills &amp; payments' + icon('next') + '</button></div>' : '')
    + '</section>';

  // Details.
  const recurring = (t.templates || []).map((tmpl, i) => {
    if(tmpl.retired) return '<div class="td-rec"><span>' + esc(tmpl.label) + ' <span class="oa-muted-sm">· stopped</span></span></div>';
    const auto = isAutoTemplate(tmpl);
    const np = auto && autoBilling.enabled ? nextPostInfo(t, tmpl) : null;
    return '<div class="td-rec"><div class="td-rec-text"><span>' + esc(tmpl.label) + ' ' + (tmpl.pendingAmount ? '(amount varies)' : peso(tmpl.amount)) + ', monthly · due day ' + tmplDay(tmpl) + '</span>'
      + '<span class="td-rec-note' + (auto && autoBilling.enabled ? ' good' : '') + '">' + (!auto ? 'Manual — post from Billing' : !autoBilling.enabled ? 'Automatic billing is off in Settings'
        : 'Auto-posts ' + autoBilling.leadDays + ' day' + (autoBilling.leadDays !== 1 ? 's' : '') + ' before due' + (np ? ' · next ' + (np.post === todayISO() ? 'today' : shortDate(np.post)) : ''))
      + (Array.isArray(tmpl.skip) && tmpl.skip.length ? ' · <button type="button" class="link-btn inline"' + tidA + ' data-tmpl="' + esc(tmpl.id || '') + '" aria-haspopup="menu" onclick="unwaiveMenu(this)">' + tmpl.skip.length + ' waived</button>' : '') + '</span></div>'
      + '<label class="switch" title="Post automatically each cycle"><input type="checkbox"' + (auto ? ' checked' : '') + tidA + ' data-i="' + i + '" onchange="toggleTemplateAuto(this.dataset.tid,+this.dataset.i,this.checked)"><span class="switch-ui"></span><span class="sr-only">Auto-post ' + esc(tmpl.label) + '</span></label></div>';
  }).join('');
  const dl = (k, v) => '<div class="td-dl"><span class="td-dt">' + k + '</span><div class="td-dd">' + v + '</div></div>';
  const details = '<section class="card td-details"><div class="td-card-head"><h2 class="card-title">Details</h2>'
    + '<button type="button" class="link-btn"' + tidA + ' onclick="openEditModal(this.dataset.tid)">Edit</button></div>'
    + dl('Access code', '<span class="td-code">' + esc(t.code) + '</span><button type="button" class="link-btn"' + tidA + ' onclick="copyPortalLink(this.dataset.tid);this.textContent=\'Link copied\'">Copy portal link</button>')
    + dl('Move-in date', mi ? medDate(mi) + ' <span class="oa-muted-sm">· billing date</span>' : '<span class="oa-muted-sm">Not set</span> <button type="button" class="link-btn inline"' + tidA + ' onclick="openEditModal(this.dataset.tid)">Set it</button>')
    + dl('Recurring', recurring ? recurring + '<button type="button" class="link-btn inline"' + tidA + ' onclick="openEditModal(this.dataset.tid,\'templates\')">Manage charges</button>'
        : '<span class="oa-muted-sm">None — bills are added by hand.</span> <button type="button" class="link-btn inline"' + tidA + ' onclick="openEditModal(this.dataset.tid,\'templates\')">Add</button>')
    + (t.phone ? dl('Phone', '<a href="tel:' + esc(t.phone) + '">' + esc(t.phone) + '</a>') : '')
    + (t.email ? dl('Email', '<a href="mailto:' + esc(t.email) + '">' + esc(t.email) + '</a>') : '')
    + '</section>';

  return pageHead(esc(t.name), sub, '', { label: 'Tenants', onclick: 'go(\'tenants\')' })
    + summary
    + '<div class="td-grid"><div class="td-col">' + billsCard + payCard + '</div>'
    + '<div class="td-col">' + rentCyclesCard(t, s) + details + '</div></div>';
}

// Rent cycles: the main rent's last 12 cycles, plus anything the
// reconciliation checker wants fixed (unbilled cycles, unapplied credit).
function rentCyclesCard(t, s) {
  const tidA = ' data-tid="' + esc(t.id) + '"';
  const head = '<div class="td-card-head"><h2 class="card-title">Rent cycles</h2><span class="oa-muted-sm">Last 12 months</span></div>';
  if(!s.recon.enabled) {
    const allStopped = (t.templates || []).some(x => x && x.retired) && !activeTemplates(t).length;
    const msg = allStopped ? 'All recurring charges are stopped. Resume one under Manage charges to bill this tenant again.'
      : s.recon.reason === 'no-templates' ? 'No recurring charges yet. Add a monthly rent and bills will post automatically each cycle.'
      : 'Set a move-in date to see rent cycles and a paid-through date. Nothing changes until you do — recurring bills keep posting on their due dates.';
    const action = allStopped || s.recon.reason === 'no-templates' ? btn(allStopped ? 'Manage charges' : 'Add recurring charge', 'openEditModal(this.dataset.tid,\'templates\')', { icon: 'repeat', attrs: tidA })
      : btn('Set move-in date', 'openEditModal(this.dataset.tid)', { icon: 'calendar', attrs: tidA });
    return '<section class="card td-cycles">' + head + '<p class="card-text">' + msg + '</p>' + action + '</section>';
  }
  const cy = rentCycles(t, 12);
  const grid = cy.length ? '<div class="td-cy-grid">' + cy.map(x => '<div class="td-cy" title="' + esc(x.title) + '"><i class="q-' + x.st + '"></i><span>' + _monthName(x.ym, 'short') + '</span></div>').join('') + '</div>'
    : '<p class="card-text muted">' + (s.primary ? 'No rent cycle has started yet.' : 'No fixed monthly rent — other recurring charges are listed below.') + '</p>';
  const issues = [];
  s.recon.charges.forEach(c => {
    const a = tidA + ' data-tmpl="' + esc(c.tmplId) + '"';
    const who = s.recon.charges.length > 1 ? esc(c.label) + ': ' : '';
    // Every charge other than the rent in the squares gets a status line.
    if(c.tmplId !== (s.primary && s.primary.tmplId)) {
      const pt = c.paidThrough ? ' · paid through ' + shortDateY(c.paidThrough) : '';
      const line = c.status === 'variable' || c.variable ? 'Amount varies · cycle check only'
        : c.status === 'behind' ? 'Behind ' + peso(c.arrears) + pt
        : c.status === 'advance' ? c.aheadCycles + ' cycle' + (c.aheadCycles !== 1 ? 's' : '') + ' ahead' + pt
        : 'Current' + pt;
      issues.push('<div class="td-issue' + (c.status === 'behind' ? ' bad' : ' muted') + '">' + icon(c.status === 'behind' ? 'alert' : 'repeat') + '<span>' + esc(c.label) + ' · ' + line + '</span></div>');
    }
    if(c.missing.length) issues.push('<div class="td-issue">' + icon('alert') + '<span>' + who + c.missing.length + ' cycle' + (c.missing.length !== 1 ? 's' : '') + ' not billed: '
      + c.missing.slice(0, 4).map(m => fmtYM(m.period, 'short')).join(', ') + (c.missing.length > 4 ? ' +' + (c.missing.length - 4) + ' more' : '') + '</span>'
      + '<span class="td-issue-actions"><button type="button" class="btn-mini"' + a + ' aria-haspopup="menu" onclick="reconMenu(this,\'post\')">Post bills</button>'
      + '<button type="button" class="btn-mini ghost"' + a + ' aria-haspopup="menu" onclick="reconMenu(this,\'waive\')">Waive</button></span></div>');
    if(c.excess > 0.005) issues.push(_creditApplicable(t, c)
      ? '<div class="td-issue">' + icon('cash') + '<span>' + who + peso(c.excess) + ' overpaid on earlier bills, not yet applied</span><span class="td-issue-actions"><button type="button" class="btn-mini"' + a + ' onclick="reconApplyCredit(this.dataset.tid,this.dataset.tmpl)">Apply credit</button></span></div>'
      : '<div class="td-issue muted">' + icon('cash') + '<span>' + who + peso(c.excess) + ' overpaid — kept as credit until there is an open bill to apply it to</span></div>');
    if(c.ignored) issues.push('<div class="td-issue muted">' + icon('alert') + '<span>' + who + c.ignored + ' bill' + (c.ignored !== 1 ? 's' : '') + ' dated before ' + (c.startYM && c.startYM > ymOf(c.moveIn) ? fmtYM(c.startYM) : 'the move-in month')
      + ' or without a date ' + (c.ignored !== 1 ? 'are' : 'is') + ' not counted' + (c.ignoredCash ? ' (' + peso(c.ignoredCash) + ' paid)' : '') + '.</span></div>');
  });
  return '<section class="card td-cycles">' + head + grid
    + (issues.length ? '<div class="td-issues">' + issues.join('') + '</div>' : '')
    + '<div class="oa-cy-legend td-cy-legend"><span><i class="q-paid"></i>Paid</span><span><i class="q-ahead"></i>Ahead</span><span><i class="q-due"></i>Due</span><span><i class="q-late"></i>Late</span>' + (cy.some(x => x.st === 'waived') ? '<span><i class="q-waived"></i>Waived</span>' : '') + '</div>'
    + '</section>';
}



// Next auto-post for a template: which cycle, its due date, when it posts.
// Simulates the real planner day by day, so the hint can never promise a
// post the planner wouldn't make.
function nextPostInfo(t, tmpl) {
  if(!tmpl || !isAutoTemplate(tmpl) || !tmpl.id) return null;
  const probe = Object.assign({}, t, { templates: [tmpl] });
  const today = todayISO();
  for(let d = 0; d <= 62; d++) {
    const day = addDaysISO(today, d);
    const plan = planAutoPost(probe, { today: day, leadDays: autoBilling.leadDays });
    if(plan.bills.length) return { ym: plan.bills[0].period, due: plan.bills[0].due, post: day };
  }
  return null;
}


async function toggleTemplateAuto(tid, i, on) {
  const ok = await saveTenantData(tid, t => {
    const templates = structuredClone(t.templates || []);
    if(!templates[i]) return null;
    templates[i].auto = !!on;
    return { templates };
  }, on ? 'Auto-post on.' : 'Auto-post off — post this charge from Billing.');
  if(ok && on) await runAutoBilling({ only: tid });
  rerenderAdmin();
}

// Save computed bills/templates for one tenant with the optimistic-
// concurrency guard. `compute(t)` returns {bills?, templates?} or null.
async function saveTenantData(tid, compute, toastMsg) {
  await _autoBillIdle();
  return _withTenantLock(tid, async () => {
    const t = tenants.find(x => x.id === tid);
    if(!t) return false;
    const res = compute(t);
    if(!res) return false;
    const patch = {};
    if(res.bills) patch.bills = res.bills;
    if(res.templates) patch.templates = res.templates;
    if(!Object.keys(patch).length) return false;
    try {
      await dbUpdateTenantGuarded(t, patch);
      Object.assign(t, patch);
      if(toastMsg) showToast(toastMsg);
      return true;
    } catch(e) {
      showToast(e.conflict ? e.message : 'Save failed: ' + e.message, false);
      if(e.conflict) rerenderAdmin();
      return false;
    }
  });
}

// One write at a time per tenant: a second quick action (a double-clicked
// Undo, a repeated inline edit) starts from the first one's saved rev and
// bills instead of failing the rev guard.
const _tenantWriteQ = new Map();
function _withTenantLock(tid, fn) {
  const prev = _tenantWriteQ.get(tid) || Promise.resolve();
  const p = prev.catch(() => {}).then(fn);
  _tenantWriteQ.set(tid, p);
  p.finally(() => { if(_tenantWriteQ.get(tid) === p) _tenantWriteQ.delete(tid); }).catch(() => {});
  return p;
}

// Can this charge's overpayment go anywhere right now (an open bill, or
// future cycles of the primary rent)? Dry run — nothing is saved.
function _creditApplicable(t, c) {
  if(!(c.excess > 0.005)) return false;
  const res = applyCredit(t, c.tmplId, { today: todayISO(), uid });
  return !!(res && res.movedTotal > 0.005);
}

// ── Reconciliation fixes ──
// Post or waive missing cycles: all of them, or one month at a time.
function reconMenu(anchor, kind) {
  const tid = anchor.dataset.tid, tmplId = anchor.dataset.tmpl;
  const t = tenants.find(x => x.id === tid);
  const c = t && tenantSummary(t).recon.charges.find(x => x.tmplId === tmplId);
  if(!c || !c.missing.length) return;
  const fn = kind === 'post' ? reconPostMissing : reconWaive;
  const periods = c.missing.map(m => m.period);
  const items = [];
  if(periods.length > 1) items.push({ label: (kind === 'post' ? 'Post all ' : 'Waive all ') + periods.length + ' cycles', icon: kind === 'post' ? 'plus' : 'check', fn: () => fn(tid, tmplId, periods) });
  periods.slice(0, 24).forEach(p => items.push({ label: (kind === 'post' ? 'Post ' : 'Waive ') + fmtYM(p), fn: () => fn(tid, tmplId, [p]) }));
  openMenu(anchor, items, (kind === 'post' ? 'Post' : 'Waive') + ' · ' + c.label);
}
async function reconPostMissing(tid, tmplId, periods) {
  const t = tenants.find(x => x.id === tid);
  if(!t) return;
  const c = tenantSummary(t).recon.charges.find(x => x.tmplId === tmplId);
  const list = c ? c.missing.filter(m => !periods || periods.includes(m.period)) : [];
  if(!list.length) return;
  const total = r2(list.reduce((s, m) => s + m.amount, 0));
  // Hand-typed bills in those months may already be this charge under
  // another name — show them so nothing is billed twice.
  const live = new Set((t.templates || []).map(x => x && x.id).filter(Boolean));
  const others = list.map(m => ({ m, bills: (t.bills || []).filter(b => b && billPeriod(b) === m.period && !(b.tmplId && live.has(b.tmplId))) }))
    .filter(x => x.bills.length);
  const warn = others.length ? '\n\n⚠ These months already have other bills — make sure they are not this charge under another name:\n'
    + others.slice(0, 12).map(x => '• ' + fmtYM(x.m.period) + ': ' + x.bills.map(b => '"' + b.label + '" ₱' + fmtMoney(b.amount)).join(', ')).join('\n')
    + (others.length > 12 ? '\n• …and ' + (others.length - 12) + ' more month' + (others.length - 12 !== 1 ? 's' : '') : '') : '';
  if(!confirm('Post ' + list.length + ' "' + c.label + '" bill' + (list.length !== 1 ? 's' : '') + ' for ' + t.name + '?\n\n' + list.map(m => '• ' + fmtYM(m.period) + ' — due ' + formatDate(m.due) + ' · ₱' + fmtMoney(m.amount)).join('\n')
    + (total ? '\n\nTotal: ₱' + fmtMoney(total) : '') + warn + '\n\nThey post as unpaid with your template due dates.')) return;
  const ok = await saveTenantData(tid, x => backfillCycles(x, tmplId, list.map(m => m.period)), 'Bills posted.');
  if(ok) rerenderAdmin();
}
async function reconWaive(tid, tmplId, periods) {
  const t = tenants.find(x => x.id === tid);
  if(!t) return;
  const c = tenantSummary(t).recon.charges.find(x => x.tmplId === tmplId);
  const list = c ? c.missing.map(m => m.period).filter(p => !periods || periods.includes(p)) : [];
  if(!list.length) return;
  if(!confirm('Waive ' + list.length + ' "' + c.label + '" cycle' + (list.length !== 1 ? 's' : '') + ' (' + list.map(p => fmtYM(p, 'short')).join(', ')
    + ')?\n\nA waived cycle is free — no bill, nothing owed — and is never posted automatically. You can undo a waiver under Details › Recurring on the tenant page.')) return;
  const ok = await saveTenantData(tid, x => waiveCycles(x, tmplId, list), 'Cycle' + (list.length !== 1 ? 's' : '') + ' waived.');
  if(ok) rerenderAdmin();
}
// Undo a waiver (a free month, or a deleted recurring bill's cycle).
function unwaiveMenu(anchor) {
  const tid = anchor.dataset.tid, tmplId = anchor.dataset.tmpl;
  const t = tenants.find(x => x.id === tid);
  const tm = t && (t.templates || []).find(x => x.id === tmplId);
  const skip = tm && Array.isArray(tm.skip) ? tm.skip.filter(isYM).slice().sort().reverse() : [];
  if(!skip.length) return;
  openMenu(anchor, skip.slice(0, 24).map(p => ({ label: 'Undo waiver · ' + fmtYM(p), icon: 'undo', fn: () => unwaiveCycle(tid, tmplId, p) })), 'Waived cycles · ' + tm.label);
}
async function unwaiveCycle(tid, tmplId, period) {
  const t0 = tenants.find(x => x.id === tid);
  const tm0 = t0 && (t0.templates || []).find(x => x.id === tmplId);
  if(!tm0) return;
  // Its posting window may already be open (or past): offer to post it now.
  const due = templateDueDate(t0, tm0, period);
  const open = diffDays(todayISO(), due) <= autoBilling.leadDays;
  const postNow = open && !templateBillExists(t0, tm0, period)
    && confirm('Undo the waiver for ' + fmtYM(period) + '.\n\nPost its "' + tm0.label + '" bill now (due ' + formatDate(due) + ')?\nOK: post it now. Cancel: only undo the waiver (it posts automatically if still in its posting window).');
  const ok = await saveTenantData(tid, t => {
    let templates = structuredClone(t.templates || []);
    const tm = templates.find(x => x.id === tmplId);
    if(!tm || !Array.isArray(tm.skip)) return null;
    tm.skip = tm.skip.filter(p => p !== period);
    // Automatic posting resumes from the un-waived cycle.
    if(isYM(tm.postedThrough) && period <= tm.postedThrough) tm.postedThrough = addYM(period, -1);
    let bills = null;
    if(postNow) {
      const r = backfillCycles({ ...t, templates }, tmplId, [period]);
      if(r) { bills = r.bills; templates = r.templates; }
    } else bumpPostedThrough({ ...t, templates }, tm);
    return bills ? { bills, templates } : { templates };
  }, postNow ? fmtYM(period) + ' is no longer waived — its bill is posted.' : fmtYM(period) + ' is no longer waived.');
  if(ok) rerenderAdmin();
}
async function reconApplyCredit(tid, tmplId) {
  const t = tenants.find(x => x.id === tid);
  if(!t) return;
  const c = tenantSummary(t).recon.charges.find(x => x.tmplId === tmplId);
  // Credit is consumed forward, cycle by cycle — so cycles that were never
  // billed are posted first; otherwise the money would skip over them.
  const missing = c ? c.missing.map(m => m.period) : [];
  const pre = missing.length ? backfillCycles(t, tmplId, missing) : null;
  const base = pre ? Object.assign({}, t, { bills: pre.bills, templates: pre.templates }) : t;
  const res = applyCredit(base, tmplId, { today: todayISO(), uid });
  if(!res || res.movedTotal <= 0.005) { showToast('There is no credit that can be applied right now.', false); return; }
  const lines = res.lines.map(l => '• ' + l.label + (l.period ? ' (' + fmtYM(l.period, 'short') + ')' : '') + ' — ₱' + l.apply.toLocaleString() + (l.kind === 'advance' ? ' advance' : '') + (l.settles ? ', settled' : '')).join('\n');
  const preNote = pre && pre.added.length ? 'First posts ' + pre.added.length + ' missing bill' + (pre.added.length !== 1 ? 's' : '') + ' (' + pre.added.map(b => fmtYM(b.period, 'short')).join(', ') + '), then applies:\n' : '';
  if(!confirm('Apply ₱' + res.movedTotal.toLocaleString() + ' of credit for ' + t.name + '?\n\n' + preNote + lines + '\n\nPayment dates stay the same, so cash reports don\'t change.')) return;
  const ok = await saveTenantData(tid, () => ({ bills: res.bills, templates: res.templates }), 'Credit applied.');
  if(ok) rerenderAdmin();
}

// ─────────────────────────────────────────────
// BILLING MODULE
// ─────────────────────────────────────────────
const BILL_VIEWS = { open:'Open', overdue:'Overdue', soon:'Due soon', awaiting:'Needs amount', paid:'Paid', all:'All' };
let billView = 'open';
let _billingTab = 'bills'; // 'bills' | 'recurring'
let billSelection = new Map(); // selected bills: 'tid|bi' → the bill object
let _billFiltersOpen = false;

function renderBillingModule() {
  if(_billingTab === 'recurring') {
    return pageHead('Recurring billing', 'Automatic posting and the reconciliation checker', btn('Run now', 'runAutoBilling({manual:true})', { icon: 'repeat' }), { label: 'Billing', onclick: 'go(\'billing\')' })
      + renderRecurringTab();
  }
  const today = todayISO(), ym = _currentYM();
  let open = 0, openN = 0, overdue = 0, overdueN = 0, formerOver = 0, soon = 0, soonN = 0, graceN = 0, firstSoon = '';
  const tally = (t, former) => (t.bills || []).forEach(b => {
    const o = billOpen(b);
    if(o <= 0.005 || billAwaitingAmount(b)) return;
    open += o; openN++;
    const ds = getDueStatus(b);
    if(ds === 'overdue') { overdue += o; overdueN++; if(former) formerOver += o; }
    else if(_billDueSoon(b, ds, today)) {
      soon += o; soonN++;
      if(ds === 'grace') graceN++;
      else if(!firstSoon || b.due < firstSoon) firstSoon = b.due;
    }
  });
  tenants.forEach(t => tally(t, false));
  archivedTenants.forEach(t => tally(t, true));
  const cat = outstandingByCategory(allTenants().flatMap(t => t.bills || []));
  const all = allTenants();
  // Rent and other charges only: utility pass-through is neither income
  // nor in the billed total, so mixing it in reads over 100%.
  const collected = r2(cashInMonth(all, ym)), billed = r2(billedInMonth(all, ym)), utilCash = r2(cashInMonth(all, ym, true));
  const pct = billed > 0 ? Math.round(collected / billed * 100) : null;
  const over = billed > 0 && collected > billed + 0.005;
  const collSub = pct === null ? 'nothing billed yet' : over ? peso(billed) + ' billed · includes older bills or advances' : pct + '% of ' + peso(billed);
  const utilNote = utilCash > 0.005 ? '<span class="oa-stat-sub">+ utilities ' + peso(utilCash) + ' passed through</span>' : '';
  const split = [cat.rent ? 'rent ' + peso(cat.rent) : '', cat.utilities ? 'utilities ' + peso(cat.utilities) : '', cat.other ? 'other ' + peso(cat.other) : ''].filter(Boolean).join(', ');
  const tile = (label, value, sub, cls, onclick) => '<button type="button" class="oa-stat" onclick="' + onclick + '"><span class="oa-stat-label">' + label + '</span><strong class="oa-stat-fig' + (cls ? ' ' + cls : '') + '">' + value + '</strong><span class="oa-stat-sub">' + sub + '</span></button>';
  const tiles = '<div class="oa-stats">'
    + tile('Outstanding', peso(r2(open)), openN + ' bill' + (openN !== 1 ? 's' : '') + (split ? ' · ' + split : ''), '', 'billView=\'open\';rerenderAdmin()')
    + tile('Overdue', overdue ? peso(r2(overdue)) : 'None', overdueN ? overdueN + ' bill' + (overdueN !== 1 ? 's' : '') + (formerOver ? ' · ' + peso(r2(formerOver)) + ' from former tenants' : '') : 'nothing past due', overdue ? 'bad' : 'good', 'billView=\'overdue\';rerenderAdmin()')
    + tile('Due soon', peso(r2(soon)), soonN ? soonN + ' bill' + (soonN !== 1 ? 's' : '') + (firstSoon ? ' · first one ' + (firstSoon === today ? 'today' : shortDate(firstSoon)) : '') + (graceN ? ' · ' + graceN + ' in grace period' : '') : 'nothing due this week', '', 'billView=\'soon\';rerenderAdmin()')
    + '<div class="oa-stat"><span class="oa-stat-label">Collected · ' + _monthName(ym) + '</span><strong class="oa-stat-fig">' + peso(collected) + '</strong>'
    +   '<span class="oa-stat-progress"><span class="oa-meter" role="img" aria-label="' + (pct === null ? 'Nothing billed yet' : pct + '% of billed') + '"><i style="width:' + Math.min(100, pct || 0) + '%"></i></span><span class="oa-stat-sub">' + collSub + '</span></span>' + utilNote + '</div>'
    + '</div>';
  const actions = btn('Add bill', 'openQuickBill()', { icon: 'plus' }) + btn('Receive payment', 'openPayModal()', { primary: true, icon: 'cash' })
    + '<button type="button" class="oa-icon-btn lg" aria-label="More billing actions" aria-haspopup="menu" onclick="openBillingMenu(this)">' + icon('kebab') + '</button>';
  const sub = openN + ' open bill' + (openN !== 1 ? 's' : '') + ' · ' + peso(r2(open)) + ' outstanding';
  return pageHead('Billing', sub) + tiles + renderBillsTab(actions) + _recentPaymentsCard();
}
function openBillingMenu(anchor) {
  openMenu(anchor, [
    { label:'Recurring billing & checker', icon:'repeat', fn:()=>go('billing', 'recurring') },
    { label:'Generate bills for a month', icon:'calendar', fn:()=>openGenModal() },
    { label:'Run automatic billing now', icon:'repeat', fn:()=>runAutoBilling({ manual: true }) },
    { label:'Export bills (CSV)', icon:'download', fn:()=>exportCSV() }
  ], 'Billing');
}

function _billFiltersActive() { return !!(filterTenantId || filterFloor || filterMonth || filterSearch.trim()); }
function clearBillFilters() { filterTenantId = ''; filterFloor = ''; filterMonth = ''; filterSearch = ''; tableRowLimit = 50; rerenderAdmin(); }
// Unfiltered row counts per tab, in one pass (the same tests as billRowsForView).
function _billViewCounts() {
  const today = todayISO(), n = { open: 0, overdue: 0, soon: 0, awaiting: 0 };
  const scan = former => t => (t.bills || []).forEach(b => {
    const ds = getDueStatus(b), isOpen = b.status !== 'paid' && billOpen(b) > 0.005, awaiting = ds === 'awaiting';
    if(former && !isOpen) return;
    if(isOpen || awaiting) n.open++;
    if(awaiting) n.awaiting++;
    if(isOpen && ds === 'overdue') n.overdue++;
    if(isOpen && _billDueSoon(b, ds, today)) n.soon++;
  });
  tenants.forEach(scan(false));
  archivedTenants.forEach(scan(true));
  return n;
}
// "Due soon": in its grace period, or due today through the next 6 days.
function _billDueSoon(b, ds, today) {
  return ds === 'grace' || (!!b.due && diffDays(today, b.due) >= 0 && diffDays(today, b.due) <= 6);
}
function renderBillsTab(actions) {
  const floors = floorList();
  // A filter pointing at a tenant/floor that no longer exists (archived)
  // would silently empty the list while the dropdown reads "All".
  if(filterTenantId && !tenants.some(t => t.id === filterTenantId)) filterTenantId = '';
  if(filterFloor && filterFloor !== '__none__' && !floors.includes(filterFloor)) filterFloor = '';
  const sel = (id, label, opts, onch) => '<select id="' + id + '" class="tb-select" aria-label="' + label + '" onchange="' + onch + '">' + opts + '</select>';
  const tenantOpts = '<option value="">All tenants</option>' + tenants.slice().sort((a, b) => unitRank(a.unit) - unitRank(b.unit) || a.name.localeCompare(b.name))
    .map(t => '<option value="' + esc(t.id) + '"' + (filterTenantId === t.id ? ' selected' : '') + '>' + esc(t.name) + ' · ' + esc(t.unit) + '</option>').join('');
  const floorOpts = '<option value="">All floors</option>' + floors.map(f => '<option value="' + esc(f) + '"' + (filterFloor === f ? ' selected' : '') + '>' + esc(f) + '</option>').join('')
    + (tenants.some(t => !floorKey(t)) ? '<option value="__none__"' + (filterFloor === '__none__' ? ' selected' : '') + '>No floor set</option>' : '');
  const counts = _billViewCounts();
  const views = ['open', 'overdue', 'soon'].concat(counts.awaiting || billView === 'awaiting' ? ['awaiting'] : [], ['paid'], billView === 'all' ? ['all'] : []);
  const tabs = segTabs(views.map(k => ({ label: BILL_VIEWS[k], count: k === 'paid' || k === 'all' ? null : counts[k], active: billView === k,
    onclick: 'billView=\'' + k + '\';tableRowLimit=50;billSelection.clear();rerenderAdmin()' })), 'on-bg bl-tabs', 'Bill status');
  const nF = [filterTenantId, filterFloor, filterMonth].filter(Boolean).length;
  const showF = _billFiltersOpen || nF > 0;
  _postRender.push(renderBillRows);
  return '<div class="oa-toolbar bl-toolbar">' + tabs
    + '<label class="oa-search">' + icon('search') + '<input type="search" id="bill-search" placeholder="Tenant, unit or bill" value="' + esc(filterSearch) + '" oninput="filterSearch=this.value;tableRowLimit=50;renderBillRows()" aria-label="Search bills"></label>'
    + '<button type="button" class="oa-icon-btn lg bl-filter-btn' + (showF ? ' on' : '') + '" aria-expanded="' + showF + '" aria-label="Filters' + (nF ? ' (' + nF + ' on)' : '') + '" title="Month, floor and tenant filters" onclick="_billFiltersOpen=!_billFiltersOpen;rerenderAdmin()">' + icon('sliders') + (nF ? '<span class="oa-dot-n">' + nF + '</span>' : '') + '</button>'
    + '<span class="bl-actions">' + actions + '</span></div>'
    + (showF ? '<div class="oa-toolbar bl-filters">'
      +   sel('fb-month', 'Month', renderMonthOptions(), "if(this.value==='__more__'){_showAllMonths=true;rerenderAdmin();return;}filterMonth=this.value;tableRowLimit=50;renderBillRows()")
      +   (floors.length ? sel('fb-floor', 'Floor', floorOpts, 'filterFloor=this.value;tableRowLimit=50;renderBillRows()') : '')
      +   sel('fb-tenant', 'Tenant', tenantOpts, 'filterTenantId=this.value;tableRowLimit=50;renderBillRows()')
      +   (billView !== 'all' ? '<button type="button" class="link-btn" onclick="billView=\'all\';tableRowLimit=50;billSelection.clear();rerenderAdmin()">Show all bills</button>' : '')
      +   (_billFiltersActive() ? '<button type="button" class="link-btn" onclick="clearBillFilters()">Clear filters</button>' : '')
      + '</div>' : '')
    + '<section class="card oa-table-card bl-card" id="bill-rows"></section>';
}

// Rows for the current view. Former tenants' unpaid bills show (read-only)
// in the open views, since they are still owed.
function billRowsForView(noFilters) {
  const today = todayISO();
  const q = noFilters ? '' : filterSearch.trim().toLowerCase();
  const rows = [];
  const scan = (t, former) => {
    const tHit = q && [t.name, t.unit, t.floor, t.code].some(v => String(v || '').toLowerCase().includes(q));
    (t.bills || []).forEach((b, bi) => {
      const ds = getDueStatus(b), open = billOpen(b);
      const isOpen = b.status !== 'paid' && open > 0.005;
      const awaiting = ds === 'awaiting';
      // Marked paid from this tab a moment ago: stays, with Undo (still
      // subject to the month and search filters).
      const jp = !noFilters && !former && billView !== 'paid' && _justPaidEntry(t.id, bi);
      const keepJp = !!jp && jp.view === billView;
      if(!keepJp) {
        if(billView === 'open' && !isOpen && !awaiting) return;
        if(billView === 'awaiting' && !awaiting) return;
        if(billView === 'overdue' && !(isOpen && ds === 'overdue')) return;
        if(billView === 'soon' && !(isOpen && _billDueSoon(b, ds, today))) return;
        if(billView === 'paid' && ds !== 'paid') return;
        if(former && !isOpen) return;
      }
      // Undated open bills stay visible in every month — they belong to none.
      if(!noFilters && filterMonth && billPeriod(b) !== filterMonth && !(!billPeriod(b) && (isOpen || awaiting || keepJp))) return;
      if(q && !tHit && ![b.label, b.remark].some(v => String(v || '').toLowerCase().includes(q))) return;
      rows.push({ tenant: t, bill: b, bi, ds, open, former });
    });
  };
  let list = tenants;
  if(!noFilters && filterTenantId) list = list.filter(t => t.id === filterTenantId);
  if(!noFilters && filterFloor) { const want = floorNorm(filterFloor === '__none__' ? '' : filterFloor); list = list.filter(t => floorNorm(t.floor) === want); }
  list.forEach(t => scan(t, false));
  if(noFilters || !filterTenantId) {
    let arch = archivedTenants;
    if(!noFilters && filterFloor) { const want = floorNorm(filterFloor === '__none__' ? '' : filterFloor); arch = arch.filter(t => floorNorm(t.floor) === want); }
    arch.forEach(t => scan(t, true));
  }
  return rows;
}

function renderBillRows() {
  const c = document.getElementById('bill-rows');
  if(!c) return;
  if(!tenants.length && !archivedTenants.length) { c.innerHTML = '<div class="empty-state"><p>Add a tenant first — bills belong to tenants.</p>' + btn('Add tenant', 'openAddModal()', { primary: true, icon: 'plus' }) + '</div>'; return; }
  const rows = billRowsForView();
  if(!rows.length) {
    c.innerHTML = '<div class="oa-empty">' + icon('check') + ' ' + (billView === 'open' && !_billFiltersActive() ? 'No open bills — everyone is settled.' : 'No bills match these filters.')
      + (_billFiltersActive() ? ' <button type="button" class="link-btn" onclick="clearBillFilters()">Clear filters</button>' : '') + '</div>';
    return;
  }
  // Keep keyboard focus on the checkbox / sort header that re-rendered.
  const a = document.activeElement;
  const fk = a && c.contains(a) ? (a.dataset.k ? '[data-k="' + CSS.escape(a.dataset.k) + '"]' : a.dataset.col ? '.oa-th[data-col="' + a.dataset.col + '"]'
    : a.closest('.oa-thead') && a.type === 'checkbox' ? '.oa-thead input[type=checkbox]' : '') : '';
  renderTableView(c, rows);
  if(fk) {
    const el = c.querySelector(fk) || c.querySelector('.oa-thead input[type=checkbox]:not([disabled])');
    if(el) { try { el.focus({ preventScroll: true }); } catch {} }
  }
}

function openBillMenu(anchor, tid, bi) {
  const t = tenants.find(x => x.id === tid);
  const b = t && t.bills[bi];
  if(!b) return;
  const items = [];
  if(b.status === 'paid') items.push({ label:'Mark as unpaid', icon:'undo', fn:()=>revertToPending(tid, bi) });
  else items.push({ label:'Mark as paid', icon:'check', fn:()=>quickMarkPaid(tid, bi) });
  items.push(
    { label:'Receive payment…', icon:'cash', fn:()=>openPayModal(tid) },
    { label:'Edit bill', icon:'edit', fn:()=>openEditBillFromTable(tid, bi) },
    { label:'Open tenant', icon:'users', fn:()=>openTenant(tid) }
  );
  if(b.status !== 'paid') items.push({ label:'Copy payment reminder', icon:'mail', fn:()=>copyReminder(tid) });
  items.push({ label:'Delete bill', icon:'trash', danger:true, fn:()=>deleteBillAt(tid, bi) });
  openMenu(anchor, items, b.label + ' — ' + t.name);
}
async function deleteBillAt(tid, bi) {
  const t = tenants.find(x => x.id === tid);
  const b = t && t.bills[bi];
  if(!b) return false;
  const tmpl = _recurringOwner(t, b);
  // A recurring bill for a cycle not yet due (e.g. posted early by a
  // mistaken advance) can go back to posting normally instead of waiving.
  const got = billSettled(b);
  // A bill with money on it goes with its payments (cash reports lose them):
  // say so, and never offer to bill the month again on top.
  const future = !!(tmpl && b.due && b.due > todayISO()) && got <= 0.005;
  if(!confirm('Delete "' + b.label + '" for ' + t.name + '? This cannot be undone.'
    + (got > 0.005 ? '\n\n₱' + fmtMoney(got) + ' was paid on this bill' + (b.paidDate ? ' (' + formatDate(b.paidDate) + ')' : '') + ' — deleting it removes that money from the records too. To reverse a payment recorded by mistake, use Undo under Payments on the tenant page, or Mark as unpaid instead.' : '')
    + (tmpl && !future ? '\n\nThis is a recurring bill. Its cycle (' + fmtYM(billPeriod(b)) + ') is marked as waived so it is never posted again automatically — you can undo the waiver under Details › Recurring on the tenant page.' : ''))) return false;
  let mode = 'waive';
  if(future) mode = confirm('Should ' + fmtYM(billPeriod(b)) + ' still be billed?\n\nOK: yes — it posts again normally ahead of its due date (' + formatDate(b.due) + ').\nCancel: no — waive it (a free month; undo under Details › Recurring).') ? 'repost' : 'waive';
  const ok = await _deleteBill(tid, b, mode);
  if(ok) rerenderAdmin();
  return ok;
}
// The recurring charge a bill was posted from (only template-posted bills
// with a cycle), if that charge still exists.
function _recurringOwner(t, b) {
  if(!b || !b.tmplId || !isYM(b.period)) return null;
  return (t.templates || []).find(x => x && x.id === b.tmplId) || null;
}
// Delete one bill (located by identity, not a possibly-stale index) and,
// for a recurring bill, waive its cycle in the same guarded write.
async function _deleteBill(tid, bill, mode) {
  return saveTenantData(tid, t => {
    const i = t.bills.indexOf(bill);
    if(i < 0) { showToast('That bill changed in the meantime — please try again.', false); return null; }
    const bills = structuredClone(t.bills);
    bills.splice(i, 1);
    const owner = _recurringOwner(t, bill);
    if(!owner) return { bills };
    const templates = structuredClone(t.templates || []);
    const tm = templates.find(x => x.id === owner.id);
    if(mode === 'repost') {
      // Not waived: automatic posting picks the cycle up again when due.
      if(isYM(tm.postedThrough) && bill.period <= tm.postedThrough) tm.postedThrough = addYM(bill.period, -1);
      bumpPostedThrough({ ...t, bills, templates }, tm);
    } else tm.skip = Array.from(new Set((Array.isArray(tm.skip) ? tm.skip : []).concat([bill.period]))).sort();
    return { bills, templates };
  }, mode === 'repost' ? 'Bill deleted — it posts again normally when due.' : 'Bill deleted.');
}

// ── Recurring tab: automatic billing + the reconciliation checker ──
function renderRecurringTab() {
  const rows = tenants.slice().sort((a, b) => unitRank(a.unit) - unitRank(b.unit) || a.name.localeCompare(b.name)).map(t => ({ t, s: tenantSummary(t) }));
  const enabled = rows.filter(r => r.s.recon.enabled);
  const noMoveIn = rows.filter(r => r.s.recon.reason === 'no-move-in');
  const noTmpl = rows.filter(r => r.s.recon.reason === 'no-templates');
  const auto = '<section class="card">'
    + '<div class="card-head"><h2 class="card-title">Automatic billing</h2>' + chip(autoBilling.enabled ? 'good' : 'muted', autoBilling.enabled ? 'On' : 'Off') + '</div>'
    + '<p class="card-text">' + (autoBilling.enabled
        ? 'Each recurring charge posts <strong>' + autoBilling.leadDays + ' day' + (autoBilling.leadDays !== 1 ? 's' : '') + '</strong> before its due date (rent in advance), whenever an admin opens the portal. If nobody opened it during a cycle\'s posting window, an active charge still posts that cycle next time (up to two months back). History from before a charge was active is never created automatically &mdash; the checker below lists it.'
        : 'Recurring bills are not posted automatically. Use <em>Generate bills for a month</em>, or turn automatic billing on in Settings.') + '</p>'
    + (autoBilling.enabled ? '<p class="card-text">' + _autoBillLastLine() + '</p>' : '')
    + '<div class="btn-row">' + btn('Run now', 'runAutoBilling({manual:true})', { icon: 'repeat' }) + btn('Settings', 'go(\'settings\')', { icon: 'sliders' }) + btn('Generate for a month', 'openGenModal()', { icon: 'calendar' }) + '</div>'
    + '</section>';

  const row = r => {
    const t = r.t;
    return r.s.recon.charges.map((c, i) => {
      const a = ' data-tid="' + esc(t.id) + '" data-tmpl="' + esc(c.tmplId) + '"';
      let status;
      if(c.variable) status = chip('muted', 'Variable');
      else if(c.status === 'behind') status = chip('bad', 'Behind ' + peso(c.arrears)) + (c.missing.length ? ' <span class="muted">incl. ' + c.missing.length + ' never billed</span>' : '');
      else if(c.status === 'advance') status = chip('good', c.aheadCycles + ' ahead');
      else status = chip('good', 'Current');
      const acts = [];
      if(c.missing.length) acts.push('<button type="button" class="btn-mini"' + a + ' aria-haspopup="menu" onclick="reconMenu(this,\'post\')">Post ' + c.missing.length + ' missing</button>'
        + '<button type="button" class="btn-mini ghost"' + a + ' aria-haspopup="menu" onclick="reconMenu(this,\'waive\')">Waive</button>');
      if(_creditApplicable(t, c)) acts.push('<button type="button" class="btn-mini"' + a + ' onclick="reconApplyCredit(this.dataset.tid,this.dataset.tmpl)">Apply ' + peso(c.excess) + ' credit</button>');
      else if(c.excess > 0.005) acts.push('<span class="muted">' + peso(c.excess) + ' credit held</span>');
      if(!acts.length && c.status === 'behind') acts.push('<button type="button" class="btn-mini" data-tid="' + esc(t.id) + '" onclick="openPayModal(this.dataset.tid)">' + icon('cash') + '<span>Receive</span></button>');
      return '<div class="rec-row">'
        + '<div class="rec-tenant">' + (i === 0 ? '<a href="#/tenants/' + encodeURIComponent(t.id) + '">' + esc(t.name) + '</a><span class="muted"> · Unit ' + esc(t.unit) + '</span>' : '') + '</div>'
        + '<div class="rec-charge">' + esc(c.label) + (c.variable ? '' : ' <span class="muted">' + peso(c.rate) + '</span>') + '</div>'
        + '<div class="rec-through">' + (c.variable ? '<span class="muted">&mdash;</span>' : c.paidThrough ? 'Paid thru ' + shortDateY(c.paidThrough) : '<span class="muted">' + (c.pool > 0.005 ? 'Partly paid' : 'Nothing paid') + '</span>') + '</div>'
        + '<div class="rec-status">' + status + '</div>'
        + '<div class="rec-actions">' + (acts.join('') || '<span class="muted">' + icon('check') + ' OK</span>') + '</div>'
        + '</div>';
    }).join('');
  };
  const checker = '<section class="card">'
    + '<div class="card-head"><h2 class="card-title">Reconciliation checker</h2><span class="muted">reckoned from each move-in date</span></div>'
    + (enabled.length
        ? '<div class="rec-table"><div class="rec-row rec-head"><div>Tenant</div><div>Charge</div><div>Coverage</div><div>Status</div><div></div></div>' + enabled.map(row).join('') + '</div>'
        : '<div class="empty-inline">No tenant has both a move-in date and a recurring charge yet.</div>')
    + '</section>';
  const listTenants = (arr, cta, fn) => arr.map(r => '<div class="plain-row" data-tid="' + esc(r.t.id) + '"><a href="#/tenants/' + encodeURIComponent(r.t.id) + '">' + esc(r.t.name) + '</a><span class="muted">Unit ' + esc(r.t.unit) + '</span>'
    + '<button type="button" class="btn-mini" onclick="' + fn + '(this.parentNode.dataset.tid' + (fn === 'openEditModal' && cta !== 'Set move-in date' ? ',\'templates\'' : '') + ')">' + cta + '</button></div>').join('');
  const off = (noMoveIn.length || noTmpl.length) ? '<section class="card">'
    + '<div class="card-head"><h2 class="card-title">Not reconciled</h2></div>'
    + (noMoveIn.length ? '<p class="card-text">No move-in date &mdash; recurring bills still post on their due dates, but cycles and paid-through dates can\'t be reckoned (unposted current bills are listed above). Their data is untouched.</p>' + listTenants(noMoveIn, 'Set move-in date', 'openEditModal') : '')
    + (noTmpl.length ? '<p class="card-text">No recurring charges &mdash; bills are added by hand.</p>' + listTenants(noTmpl, 'Add charge', 'openEditModal') : '')
    + '</section>' : '';
  const up = [];
  rows.forEach(r => unpostedCurrent(r.t).forEach(u => up.push({ t: r.t, u })));
  const unpostedCard = up.length ? '<section class="card">'
    + '<div class="card-head"><h2 class="card-title">Not posted this cycle</h2><span class="muted">tenants without a move-in date</span></div>'
    + '<p class="card-text">These recurring bills are due (or within the posting window) but were not posted — e.g. the charge was just set up after its due date, or automatic posting is off for it.</p>'
    + up.map(({ t, u }) => '<div class="plain-row" data-tid="' + esc(t.id) + '" data-tmpl="' + esc(u.tmpl.id || '') + '" data-period="' + u.period + '">'
        + '<div class="plain-main"><div class="plain-title">' + esc(t.name) + ' <span class="muted">· Unit ' + esc(t.unit) + '</span></div>'
        + '<div class="plain-sub">' + esc(u.tmpl.label) + ' · ' + fmtYM(u.period) + ' · due ' + formatDate(u.due) + '</div></div>'
        + (u.tmpl.id ? '<button type="button" class="btn-mini" onclick="const r=this.parentNode;postCurrentCycle(r.dataset.tid,r.dataset.tmpl,r.dataset.period)">Post</button>'
            + '<button type="button" class="btn-mini ghost" onclick="const r=this.parentNode;reconWaiveCurrent(r.dataset.tid,r.dataset.tmpl,r.dataset.period)">Waive</button>' : '')
        + '</div>').join('')
    + '</section>' : '';
  return auto + unpostedCard + checker + off;
}
async function reconWaiveCurrent(tid, tmplId, period) {
  if(!confirm('Waive ' + fmtYM(period) + '? It won\'t be billed or posted automatically. You can undo this under Details › Recurring on the tenant page.')) return;
  const ok = await saveTenantData(tid, x => waiveCycles(x, tmplId, [period]), 'Cycle waived.');
  if(ok) rerenderAdmin();
}

// ─────────────────────────────────────────────
// AUTOMATIC BILLING RUNNER
// Posts recurring bills that planAutoPost says should exist. Runs when an
// admin opens the portal, when the tab regains focus on a new day, after
// a template or tenant changes, and on demand. Sequential per tenant; a
// concurrent write from another device (rev conflict) reloads that tenant
// and retries once on the fresh row — the plan is idempotent, so a second
// device finding the bills already posted is a no-op.
// ─────────────────────────────────────────────
let autoBilling = { enabled: true, leadDays: 7 };
let _autoBillLast = null;   // { day, posted:[{tid,name,label,period}], failed }
let _autoBillChain = Promise.resolve();

// Runs are serialized: a follow-up run (a new charge, a restored tenant)
// waits for the one in progress instead of being dropped.
function runAutoBilling(opts) {
  const next = _autoBillChain.then(() => _runAutoBilling(opts || {}));
  _autoBillChain = next.catch(() => {});
  return next;
}
async function _runAutoBilling(opts) {
  if(currentUser !== 'admin') return;
  if(_settingsLoadFailed) { if(opts.manual) showToast('Settings failed to load — refresh before running automatic billing.', false); return; }
  // A full run (new day, Run now) works from the database's current state,
  // not this tab's sign-in snapshot: settings and tenants changed on
  // another device (turned off, archived, added, paid) are respected.
  if(opts.only && !opts.fresh) await _reloadAutoBillSettings(); // a single-tenant run too honours "off" set elsewhere
  if(!opts.only && !opts.fresh) {
    const okSet = await _reloadAutoBillSettings();
    let okList = true;
    try { await _refreshTenantLists(); } catch { okList = false; }
    if(!okSet || !okList) {
      if(opts.manual) showToast('Could not reach the database to check for changes — try again in a moment.', false);
      renderAdminNav();
      return;
    }
  }
  if(!autoBilling.enabled && !opts.manual) { if(!opts.only && !opts.fresh) _safeRerender(); return; }
  const today = todayISO();
  const posted = [];
  let failed = 0, noRev = 0;
  try {
    const ids = opts.only ? [opts.only] : tenants.map(t => t.id);
    for(const id of ids) {
      for(let attempt = 0; attempt < 2; attempt++) {
        const t = tenants.find(x => x.id === id);
        if(!t) break;
        // Without the rev column (migration 2) writes can't detect another
        // device's concurrent change, so background runs leave such rows
        // alone; "Run now" still works.
        if(t.rev == null && !opts.manual) { if(planAutoPost(t, { today, leadDays: autoBilling.leadDays, uid }).bills.length) noRev++; break; }
        if(t.rev == null) {
          // No rev to catch a concurrent change: plan on the row as it is
          // in the database right now, never on this tab's copy.
          const fr = await sbFetch('tenants?id=eq.' + id + '&select=*');
          const row = fr && fr[0] ? _normalizeTenant(fr[0]) : null;
          if(!row || row.archived_at) { tenants = tenants.filter(x => x.id !== id); break; }
          tenants = tenants.map(x => x.id === id ? row : x);
        }
        const tt = tenants.find(x => x.id === id);
        const plan = planAutoPost(tt, { today, leadDays: autoBilling.leadDays, uid });
        if(!plan.changed) break;
        const patch = { templates: plan.templates };
        if(plan.bills.length) patch.bills = plan.allBills || tt.bills.concat(plan.bills);
        try {
          await dbUpdateTenantGuarded(tt, patch);
          Object.assign(tt, patch);
          plan.bills.forEach(b => posted.push({ tid: tt.id, name: tt.name, label: b.label, period: b.period, fromCredit: billTotalPaid(b) > 0.005 }));
          break;
        } catch(e) {
          if(e.gone) break;                          // archived/deleted elsewhere — nothing to post
          if(e.conflict && attempt === 0) continue; // fresh row loaded — re-plan once
          failed++;
          break;
        }
      }
    }
  } catch(e) { failed++; }
  if(!opts.only) _autoBillLast = { day: today, posted, failed, noRev };
  else if(_autoBillLast && posted.length) _autoBillLast.posted = _autoBillLast.posted.concat(posted);
  if(posted.length) {
    const months = Array.from(new Set(posted.map(p => fmtYM(p.period, 'short'))));
    const cr = posted.filter(p => p.fromCredit);
    showToast('Posted ' + posted.length + ' recurring bill' + (posted.length !== 1 ? 's' : '') + ' (' + months.join(', ') + ').'
      + (cr.length ? ' ' + cr.length + ' paid from money received earlier beyond an earlier bill (' + Array.from(new Set(cr.map(p => p.name))).join(', ') + ') — see the payment notes.' : ''));
  } else if(failed) showToast(failed + ' tenant' + (failed !== 1 ? 's' : '') + ' could not be updated — recurring bills will retry next time.', false);
  else if(opts.manual) {
    // "Everything is posted" only when no due cycle is still unbilled
    // (waived-then-restored or checker-listed cycles need a manual post).
    const lead = autoBilling.leadDays;
    const pending = tenants.reduce((n, t) => n + unpostedCurrent(t).length
      + reconcileTenant(t, { today, leadDays: lead }).charges.reduce((m, c) => m + c.missing.length, 0), 0);
    showToast(pending ? 'Nothing new to post automatically — ' + pending + ' cycle' + (pending !== 1 ? 's are' : ' is') + ' still not billed; post or waive ' + (pending !== 1 ? 'them' : 'it') + ' from the checker.'
      : autoBilling.enabled ? 'Everything due is already posted.' : 'Nothing to post right now.', !pending);
  }
  // Single-tenant runs are triggered by an admin action whose caller
  // re-renders. A manual run re-renders now; a background run never wipes
  // what the admin is typing (it waits until they're done).
  if(opts.only) return;
  if(opts.manual) rerenderAdmin(); else _safeRerender();
}
// Resolves once no automatic-billing run is in progress.
async function _autoBillIdle() { try { await _autoBillChain; } catch {} }

// Is the admin in the middle of typing in the current module? A focused
// field, an open inline amount edit, or a form field changed from its
// initial value all count.
function _isEditingMain() {
  const main = document.getElementById('main-content');
  if(!main) return false;
  const a = document.activeElement;
  if(a && main.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)) return true;
  if(main.querySelector('.td-amt-input')) return true;
  return Array.from(main.querySelectorAll('input, textarea')).some(el =>
    el.type !== 'search' && el.type !== 'checkbox' && el.value !== el.defaultValue);
}
let _rerenderPending = false;
function _safeRerender() {
  if(!_isEditingMain()) { _rerenderPending = false; rerenderAdmin(); return; }
  renderAdminNav(); // badges stay current; the page waits
  if(_rerenderPending) return;
  _rerenderPending = true;
  const retry = () => {
    if(!_rerenderPending || currentUser !== 'admin') { document.removeEventListener('focusout', onOut, true); return; }
    if(_isEditingMain()) return;
    _rerenderPending = false;
    document.removeEventListener('focusout', onOut, true);
    rerenderAdmin();
  };
  const onOut = () => setTimeout(retry, 300);
  document.addEventListener('focusout', onOut, true);
}
let _autoBillDay = '';
document.addEventListener('visibilitychange', () => {
  if(document.visibilityState !== 'visible' || currentUser !== 'admin') return;
  if(_autoBillDay && _autoBillDay !== todayISO()) { _autoBillDay = todayISO(); runAutoBilling(); }
});

// ─────────────────────────────────────────────
// RECEIVE PAYMENT
// One entry point for money coming in: applied to the oldest open bills
// first, and (annuity due) any excess pays future rent cycles in advance.
// ─────────────────────────────────────────────
let _payPlan = null;
let _payRid = ''; // receipt id stamped on every entry this payment writes
// A payment dated after today lands in a future month's cash figures —
// almost always a mistyped date. Ask before recording one.
function _futureDateOk(d) {
  if(!d || d <= todayISO()) return true;
  const sameMonth = ymOf(d) === ymOf(todayISO());
  return confirm('The date is in the future ('+formatDate(d)+').\n\n'
    + (sameMonth ? 'It is counted in this month\'s figures, on a day that hasn\'t come yet.'
                 : 'Cash reports count money on the date it was received, so it will appear in '+fmtYM(ymOf(d))+'\'s figures, not this month\'s.')
    + ' Record it with this date anyway?');
}
function openPayModal(tid) {
  if(!tenants.length) { showToast('Add a tenant first.', false); return; }
  const sel = document.getElementById('pay-tenant');
  const sorted = tenants.slice().sort((a, b) => unitRank(a.unit) - unitRank(b.unit) || a.name.localeCompare(b.name));
  const pick = tid || (sorted.find(t => tenantSummary(t).open > 0) || sorted[0]).id;
  sel.innerHTML = sorted.map(t => '<option value="' + esc(t.id) + '"' + (t.id === pick ? ' selected' : '') + '>' + esc(t.name) + ' · Unit ' + esc(t.unit)
    + (tenantSummary(t).open ? ' · owes ₱' + tenantSummary(t).open.toLocaleString() : '') + '</option>').join('');
  document.getElementById('pay-amount').value = '';
  document.getElementById('pay-date').value = todayISO();
  document.getElementById('pay-date').max = todayISO();
  document.getElementById('pay-note').value = '';
  _payRid = uid();
  document.getElementById('pay-advance').checked = true;
  renderPayPreview();
  openModal('pay-modal');
  requestAnimationFrame(() => document.getElementById('pay-amount').focus());
}
function closePayModal() { closeModalEl('pay-modal'); _payPlan = null; }
function payFill(v) { document.getElementById('pay-amount').value = fmtMoney(v); renderPayPreview(); }
function renderPayPreview() {
  const t = tenants.find(x => x.id === document.getElementById('pay-tenant').value);
  const box = document.getElementById('pay-preview');
  const btnEl = document.getElementById('pay-confirm');
  const card = document.getElementById('pay-tenant-card');
  const fillBox = document.getElementById('pay-fills');
  _payPlan = null;
  if(!t) { box.innerHTML = ''; fillBox.innerHTML = ''; card.innerHTML = ''; btnEl.disabled = true; return; }
  const s = tenantSummary(t);
  const open = r2(t.bills.reduce((x, b) => x + billOpen(b), 0));
  const prim = primaryTemplate(t);
  card.innerHTML = avatar(t.name, 38) + '<span class="pay-pick-text"><strong>' + esc(t.name) + ' · Unit ' + esc(t.unit) + '</strong>'
    + '<span>' + (open ? 'Owes ' + peso(open) : 'Nothing owed') + (s.primary && s.primary.paidThrough ? ' · rent paid through ' + shortDateY(s.primary.paidThrough) : '') + '</span></span>' + icon('chevDown');
  const advWrap = document.getElementById('pay-advance-wrap');
  advWrap.style.display = prim ? '' : 'none';
  const raw = document.getElementById('pay-amount').value;
  const amt = normalizeAmount(raw);
  const fill = (v, label) => '<button type="button" class="pay-fill' + (amt > 0 && Math.abs(amt - v) < 0.005 ? ' on' : '') + '" onclick="payFill(' + v + ')">' + label + ' <strong>' + peso(v) + '</strong></button>';
  fillBox.innerHTML = (open ? fill(open, 'Full balance') : '') + (prim ? fill(r2(open + tmplRate(prim)), open ? 'Balance + 1 month' : '1 month advance') : '');
  const date = document.getElementById('pay-date').value;
  let body = '';
  if(amt > 0 && date) {
    const note = document.getElementById('pay-note').value.trim();
    const plan = allocatePayment(t, [{ amount: amt, date, note }], { today: todayISO(), advance: document.getElementById('pay-advance').checked, uid, rid: _payRid });
    _payPlan = { tid: t.id, rev: t.rev, plan, amt };
    const n = plan.lines.length;
    body = !n ? '' : '<div class="pay-box"><div class="pay-box-head"><span>How it will be applied</span><span>' + n + ' item' + (n !== 1 ? 's' : '') + '</span></div>'
      + plan.lines.map(l => '<div class="pay-line' + (l.kind === 'advance' ? ' adv' : l.settles ? '' : ' part') + '">'
        + '<span class="pl-ic">' + icon('check') + '</span>'
        + '<div class="pl-main"><div class="pl-label">' + esc(l.label) + (l.period ? ' <span class="muted">· ' + fmtYM(l.period, 'short') + '</span>' : '') + '</div>'
        + '<div class="pl-sub">' + (l.kind === 'advance' ? 'Advance' + (l.window ? ' · covers ' + shortDate(l.window.start) + ' – ' + shortDate(addDaysISO(l.window.end, -1)) : ' · due ' + shortDate(l.due))
            : (l.due ? 'Due ' + shortDate(l.due) : 'No due date')) + (l.settles ? ' · settled' : ' · ' + peso(l.remaining) + ' left') + '</div></div>'
        + '<div class="pl-amt">' + peso(l.apply) + '</div></div>').join('') + '</div>';
    if(plan.leftover > 0.005) body += '<div class="pay-warn">' + icon('alert') + '<span>' + peso(plan.leftover) + ' is more than this tenant owes'
      + (prim ? (document.getElementById('pay-advance').checked ? '.' : ' — tick "Apply any excess as advance rent" to carry it into future cycles.')
              : ' and there is no recurring rent to apply an advance to. Lower the amount or add a monthly rent template first.') + '</span></div>';
  }
  box.innerHTML = body;
  const over = !!(_payPlan && _payPlan.plan.leftover > 0.005);
  btnEl.disabled = !(_payPlan && _payPlan.plan.lines.length && !over);
  btnEl.textContent = over ? 'Fix the amount first' : _payPlan && _payPlan.plan.lines.length ? 'Record ₱' + fmtMoney(amt) : 'Record payment';
}
async function confirmPayment() {
  const p = _payPlan;
  const btnEl = document.getElementById('pay-confirm');
  if(!p || btnEl.disabled) return;
  await _autoBillIdle();
  const t = tenants.find(x => x.id === p.tid);
  // The plan was built on the row as shown; if anything changed since, rebuild.
  if(!t || t.rev !== p.rev) { renderPayPreview(); showToast('Data changed — please review the allocation again.', false); return; }
  if(!_futureDateOk(document.getElementById('pay-date').value)) return;
  btnEl.disabled = true; btnEl.textContent = 'Saving…';
  const ok = await saveTenantData(p.tid, () => ({ bills: p.plan.bills, templates: p.plan.templates }), 'Payment of ₱' + p.amt.toLocaleString() + ' recorded for ' + t.name + '.');
  btnEl.disabled = false;
  if(ok) { _payRid = uid(); closePayModal(); rerenderAdmin(); }
  else renderPayPreview();
}

// ─────────────────────────────────────────────
// MENUS — one popover component for row/overflow actions. Anchored under
// its button on desktop; a bottom sheet on phones.
// ─────────────────────────────────────────────
let _menuItems = null;
let _menuReturn = null;
function openMenu(anchor, items, title) {
  closeMenu();
  _menuItems = items;
  _menuReturn = anchor || null;
  const layer = document.createElement('div');
  layer.id = 'menu-layer';
  layer.className = 'menu-layer';
  layer.innerHTML = '<div class="menu-scrim" onclick="closeMenu()"></div><div class="menu" role="menu" aria-label="' + esc(title || 'Actions') + '">'
    + (title ? '<div class="menu-title">' + esc(title) + '</div>' : '')
    + items.map((it, i) => '<button type="button" role="menuitem" class="menu-item' + (it.danger ? ' danger' : '') + '" onclick="menuPick(' + i + ')">' + (it.icon ? icon(it.icon) : '') + '<span>' + esc(it.label) + '</span></button>').join('')
    + '</div>';
  document.body.appendChild(layer);
  const menu = layer.querySelector('.menu');
  if(window.innerWidth > 768 && anchor && anchor.getBoundingClientRect) {
    const r = anchor.getBoundingClientRect();
    const mw = menu.offsetWidth, mh = menu.offsetHeight;
    let left = Math.min(r.right - mw, window.innerWidth - mw - 8);
    left = Math.max(8, left);
    let top = r.bottom + 6;
    if(top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 6);
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
  } else layer.classList.add('as-sheet');
  const first = menu.querySelector('.menu-item');
  if(first) first.focus();
}
function menuPick(i) {
  const it = _menuItems && _menuItems[i];
  const back = _menuReturn;
  closeMenu(true);
  // Focus goes back to the menu button first, so a modal the action opens
  // restores focus there when it closes.
  if(back && back.isConnected) { try { back.focus(); } catch {} }
  if(it) it.fn();
}
function closeMenu(picked) {
  const el = document.getElementById('menu-layer');
  if(el) el.remove();
  _menuItems = null;
  if(!picked && _menuReturn && _menuReturn.isConnected) { try { _menuReturn.focus(); } catch {} }
  _menuReturn = null;
}
document.addEventListener('keydown', e => {
  const layer = document.getElementById('menu-layer');
  if(!layer) return;
  const items = Array.from(layer.querySelectorAll('.menu-item'));
  const idx = items.indexOf(document.activeElement);
  const back = e.key === 'ArrowUp' || (e.key === 'Tab' && e.shiftKey);
  if(e.key === 'Escape') { e.stopImmediatePropagation(); closeMenu(); }
  else if(e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Tab') {
    // Focus stays inside the menu while it's open, cycling through items.
    e.preventDefault();
    items[(idx + (back ? -1 : 1) + items.length) % items.length].focus();
  }
}, true);

// ─────────────────────────────────────────────
// REPORTS MODULE
// ─────────────────────────────────────────────
// Reports & insights share one page header with underline tabs.
function _reportsHead(active, right) {
  const tab = (k, l) => '<a href="#/' + k + '" class="oa-utab' + (active === k ? ' active' : '') + '"' + (active === k ? ' aria-current="page"' : '') + '>' + l + '</a>';
  return pageHead('Reports &amp; insights', active === 'insights' ? 'How the building is doing · revenue on accrual basis' + (_incStmtProrate() ? ', spread over each billing cycle' : '') : 'Printable statements and exports')
    + '<div class="oa-utabs"><nav class="oa-utabs-list" aria-label="Reports and insights">' + tab('insights', 'Insights') + tab('reports', 'Statements &amp; exports') + '</nav>' + (right || '') + '</div>';
}
function openInsightWindowMenu(anchor) {
  openMenu(anchor, Object.entries(INSIGHT_WINDOWS).map(([k, l]) => ({ label: (insightWindow === k ? '✓ ' : '') + l, fn: () => { insightWindow = k; rerenderAdmin(); } })), 'Period');
}
function _pctDelta(cur, prev, upIsGood, tail) {
  // Nothing to compare with: keep only the extra note (a tail starting "·").
  if(!prev) return '<span class="oa-stat-sub">no earlier figures' + (tail && tail.charAt(0) === '·' ? ' ' + tail : '') + '</span>';
  const pct = Math.round((cur - prev) / Math.abs(prev) * 1000) / 10;
  const good = pct === 0 ? null : (pct > 0) === upIsGood;
  return '<span class="oa-stat-sub"><b class="' + (good === null ? '' : good ? 'up' : 'down') + '">' + (pct > 0 ? '+' : pct < 0 ? '−' : '') + Math.abs(pct) + '%</b> ' + (tail || '') + '</span>';
}

function renderInsightsModule() {
  const all = allTenants();
  const rg = _insightRange(insightWindow);
  const period = '<div class="oa-utabs-right"><span class="oa-muted-sm">Period</span><button type="button" class="oa-dd sm" aria-haspopup="menu" onclick="openInsightWindowMenu(this)"><span>' + fmtYM(rg.from, 'short') + ' – ' + fmtYM(rg.to, 'short') + '</span>' + icon('chevDown') + '</button></div>';
  const head = _reportsHead('insights', period);
  if(!all.length) return head + '<div class="empty-state"><p>Insights appear once you have tenants and bills.</p></div>';
  const hasExp = expensesAvailable && !_expensesLoadError;
  const base = { tenants: all, expenses, hasExpenses: hasExp, floorRank, floorCanon: appFloorCanon(), allocation: 'none' };
  // Same revenue recognition as the printed income statement, so the two tie out.
  const prorate = _incStmtProrate();
  const acc = computeIncomeStatement(Object.assign({}, base, { from: rg.from, to: rg.to, basis: 'accrual', prorate }));
  const accPrev = computeIncomeStatement(Object.assign({}, base, { from: rg.prevFrom, to: rg.prevTo, basis: 'accrual', prorate }));
  const cash = computeIncomeStatement(Object.assign({}, base, { from: rg.from, to: rg.to, basis: 'cash' }));
  const today = todayISO();

  // Collection rate: share of the period's billing already paid.
  const effOf = (from, to) => {
    let billed = 0, paid = 0;
    const win = new Set(ymRange(from, to));
    all.forEach(t => t.bills.forEach(b => {
      if(!win.has(billPeriod(b)) || billPeriod(b) > _currentYM()) return;
      const amt = Number(b.amount) || 0;
      billed += amt; paid += Math.min(amt, billSettled(b));
    }));
    return { billed: r2(billed), paid: r2(paid), pct: billed > 0 ? Math.round(paid / billed * 100) : null };
  };
  const eff = effOf(rg.from, rg.to), effPrev = effOf(rg.prevFrom, rg.prevTo);
  const prevLbl = 'vs previous ' + (rg.n === 1 ? 'month' : rg.n + ' months');
  const T = acc.total, P = accPrev.total;
  const tile = (label, value, sub, cls) => '<div class="oa-stat"><span class="oa-stat-label">' + label + '</span><strong class="oa-stat-fig' + (cls ? ' ' + cls : '') + '">' + value + '</strong>' + sub + '</div>';
  const money = v => (v < 0 ? '&minus;' : '') + peso(Math.abs(v));
  const tiles = '<div class="oa-stats">'
    + tile('Revenue', peso(T.revenue.total), _pctDelta(T.revenue.total, P.revenue.total, true, prevLbl))
    + (hasExp ? tile('Expenses', peso(T.expenses), _pctDelta(T.expenses, P.expenses, false, prevLbl)) : tile('Expenses', '&mdash;', '<span class="oa-stat-sub">ledger not set up</span>'))
    + (hasExp ? tile('Net income', money(T.net), _pctDelta(T.net, P.net, true, '· ' + money(Math.round(T.net / Math.max(1, rg.n))) + ' a month'), T.net < 0 ? 'bad' : '') : '')
    + tile('Collection rate', eff.pct === null ? '&mdash;' : eff.pct + '%', '<span class="oa-stat-sub">' + (eff.billed ? 'of everything billed was paid' : 'nothing billed yet')
        + (eff.pct !== null && effPrev.pct !== null && eff.pct !== effPrev.pct ? ' · <b class="' + (eff.pct > effPrev.pct ? 'up' : 'down') + '">' + (eff.pct > effPrev.pct ? '+' : '−') + Math.abs(eff.pct - effPrev.pct) + ' pts</b>' : '') + '</span>', eff.pct !== null && eff.pct < 80 ? 'bad' : '')
    + '</div>';
  const archNote = _archivedLoadError ? '<div class="hint-note">' + icon('alert') + ' Archived tenants could not be loaded — former tenants\' history is missing from these figures. Refresh to retry.</div>' : '';
  return head + archNote + tiles
    + _netByMonthCard(acc, hasExp)
    + '<div class="in-grid">' + _agingCard(today) + (hasExp ? _expenseMixCard(acc) : '') + '</div>'
    + _floorTableCard(acc, cash)
    + _passThroughCard(acc) + _punctualityCard(rg, today);
}

// Net income (revenue without an expense ledger) per month: best month in
// brand orange, the month in progress lighter, dashed line at the average.
function _netByMonthCard(acc, hasExp) {
  const rows = acc.perMonth.__total;
  const cur = _currentYM();
  const val = r => hasExp ? r.net : r.revenue;
  // Best month and the average use finished months, from the first one with figures.
  const full = rows.filter(r => r.ym < cur);
  const first = full.findIndex(r => r.revenue || r.expenses);
  const done = first < 0 ? [] : full.slice(first);
  const avg = done.length ? Math.round(done.reduce((s, r) => s + val(r), 0) / done.length) : 0;
  const best = done.length ? done.slice().sort((a, b) => val(b) - val(a))[0] : null;
  const signed = v => (v < 0 ? '&minus;' : '') + peso(Math.abs(v));
  const max = Math.max(1, ...rows.map(r => Math.max(0, val(r))), avg);
  const h = v => (Math.max(0, v) / max * 100).toFixed(2) + '%';
  const cols = rows.map(r => {
    const v = val(r), cls = r.ym === cur ? 'part' : best && r.ym === best.ym ? 'best' : '';
    return '<div class="nm-col ' + cls + '" title="' + esc(fmtYM(r.ym) + (r.ym === cur ? ' (so far)' : '') + ': ' + (v < 0 ? '−' : '') + '₱' + fmtMoney(Math.abs(v))) + '">'
      + '<span class="nm-bar" style="height:' + h(v) + '"><span class="nm-val' + (v < 0 ? ' neg' : '') + '">' + (v < 0 ? '−' : '') + _kShort(v) + '</span></span></div>';
  }).join('');
  const labels = rows.map(r => '<span>' + _monthName(r.ym, 'short') + '</span>').join('');
  const what = hasExp ? 'Net income' : 'Revenue';
  const sub = (best ? 'Best month: ' + fmtYM(best.ym).replace(/ \d{4}$/, '') + ' at ' + signed(val(best)) : '')
    + (rows.some(r => r.ym === cur) ? (best ? ' · ' : '') + _monthName(cur) + ' is still in progress' : '');
  const table = '<details class="viz-table"><summary>Show as table</summary><div class="table-scroll"><table class="mini-table"><thead><tr><th>Month</th><th class="num">Revenue</th>' + (hasExp ? '<th class="num">Expenses</th><th class="num">Net</th>' : '') + '</tr></thead><tbody>'
    + rows.map(r => '<tr><td>' + fmtYM(r.ym, 'short') + '</td><td class="num">' + peso(r.revenue) + '</td>' + (hasExp ? '<td class="num">' + peso(r.expenses) + '</td><td class="num' + (r.net < 0 ? ' txt-bad' : '') + '">' + (r.net < 0 ? '&minus;' : '') + peso(Math.abs(r.net)) + '</td>' : '') + '</tr>').join('')
    + '</tbody></table></div></details>';
  return '<section class="card in-chart">'
    + '<div class="ch-head"><div class="ch-titles"><h2 class="card-title">' + what + ' by month</h2><span class="ch-sub">' + sub + '</span></div>'
    + (done.length ? '<span class="nm-avg-key"><i></i>' + done.length + '-month average ' + signed(avg) + '</span>' : '') + '</div>'
    + '<div class="nm-plot" role="img" aria-label="' + what + ' by month"><div class="nm-cols">' + cols + '</div>'
    + (done.length ? '<i class="nm-avg" style="bottom:' + h(avg) + '"></i>' : '') + '</div>'
    + '<div class="nm-x" aria-hidden="true">' + labels + '</div>'
    + table + '</section>';
}

function _agingCard(today) {
  const buckets = agingBuckets(allTenants(), today);
  const total = r2(buckets.reduce((s, b) => s + b.amount, 0));
  const late = r2(buckets.filter(b => !['current', 'nodate'].includes(b.key)).reduce((s, b) => s + b.amount, 0));
  // Same tenants as the buckets above (current and former), same recognition as the statement.
  const memo = computeIncomeStatement({ tenants: allTenants(), expenses: [], from: _currentYM(), to: _currentYM(), basis: 'accrual', prorate: _incStmtProrate(), hasExpenses: false }).memo.__total;
  const max = Math.max(1, ...buckets.map(b => b.amount));
  const label = { current: 'Not yet due', d30: '1–30 days late', d60: '31–60 days late', d90: '61–90 days late', d90p: 'Over 90 days', nodate: 'No due date' };
  const rows = buckets.filter(b => b.key !== 'nodate' || b.amount > 0).map(b => '<div class="ag-row ag-' + b.key + '">'
    + '<div class="ag-label"><strong>' + label[b.key] + '</strong><span>' + (b.count ? b.count + ' bill' + (b.count !== 1 ? 's' : '') : 'None') + '</span></div>'
    + '<span class="ag-track"><i style="width:' + (b.amount > 0 ? Math.max(2, b.amount / max * 100).toFixed(1) : 0) + '%"></i></span>'
    + '<strong class="ag-amt">' + peso(b.amount) + '</strong></div>').join('');
  return '<section class="card in-card"><div class="in-card-head"><div><h2 class="card-title">Money owed, by age</h2><span class="ch-sub">'
    + (!total ? 'Nobody owes anything right now.' : late ? peso(late) + ' of ' + peso(total) + ' is past due' : 'Everything owed is still within its due date.') + '</span></div>'
    + '<button type="button" class="link-btn" onclick="goBills(\'overdue\')">Overdue bills</button></div>'
    + '<div class="ag-list">' + rows + '</div>'
    + '<div class="in-foot"><div><span>Collected in advance</span><strong>' + peso(memo.unearned) + '</strong></div><div><span>Tenant credits (overpaid)</span><strong>' + peso(memo.credits) + '</strong></div></div>'
    + '</section>';
}

function _expenseMixCard(acc) {
  const T = acc.total;
  const cats = EXPENSE_CATEGORIES.map(c => ({ key: c.key, label: c.label, value: r2(T.direct[c.key] + T.shared[c.key] - T.recovered[c.key]) })).filter(x => x.value > 0).sort((a, b) => b.value - a.value);
  const spent = T.expenses;
  const sum = r2(cats.reduce((s, c) => s + c.value, 0)) || 1;
  return '<section class="card in-card"><div class="in-card-head"><div><h2 class="card-title">Where the money goes</h2><span class="ch-sub">'
    + peso(spent) + ' in expenses' + (T.recovered.total > 0.005 ? ' after ' + peso(T.recovered.total) + ' of utilities billed back' : '') + (T.revenue.total > 0 ? ' · ' + Math.round(spent / T.revenue.total * 100) + '% of revenue' : '') + '</span></div>'
    + '<button type="button" class="link-btn" onclick="go(\'expenses\')">Expenses</button></div>'
    + (cats.length
      ? '<div class="mix-bar" role="img" aria-label="Expenses by category">' + cats.map(c => '<i class="c-' + c.key + '" style="width:' + (c.value / sum * 100).toFixed(2) + '%" title="' + esc(c.label + ': ₱' + fmtMoney(c.value)) + '"></i>').join('') + '</div>'
        + '<div class="mix-legend">' + cats.map(c => '<div class="mix-item"><span class="mix-name"><i class="c-' + c.key + '"></i><span class="mix-label" title="' + esc(c.label) + '">' + esc(c.label) + '</span></span><span class="mix-pct">' + Math.round(c.value / sum * 100) + '%</span><strong>' + peso(c.value) + '</strong></div>').join('') + '</div>'
      : '<div class="empty-inline">No expenses logged in this period.</div>')
    + '</section>';
}

// By floor: each floor's revenue against its floor-tagged costs, then the
// building-wide costs and the building total.
function _floorTableCard(acc, cash) {
  const floors = acc.floors;
  if(!floors.some(f => f)) return '';
  const hasExp = expensesAvailable && !_expensesLoadError;
  const money = v => (v < 0 ? '&minus;' : '') + peso(Math.abs(v));
  const dash = '<span class="oa-muted-sm">&mdash;</span>';
  let floorExpSum = 0, owedSum = 0, curN = 0;
  const rows = floors.map(f => {
    const c = acc.columns[f], m = cash.memo[f];
    const nCur = tenants.filter(t => floorNorm(t.floor) === floorNorm(f)).length;
    const nFormer = archivedTenants.filter(t => floorNorm(t.floor) === floorNorm(f) && occupiedInRange(t, acc.from, acc.to)).length;
    const owed = r2(allTenants().filter(t => floorNorm(t.floor) === floorNorm(f)).reduce((s, t) => s + tenantSummary(t).open, 0));
    // Only floor-tagged costs: building-wide costs are not charged to a floor here.
    const floorExp = r2(c.direct.total - c.recovered.total); // net of utilities billed back
    floorExpSum = r2(floorExpSum + floorExp); owedSum = r2(owedSum + owed); curN += nCur;
    const net = r2(c.revenue.total - floorExp);
    return '<div class="oa-tr in-floor' + (hasExp ? '' : ' no-exp') + '"><strong>' + esc(f || 'No floor') + '</strong>'
      + '<span class="oa-cell-bill">' + nCur + (nFormer ? ' + ' + nFormer + ' former' : '') + '</span>'
      + '<span class="oa-cell-amt n">' + peso(c.revenue.total) + '</span>'
      + (hasExp ? '<span class="oa-cell-amt n muted">' + (floorExp > 0.005 ? peso(floorExp) : dash) + '</span><span class="oa-cell-amt' + (net < 0 ? ' bad' : '') + '">' + money(net) + '</span>' : '')
      + '<span class="oa-cell-amt n">' + (m && m.rate !== null ? m.rate + '%' : dash) + '</span>'
      + '<span class="oa-cell-amt n">' + (owed ? peso(owed) : dash) + '</span></div>';
  }).join('');
  const shared = r2(acc.total.expenses - floorExpSum);
  const tot = cash.memo.__total;
  const bw = hasExp && Math.abs(shared) > 0.005 ? '<div class="oa-tr in-floor"><strong>Building-wide</strong><span class="oa-cell-bill">' + dash + '</span><span class="oa-cell-amt n">' + dash + '</span>'
    + '<span class="oa-cell-amt n muted">' + peso(shared) + '</span><span class="oa-cell-amt' + (shared > 0 ? ' bad' : '') + '">' + money(-shared) + '</span><span class="oa-cell-amt n">' + dash + '</span><span class="oa-cell-amt n">' + dash + '</span></div>' : '';
  const total = '<div class="oa-tr in-floor in-total' + (hasExp ? '' : ' no-exp') + '"><strong>Building total</strong><span class="oa-cell-bill"><b>' + curN + '</b></span><span class="oa-cell-amt">' + peso(acc.total.revenue.total) + '</span>'
    + (hasExp ? '<span class="oa-cell-amt">' + peso(acc.total.expenses) + '</span><span class="oa-cell-amt' + (acc.total.net < 0 ? ' bad' : '') + '">' + money(acc.total.net) + '</span>' : '')
    + '<span class="oa-cell-amt">' + (tot && tot.rate !== null ? tot.rate + '%' : '&mdash;') + '</span><span class="oa-cell-amt">' + peso(owedSum) + '</span></div>';
  return '<section class="card oa-table-card in-floors"><div class="oa-card-head"><h2 class="card-title">By floor</h2>'
    + '<span class="oa-muted-sm">' + (hasExp ? 'Floor expenses are floor-tagged, net of utilities billed back; the rest is building-wide · ' : '') + 'Collected = cash received vs billed in the period, excluding utilities billed back · <button type="button" class="link-btn inline" onclick="openIncStmtModal(\'floors-compare\')">Per-floor income statement</button></span></div>'
    + '<div class="oa-table"><div class="oa-thead in-floor' + (hasExp ? '' : ' no-exp') + '" role="row"><span>Floor</span><span>Tenants</span><span class="r">Revenue</span>' + (hasExp ? '<span class="r">Expenses</span><span class="r">Net</span>' : '') + '<span class="r">Collected</span><span class="r">Owed now</span></div>'
    + rows + bw + total + '</div></section>';
}
// A former tenant counts on a floor when they lived there during the period.
function occupiedInRange(t, from, to) { return ymRange(from, to).some(ym => occupiedInMonth(t, ym)); }

function renderReportsModule() {
  const floors = floorList();
  const tOpts = tenants.slice().sort((a, b) => unitRank(a.unit) - unitRank(b.unit) || a.name.localeCompare(b.name))
    .map(t => '<option value="' + esc(t.id) + '">' + esc(t.name) + ' · Unit ' + esc(t.unit) + '</option>').join('');
  const card = (ic, title, text, actions) => '<section class="card report-card"><div class="report-ico">' + icon(ic) + '</div><div class="report-body"><h2 class="card-title">' + title + '</h2><p class="card-text">' + text + '</p><div class="btn-row">' + actions + '</div></div></section>';
  return _reportsHead('reports')
    + '<div class="report-grid">'
    + card('doc', 'Income statement', 'Revenue, expenses and net income for any period. <strong>Accrual basis</strong> by default (revenue in the cycle it\'s earned; advances held as unearned), or cash basis.',
        btn('Open', 'openIncStmtModal()', { primary: true, icon: 'print' }))
    + card('building', 'Income statement per floor', floors.length
        ? 'Each floor\'s revenue with its own floor-tagged expenses (building-wide costs can optionally be split) &mdash; side by side, or one page per floor.'
        : 'Give tenants a floor/group label to compare floors. Floor-tagged expenses go to their floor; shared costs stay in the building total unless you choose to split them.',
        btn('Side by side', 'openIncStmtModal(\'floors-compare\')', { icon: 'building' }) + btn('One page per floor', 'openIncStmtModal(\'floors-pages\')', { icon: 'print' }))
    + card('users', 'Statement of account', 'A tenant\'s bills, payments and balance for a period — ready to print or save as PDF.',
        (tenants.length ? '<select id="rep-tenant" class="tb-select" aria-label="Tenant">' + tOpts + '</select>' + btn('Open', 'openStmtModalById(document.getElementById(\'rep-tenant\').value)', { primary: true, icon: 'print' }) : '<span class="muted">No tenants yet.</span>'))
    + card('download', 'Exports', 'Spreadsheet-ready CSV files of every bill and every expense.',
        btn('Bills CSV', 'exportCSV()', { icon: 'download' }) + btn('Expenses CSV', 'exportExpensesCSV()', { icon: 'download' }))
    + '</div>';
}

// ─────────────────────────────────────────────
// SETTINGS MODULE
// ─────────────────────────────────────────────
let _setEdit = ''; // portal text being edited inline: 'payinst' | 'announce' | 'branding'
let _setEditFocus = false; // focus the editor on the next render (it just opened)
let _setReturn = '';       // editor just closed: focus its Edit button
let _setSaving = '';       // editor whose save is in flight
const _setDraft = {};      // unsaved text from a failed save, per editor
function _autoBillLastLine() {
  const last = _autoBillLast;
  if(!autoBilling.enabled) return 'Automatic billing is off — post recurring bills from Billing.';
  if(!last) return 'Checking recurring bills…';
  const when = last.day === todayISO() ? 'today' : shortDate(last.day);
  return 'Last run ' + when + ' · ' + (last.posted.length ? 'posted ' + last.posted.length + ' bill' + (last.posted.length !== 1 ? 's' : '') : 'nothing new to post')
    + (last.failed ? ' · <span class="txt-bad">' + last.failed + ' could not be saved — try Run now</span>' : '')
    + (last.noRev ? ' · <span class="txt-bad">' + last.noRev + ' skipped: background posting needs supabase-migration-2.sql</span>' : '');
}
function renderSettingsModule() {
  const head = (ic, tone, title, sub) => '<div class="st-head"><span class="st-ic ' + tone + '">' + icon(ic) + '</span><div><h2 class="card-title">' + title + '</h2>' + (sub ? '<span class="st-sub">' + sub + '</span>' : '') + '</div></div>';
  const row = (label, hint, ctrl) => '<div class="st-row"><div class="st-row-text"><div class="st-label">' + label + '</div>' + (hint ? '<div class="st-hint">' + hint + '</div>' : '') + '</div>' + (ctrl || '') + '</div>';
  const leadOpts = [0, 3, 5, 7, 10, 14, 21].map(d => '<option value="' + d + '"' + (autoBilling.leadDays === d ? ' selected' : '') + '>' + (d ? d + ' days before due' : 'On the due date') + '</option>').join('')
    + (![0, 3, 5, 7, 10, 14, 21].includes(autoBilling.leadDays) ? '<option value="' + autoBilling.leadDays + '" selected>' + autoBilling.leadDays + ' days before due</option>' : '');
  const autoCard = '<section class="card st-card">' + head('repeat', 'accent', 'Automatic billing')
    + row('Post recurring bills automatically', 'Each recurring charge creates its bill ahead of the due date, every cycle. It also catches up a cycle missed while nobody opened the app, up to two months back. History from before a charge was active is never created automatically.',
        '<label class="switch lg"><input type="checkbox" id="set-auto"' + (autoBilling.enabled ? ' checked' : '') + ' onchange="saveAutoBilling(\'enabled\')"><span class="switch-ui"></span><span class="sr-only">Post recurring bills automatically</span></label>')
    + row('Posting lead time', 'Rent is paid in advance, so tenants see the bill before it\'s due.',
        '<select id="set-lead" class="tb-select st-select" aria-label="Posting lead time" onchange="saveAutoBilling(\'lead\')">' + leadOpts + '</select>')
    + '<div class="st-foot"><span>' + _autoBillLastLine() + '</span>' + btn('Run now', 'runAutoBilling({manual:true})', { icon: 'repeat' }) + '</div>'
    + '</section>';
  const GRACE_OPTS = [0, 1, 2, 3, 5, 7, 10, 15];
  const graceSet = GRACE_OPTS.concat(GRACE_OPTS.includes(graceDays) ? [] : [graceDays]).sort((a, b) => a - b);
  const lateCard = '<section class="card st-card">' + head('calendar', 'warn', 'Late payments')
    + '<div class="st-row st-col"><div class="st-row-text"><div class="st-label">Grace period</div><div class="st-hint">Days after the due date before a bill shows as overdue and counts as late.</div></div>'
    + segTabs(graceSet.map(d => ({ label: d ? d + ' day' + (d !== 1 ? 's' : '') : 'None', active: graceDays === d, onclick: 'saveGraceDays(' + d + ')' })), 'st-grace', 'Grace period') + '</div>'
    + '</section>';
  const pill = (ok, okText, warnText) => ok === true ? oaPill('paid', okText) : ok === false ? oaPill('due', warnText) : oaPill('neutral', 'Unknown');
  const dbCard = '<section class="card st-card">' + head('doc', 'neutral', 'Database')
    + '<div class="st-db"><span>Expenses ledger <span class="oa-muted-sm">· migration 2</span></span>' + pill(expensesAvailable, 'Installed', 'Run supabase-migration-2.sql') + '</div>'
    + '<div class="st-db"><span>Change protection <span class="oa-muted-sm">· migration 2</span></span>' + pill(!(tenants.length && tenants.some(t => t.rev == null)), 'Installed', 'Run migration 2 — background posting is paused') + '</div>'
    + '<div class="st-db"><span>Expense floor tags <span class="oa-muted-sm">· migration 3</span></span>' + pill(expensesFloorAvailable === false ? false : expensesFloorAvailable ? true : null, 'Installed', 'Run supabase-migration-3.sql') + '</div>'
    + '</section>';
  // Tenant portal texts, edited in place. An open editor keeps what is typed
  // in it across re-renders (grace, Run now…); a failed save keeps its draft.
  const live = id => { const el = document.getElementById(id); return el ? el.value : null; };
  const draft = (key, id, saved, f) => { const v = live(id); return v !== null ? v : _setDraft[key] ? (f ? _setDraft[key][f] : _setDraft[key]) : saved; };
  const saveBtn = (key, fn) => '<button type="button" class="btn-pri" onclick="' + fn + '"' + (_setSaving === key ? ' disabled>Saving…' : '>Save') + '</button>';
  const pRow = (key, label, val, empty, hint, editor) => '<div class="st-prow"><div class="st-prow-head"><span class="st-label">' + label + '</span>'
    + (_setEdit === key ? '' : '<button type="button" class="btn-sec st-edit" id="st-edit-' + key + '" aria-label="Edit ' + label.toLowerCase() + '" onclick="' + { payinst: 'openPayInstModal()', announce: 'openAnnounceModal()', branding: 'openBrandingModal()' }[key] + '">Edit</button>') + '</div>'
    + (_setEdit === key ? editor : '<div class="st-text' + (val ? '' : ' empty') + '">' + (val ? esc(val) : empty) + '</div>')
    + '<div class="st-hint">' + hint + '</div></div>';
  const ta = (key, label, val, ph, save, cancel) => '<div class="st-editor" onkeydown="if(event.key===\'Escape\'){event.stopPropagation();' + cancel + '}"><textarea id="' + key + '-textarea" aria-label="' + esc(label) + '" rows="4" placeholder="' + esc(ph) + '">' + esc(draft(key, key + '-textarea', val) || '') + '</textarea>'
    + '<div id="' + key + '-error" class="st-err" hidden></div>'
    + '<div class="st-editor-actions"><button type="button" class="btn-sec" onclick="' + cancel + '">Cancel</button>' + saveBtn(key, save) + '</div></div>';
  const brandEditor = '<div class="st-editor" onkeydown="if(event.key===\'Escape\'){event.stopPropagation();closeBrandingModal()}else if(event.key===\'Enter\'&&event.target.tagName===\'INPUT\'){saveBranding()}"><div class="field"><label for="branding-name">Property name</label><input type="text" id="branding-name" maxlength="60" value="' + esc(draft('branding', 'branding-name', propertyName, 'name')) + '" placeholder="e.g. Orange Apartment"></div>'
    + '<div class="field"><label for="branding-sub">Tagline / location <span class="opt">(optional, on statements)</span></label><input type="text" id="branding-sub" maxlength="80" value="' + esc(draft('branding', 'branding-sub', propertySubtitle, 'sub')) + '" placeholder="e.g. Tenant Billing Portal · Baguio"></div>'
    + '<div id="branding-error" class="st-err" hidden></div>'
    + '<div class="st-editor-actions"><button type="button" class="btn-sec" onclick="closeBrandingModal()">Cancel</button>' + saveBtn('branding', 'saveBranding()') + '</div></div>';
  const portal = '<section class="card st-card">' + head('home', 'blue', 'Tenant portal', 'What tenants see when they sign in')
    + pRow('payinst', 'Payment instructions', paymentInstructions, 'Not set — tenants won\'t see how to pay.', 'Shown on every tenant\'s “How to pay” screen.',
        ta('payinst', 'Payment instructions', paymentInstructions, 'e.g. GCash: 0917 123 4567\nBDO: 1234-5678-9012\nCash: hand to the admin at Unit 1', 'savePayInst()', 'closePayInstModal()'))
    + pRow('announce', 'Announcements', announcements, 'Not set — the notice board is hidden.', 'Leave empty to hide the notice board.',
        ta('announce', 'Announcements', announcements, 'e.g. Water interruption on Aug 15, 8am–5pm.', 'saveAnnouncements()', 'closeAnnounceModal()'))
    + pRow('branding', 'Property name', propertyName + (propertySubtitle ? ' · ' + propertySubtitle : ''), '', 'Appears in the portal header, on statements and in payment reminders.', brandEditor)
    + '</section>';
  const floorsCard = '<section class="card st-card">' + head('building', 'neutral', 'Floors', 'Offered when tagging tenants and expenses')
    + (allFloors().length ? allFloors().map(f => {
        const n = allTenants().filter(t => floorNorm(t.floor) === floorNorm(f)).length, m = expenses.filter(x => floorNorm(x.floor) === floorNorm(f)).length;
        return '<div class="st-db"><span>' + esc(f) + ' <span class="oa-muted-sm">· ' + n + ' tenant' + (n !== 1 ? 's' : '') + ' · ' + m + ' expense' + (m !== 1 ? 's' : '') + '</span></span>'
          + '<span class="st-floor-acts"><button type="button" class="oa-icon-btn" data-f="' + esc(f) + '" onclick="renameFloor(this.dataset.f)" aria-label="Rename ' + esc(f) + '" title="Rename (updates every tenant and expense on it)">' + icon('edit') + '</button>'
          + '<button type="button" class="oa-icon-btn" data-f="' + esc(f) + '" onclick="removeFloor(this.dataset.f)" aria-label="Remove ' + esc(f) + '" title="Remove">' + icon('trash') + '</button></span></div>';
      }).join('') : '<div class="st-db"><span class="oa-muted-sm">No floors yet.</span></div>')
    + '<div class="st-foot">' + btn('Add floor', 'addFloorPrompt().then(()=>rerenderAdmin())', { icon: 'plus' }) + '</div>'
    + '</section>';
  if(_setEdit && _setEditFocus) { _setEditFocus = false; _postRender.push(() => { const el = document.querySelector('.st-editor textarea, .st-editor input'); if(el) el.focus(); }); }
  if(_setReturn) { const k = _setReturn; _setReturn = ''; _postRender.push(() => { const el = document.getElementById('st-edit-' + k); if(el) el.focus(); }); }
  return pageHead('Settings', 'Billing rules, the tenant portal and the database')
    + '<div class="st-grid"><div class="td-col">' + autoCard + lateCard + dbCard + '</div><div class="td-col">' + portal + floorsCard + '</div></div>';
}
async function renameFloor(f) {
  if(!_guardSettingsEdit()) return;
  const raw = prompt('Rename "' + f + '" to:', f);
  const v = String(raw || '').trim().replace(/\s+/g, ' ');
  if(!v || v === f) return;
  if(v.length > 40) { showToast('Keep the floor name to 40 characters.', false); return; }
  const clash = allFloors().find(x => floorNorm(x) === floorNorm(v) && floorNorm(x) !== floorNorm(f));
  if(clash && !confirm('"' + clash + '" already exists. Merge "' + f + '" into it?')) return;
  const target = clash || v;
  const ts = tenants.filter(t => floorNorm(t.floor) === floorNorm(f));
  const arch = archivedTenants.filter(t => floorNorm(t.floor) === floorNorm(f));
  const xs = expenses.filter(x => floorNorm(x.floor) === floorNorm(f));
  setLoading(true, 'Renaming floor…');
  let failed = 0;
  for(const t of ts) { try { await dbUpdateTenantGuarded(t, { floor: target }); t.floor = target; } catch { failed++; } }
  // Former tenants too, so past reports use the new name (still-archived rows only, unchanged since loaded).
  for(const t of arch) {
    try {
      let q = 'tenants?id=eq.' + t.id + '&archived_at=not.is.null';
      const body = { floor: target };
      if(t.rev != null) { q += '&rev=eq.' + t.rev; body.rev = Number(t.rev) + 1; }
      const rows = await sbFetch(q, { method: 'PATCH', body: JSON.stringify(body) });
      if(rows && rows.length) { t.floor = target; if(t.rev != null) t.rev = body.rev; } else failed++;
    } catch { failed++; }
  }
  for(const x of xs) { try { await dbUpdateExpense(x.id, { floor: target }); x.floor = target; } catch { failed++; } }
  try { await _saveManagedFloors(managedFloors.filter(x => floorNorm(x) !== floorNorm(f) && floorNorm(x) !== floorNorm(target)).concat([target])); } catch { failed++; }
  setLoading(false);
  showToast(failed ? failed + ' item(s) could not be updated — refresh and try again.' : 'Floor renamed to "' + target + '".', !failed);
  rerenderAdmin();
}
async function removeFloor(f) {
  if(!_guardSettingsEdit()) return;
  const n = allTenants().filter(t => floorNorm(t.floor) === floorNorm(f)).length, m = expenses.filter(x => floorNorm(x.floor) === floorNorm(f)).length;
  if(n || m) { showToast('"' + f + '" is used by ' + n + ' tenant(s) and ' + m + ' expense(s). Rename it, or move them to another floor first.', false); return; }
  if(!confirm('Remove floor "' + f + '"?')) return;
  try { await _saveManagedFloors(managedFloors.filter(x => floorNorm(x) !== floorNorm(f))); showToast('Floor removed.'); } catch(e) { showToast('Could not save: ' + e.message, false); }
  rerenderAdmin();
}
async function saveGraceDays(days) {
  if(!_guardSettingsEdit()) { rerenderAdmin(); return; }
  const v = Math.min(30, Math.max(0, Math.round(Number(days) || 0)));
  if(v === graceDays) return;
  try { await dbSetSetting('grace_days', String(v)); graceDays = v; showToast(v ? 'Grace period set to ' + v + ' day' + (v !== 1 ? 's' : '') + '.' : 'Grace period removed.'); }
  catch(e) { showToast('Could not save: ' + e.message, false); }
  rerenderAdmin();
}
async function saveAutoBilling(which) {
  if(!_guardSettingsEdit()) { rerenderAdmin(); return; }
  const wantEnabled = document.getElementById('set-auto').checked;
  const wantLead = Math.min(27, Math.max(0, Number(document.getElementById('set-lead').value) || 0));
  try {
    // Write only the setting that changed, on top of the current value of
    // the other one (another device may have changed it).
    await _reloadAutoBillSettings();
    const enabled = which === 'lead' ? autoBilling.enabled : wantEnabled;
    const lead = which === 'enabled' ? autoBilling.leadDays : wantLead;
    if(which === 'lead') await dbSetSetting('auto_billing_lead_days', String(lead));
    else await dbSetSetting('auto_billing', enabled ? 'on' : 'off');
    autoBilling = { enabled, leadDays: lead };
    showToast(enabled ? 'Automatic billing on — posting ' + (lead ? lead + ' days before due.' : 'on the due date.') : 'Automatic billing off.');
    if(enabled) await runAutoBilling();
  } catch(e) { showToast('Save failed: ' + e.message, false); }
  rerenderAdmin();
}

// ─────────────────────────────────────────────
// EXPENSES MODULE — what the building actually spends.
// Once any tenant is on an all-inclusive rate, management shoulders the
// utilities, so collected-vs-spent is the number that tells the landlord
// whether the flat rate is actually profitable. Expenses can be tagged to
// a floor (migration 3) so per-floor income statements carry their direct
// costs; untagged expenses are shared building costs.
// ─────────────────────────────────────────────
const EXPENSE_CATEGORIES = [
  { key:'electricity', label:'Electricity' },
  { key:'water',       label:'Water' },
  { key:'internet',    label:'Internet' },
  { key:'maintenance', label:'Maintenance' },
  { key:'taxes',       label:'Taxes & Fees' },
  { key:'other',       label:'Other' }
];
const _expCatLabel = k => (EXPENSE_CATEGORIES.find(c=>c.key===k)||{label:k||'Other'}).label;
// Table missing (migration 2 not run) vs the floor column missing
// (migration 3 not run). Column errors mention the column, so test them
// first and never mistake them for a missing table.
const _EXP_FLOOR_MISSING = /(column[^]*floor|floor[^]*column|'floor')/i;
const _EXP_TABLE_MISSING = /relation "?(public\.)?expenses"? does not exist|Could not find the table|PGRST205/i;
const _EXP_MISSING = { test: m => !_EXP_FLOOR_MISSING.test(m || '') && _EXP_TABLE_MISSING.test(m || '') };

function _expYM(){ return expenseMonth || _currentYM(); }
function _expensesInMonth(ym) {
  return r2(expenses.reduce((s,x)=>s+((x.expense_date||'').startsWith(ym)?Number(x.amount)||0:0),0));
}
// Dashboard "Log an expense": the log form, not an edit left open earlier.
function logExpenseShortcut(){ _editingExpenseId = null; go('expenses'); }
function setExpenseMonth(v){ expenseMonth = (v && v!==_currentYM()) ? v : ''; _editingExpenseId = null; rerenderAdmin(); }
function shiftExpenseMonth(n){ setExpenseMonth(addYM(_expYM(), n)); }

// Options for a floor dropdown: the whole building, every known floor, and
// "+ Add a floor…" (so a floor is picked, never typed ad hoc).
function _floorOptions(current) {
  const floors = allFloors();
  const cur = current ? (appFloorCanon()(current) || current) : '';
  if(cur && !floors.includes(cur)) floors.push(cur);
  return '<option value=""' + (!cur ? ' selected' : '') + '>Building-wide</option>'
    + floors.map(f => '<option value="' + esc(f) + '"' + (f === cur ? ' selected' : '') + '>' + esc(f) + '</option>').join('')
    + '<option value="__add__">+ Add a floor…</option>';
}
async function expFloorPicked(sel) {
  if(sel.value !== '__add__') { sel.dataset.last = sel.value; return; }
  const name = await addFloorPrompt();
  sel.innerHTML = _floorOptions(name || sel.dataset.last || '');
  sel.dataset.last = sel.value;
}
// Ask for a new floor name and add it to the managed list. Returns the
// canonical name, or '' if cancelled.
async function addFloorPrompt() {
  if(!_guardSettingsEdit()) return '';   // never overwrite a list that failed to load
  const raw = prompt('New floor name (e.g. 6th Floor):', '');
  const v = String(raw || '').trim().replace(/\s+/g, ' ');
  if(!v) return '';
  if(v.length > 40) { showToast('Keep the floor name to 40 characters.', false); return ''; }
  const existing = appFloorCanon()(v);
  if(existing) { showToast('"' + existing + '" already exists — selected it.'); if(!managedFloors.includes(existing)) { try { await _saveManagedFloors(managedFloors.concat([existing])); } catch {} } return existing; }
  try { await _saveManagedFloors(managedFloors.concat([v])); showToast('Floor "' + v + '" added.'); return v; }
  catch(e) { showToast('Could not save the floor: ' + e.message, false); return ''; }
}
function _expFormHtml(idSuffix, x) {
  const today = todayISO();
  const floorField = expensesFloorAvailable !== false
    ? `<div class="field ex-f-floor"><label for="exp-floor-${idSuffix}">Floor</label><select id="exp-floor-${idSuffix}" data-last="${esc(x ? (appFloorCanon()(x.floor || '') || x.floor || '') : '')}" onchange="expFloorPicked(this)">${_floorOptions(x ? x.floor || '' : '')}</select></div>`
    : '';
  return `<div class="ex-form${floorField ? ' has-floor' : ''}">
      <div class="field ex-f-date"><label for="exp-date-${idSuffix}">Date</label><input type="date" id="exp-date-${idSuffix}" value="${esc(x ? x.expense_date : today)}"></div>
      <div class="field ex-f-cat"><label for="exp-cat-${idSuffix}">Category</label>
        <select id="exp-cat-${idSuffix}">${EXPENSE_CATEGORIES.map(c => `<option value="${c.key}"${x && x.category === c.key ? ' selected' : ''}>${c.label}</option>`).join('')}</select>
      </div>
      <div class="field ex-f-amt"><label for="exp-amount-${idSuffix}">Amount</label><div class="ex-peso"><span aria-hidden="true">&#8369;</span><input type="text" id="exp-amount-${idSuffix}" inputmode="decimal" autocomplete="off" placeholder="0" value="${x ? x.amount : ''}"></div></div>
      ${floorField}
      <div class="field ex-f-note"><label for="exp-note-${idSuffix}">Note</label><input type="text" id="exp-note-${idSuffix}" maxlength="200" placeholder="What was it for?" value="${esc(x ? x.note || '' : '')}"></div>
      <div class="ex-f-actions">
      ${x ? `<button type="button" class="btn-sec" onclick="cancelExpenseEdit()">Cancel</button><button type="button" class="btn-pri" data-id="${esc(x.id)}" onclick="saveExpenseEdit(this.dataset.id)">Save</button>`
         : `<button type="button" class="btn-pri" onclick="addExpense()">${icon('plus')}<span>Add</span></button>`}
      </div>
    </div>`;
}

function renderExpensesModule() {
  if(!expensesAvailable) {
    return pageHead('Expenses') + `<div class="card"><div class="exp-setup-note">
      The expenses table doesn't exist in your database yet.<br>
      Run <strong>supabase-migration-2.sql</strong> in the Supabase SQL Editor (Dashboard &gt; SQL Editor), then refresh this page.
    </div></div>`;
  }
  const ym = _expYM(), isCur = ym === _currentYM(), isFuture = ym > _currentYM();
  const monthLabel = fmtYM(ym);
  const monthTotal = _expensesInMonth(ym);
  const prevYM = addYM(ym, -1), prevTotal = _expensesInMonth(prevYM);
  const monthExpenses = expenses
    .filter(x => (x.expense_date || '').startsWith(ym))
    .slice().sort((a, b) => (b.expense_date || '').localeCompare(a.expense_date || ''));
  const catKey = x => EXPENSE_CATEGORIES.some(c => c.key === x.category) ? x.category : 'other';
  const byCat = {};
  monthExpenses.forEach(x => { const k = catKey(x); byCat[k] = r2((byCat[k] || 0) + (Number(x.amount) || 0)); });
  const catMax = Math.max(1, ...Object.values(byCat));
  const loadErrNote = _expensesLoadError
    ? `<div class="exp-setup-note ex-note-err">Expenses could not be loaded just now — the list below may be incomplete. Refresh the page to retry.</div>` : '';
  const floorNote = expensesFloorAvailable === false
    ? `<div class="hint-note">${icon('alert')} To tag expenses by floor, run <strong>supabase-migration-3.sql</strong> in the Supabase SQL Editor and refresh.</div>` : '';
  const showFloor = expensesFloorAvailable !== false;
  const rows = monthExpenses.map(x =>
    _editingExpenseId === x.id
      ? `<div class="ex-edit-row">${_expFormHtml('edit', x)}</div>`
      : `<div class="oa-tr ex-row${showFloor ? '' : ' no-floor'}" data-id="${esc(x.id)}">
          <span class="oa-cell-due">${shortDate(x.expense_date)}</span>
          <span><span class="oa-cat c-${esc(catKey(x))}">${esc(_expCatLabel(x.category))}</span></span>
          <span class="ex-note">${esc(x.note || '') || '<span class="oa-muted-sm">&mdash;</span>'}</span>
          ${showFloor ? `<span class="oa-cell-bill ex-floor">${(x.floor || '').trim() ? esc(x.floor) : 'Building-wide'}</span>` : ''}
          <span class="oa-cell-amt">${peso(x.amount)}</span>
          <button type="button" class="oa-icon-btn ghost sm" aria-label="Actions for this expense" aria-haspopup="menu" onclick="openExpenseMenu(this,this.closest('[data-id]').dataset.id)">${icon('kebab')}</button>
        </div>`).join('');
  const table = `<section class="card oa-table-card ex-month">
      <div class="oa-card-head ex-month-head"><div class="ex-month-nav">
        <button type="button" class="oa-icon-btn" onclick="shiftExpenseMonth(-1)" aria-label="Previous month">${icon('back')}</button>
        <h2 class="card-title">${esc(monthLabel)}</h2>
        <button type="button" class="oa-icon-btn" onclick="shiftExpenseMonth(1)" aria-label="Next month">${icon('next')}</button>
        <label class="ex-jump${_hasMonthInput ? '' : ' is-text'}" title="Jump to a month">${icon('calendar')}<input type="month" id="exp-month-filter" value="${ym}" onclick="try{this.showPicker()}catch(e){}" onchange="setExpenseMonth(this.value)" aria-label="Jump to a month"${_hasMonthInput ? '' : ' placeholder="YYYY-MM"'}></label>
      </div><button type="button" class="link-btn oa-more" onclick="exportExpensesCSV()">${icon('download')}Expenses CSV</button></div>
      ${monthExpenses.length
        ? `<div class="oa-table"><div class="oa-thead ex-row${showFloor ? '' : ' no-floor'}" role="row"><span>Date</span><span>Category</span><span>Note</span>${showFloor ? '<span>Floor</span>' : ''}<span class="r">Amount</span><span></span></div>${rows}</div>`
        : `<div class="oa-empty">No expenses recorded for ${esc(monthLabel)}.</div>`}
      <div class="oa-card-foot"><span>${monthExpenses.length} expense${monthExpenses.length !== 1 ? 's' : ''}</span><strong class="ex-total">Total ${peso(monthTotal)}</strong></div>
    </section>`;
  const cats = Object.keys(byCat).sort((a, b) => byCat[b] - byCat[a]);
  const catCard = `<section class="card ex-cats"><div class="td-card-head"><h2 class="card-title">By category</h2><span class="oa-muted-sm">${_monthName(ym)}</span></div>
      ${cats.length ? cats.map(k => `<div class="ex-cat"><div class="ex-cat-top"><span>${esc(_expCatLabel(k))}</span><strong>${peso(byCat[k])}</strong></div><span class="ex-bar"><i class="c-${k}" style="width:${(byCat[k] / catMax * 100).toFixed(1)}%"></i></span></div>`).join('')
        : '<p class="card-text muted">' + (isCur ? 'Nothing spent this month yet.' : 'Nothing spent in ' + esc(monthLabel) + '.') + '</p>'}
    </section>`;
  const diff = r2(monthTotal - prevTotal);
  const tagged = showFloor ? r2(monthExpenses.filter(x => (x.floor || '').trim()).reduce((s, x) => s + (Number(x.amount) || 0), 0)) : 0;
  const cmpCard = `<section class="card ex-compare">
      <div class="ex-cmp"><span class="oa-muted-sm">${_monthName(prevYM)} total</span><strong>${peso(prevTotal)}</strong>
        <span class="ex-diff${diff > 0.005 ? ' up' : diff < -0.005 ? ' down' : ''}">${Math.abs(diff) < 0.005 ? 'Same as ' + _monthName(prevYM) : _monthName(ym) + (isCur ? ' so far is ' : isFuture ? ' is ' : ' was ') + peso(Math.abs(diff)) + (diff > 0 ? ' higher' : ' lower')}</span></div>
      ${showFloor ? `<div class="ex-cmp"><span class="oa-muted-sm">Tagged to a floor</span><strong>${peso(tagged)}</strong><span class="oa-muted-sm">${peso(r2(monthTotal - tagged))} building-wide</span></div>` : ''}
    </section>`;
  return pageHead('Expenses', esc(monthLabel) + ' · ' + peso(monthTotal) + (isCur ? ' so far' : isFuture ? ' logged' : ' spent'))
    + loadErrNote + floorNote
    + (_editingExpenseId ? '' : `<section class="card ex-log"><h2 class="card-title">Log an expense</h2>${_expFormHtml('new', null)}</section>`)
    + `<div class="ex-grid">${table}<div class="td-col">${catCard}${cmpCard}</div></div>`;
}
function openExpenseMenu(anchor, id) {
  openMenu(anchor, [
    { label: 'Edit', icon: 'edit', fn: () => editExpense(id) },
    { label: 'Delete', icon: 'trash', danger: true, fn: () => deleteExpense(id) }
  ], 'Expense');
}

let _expenseSaving = false;
// Insert/patch an expense; when the floor column doesn't exist yet
// (migration 3 not run) retry without it rather than failing the save.
async function _expenseWrite(fn, rec) {
  try { return await fn(rec); }
  catch(e) {
    if('floor' in rec && _EXP_FLOOR_MISSING.test(e.message||'')) {
      expensesFloorAvailable = false;
      const { floor, ...rest } = rec;
      const r = await fn(rest);
      if(floor) showToast('Saved without the floor tag — run supabase-migration-3.sql to tag expenses by floor.', false);
      return r;
    }
    throw e;
  }
}
function _readExpenseForm(suffix) {
  const date = document.getElementById('exp-date-'+suffix).value;
  const category = document.getElementById('exp-cat-'+suffix).value;
  const amount = normalizeAmount(document.getElementById('exp-amount-'+suffix).value);
  const note = document.getElementById('exp-note-'+suffix).value.trim();
  const floorEl = document.getElementById('exp-floor-'+suffix);
  if(!date){ showToast('Please pick the expense date.', false); return null; }
  if(!amount || amount<=0){ showToast('Please enter a valid amount.', false); return null; }
  const rec = { expense_date: date, category, amount, note };
  if(floorEl && expensesFloorAvailable !== false) rec.floor = floorEl.value === '__add__' ? '' : snapFloor(floorEl.value);
  return rec;
}
async function addExpense() {
  if(_expenseSaving) return; // double-click inserts duplicate rows otherwise
  const rec = _readExpenseForm('new');
  if(!rec) return;
  rec.id = uid();
  _expenseSaving = true;
  try {
    await _expenseWrite(dbInsertExpense, rec);
    if(expensesFloorAvailable === false) delete rec.floor;
    expenses.push(rec);
    // Jump to the month the expense was filed under so it's visible.
    expenseMonth = rec.expense_date.slice(0,7)===_currentYM() ? '' : rec.expense_date.slice(0,7);
    showToast('Expense recorded.');
    rerenderAdmin();
  } catch(e) {
    if(_EXP_MISSING.test(e.message||'')) { expensesAvailable=false; rerenderAdmin(); }
    else showToast('Save failed: '+e.message, false);
  } finally { _expenseSaving = false; }
}
function editExpense(id){ _editingExpenseId = id; rerenderAdmin(); }
function cancelExpenseEdit(){ _editingExpenseId = null; rerenderAdmin(); }
async function saveExpenseEdit(id) {
  const x = expenses.find(x=>x.id===id); if(!x) return;
  const patch = _readExpenseForm('edit');
  if(!patch) return;
  try {
    await _expenseWrite(p => dbUpdateExpense(id, p), patch);
    if(expensesFloorAvailable === false) delete patch.floor;
    Object.assign(x, patch);
    _editingExpenseId = null;
    showToast('Expense updated.');
    rerenderAdmin();
  } catch(e) { showToast('Save failed: '+e.message, false); }
}
async function deleteExpense(id) {
  if(!confirm('Delete this expense?')) return;
  try {
    await dbDeleteExpense(id);
    expenses = expenses.filter(x=>x.id!==id);
    if(_editingExpenseId===id) _editingExpenseId = null;
    showToast('Expense deleted.');
    rerenderAdmin();
  } catch(e) { showToast('Delete failed: '+e.message, false); }
}
function exportExpensesCSV() {
  if(!expenses.length){ showToast('No expenses to export yet.', false); return; }
  const rows = [['Date','Category','Amount','Floor','Note']];
  expenses.slice().sort((a,b)=>(a.expense_date||'').localeCompare(b.expense_date||''))
    .forEach(x=>rows.push([x.expense_date||'', _expCatLabel(x.category), x.amount, x.floor||'', x.note||'']));
  _downloadCSV(rows, 'expenses-'+todayISO()+'.csv');
  showToast('Expenses CSV exported ✓');
}


// ─────────────────────────────────────────────
// INSIGHTS MODULE
// Answers five questions, each in the form that fits it: how the business
// did (KPI tiles vs the previous period), how revenue and costs moved
// (monthly columns), how old the money owed is (aging bars), where the
// money goes (expense mix + utility recovery), and which floors and
// tenants drive it (tables). One period selector scopes everything.
// Figures reuse computeIncomeStatement, so they tie out to the reports.
// ─────────────────────────────────────────────
const INSIGHT_WINDOWS = { '3m':'3 months', '6m':'6 months', '12m':'12 months', 'ytd':'Year to date' };
let insightWindow = '12m';

// The income statement's saved "spread rent over each cycle" choice (off by default:
// each charge counts in its billing month).
function _incStmtProrate() {
  try { const p = JSON.parse(localStorage.getItem(INCSTMT_PREFS_KEY)); if(p && typeof p.spread === 'boolean') return p.spread; } catch {}
  return false;
}
function _insightRange(win) {
  const cur = _currentYM();
  const back = win === '3m' ? 2 : win === '12m' ? 11 : 5;
  const from = win === 'ytd' ? cur.slice(0, 4) + '-01' : addYM(cur, -back);
  const n = ymRange(from, cur).length;
  return { from, to: cur, prevFrom: addYM(from, -n), prevTo: addYM(from, -1), n };
}
function _niceStep(raw) {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(raw, 1))));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}
function _compactPeso(v) {
  const a = Math.abs(v);
  const s = a >= 1e6 ? (a / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M' : a >= 1e3 ? (a / 1e3).toFixed(a >= 1e4 ? 0 : 1) + 'k' : String(Math.round(a));
  return (v < 0 ? '−' : '') + '₱' + s.replace(/\.0(?=[kM])/, '');
}






// Utilities billed back to tenants: collected for the provider, so kept
// out of revenue (IFRS 15 — the landlord acts as agent) and shown here.
function _passThroughCard(acc) {
  const P = acc.total.passThrough;
  if(!(P.billed > 0.005 || P.settled > 0.005 || P.outstanding > 0.005)) return '';
  const T = acc.total;
  const utilSpent = r2(['electricity', 'water', 'internet'].reduce((s, k) => s + T.direct[k] + T.shared[k], 0));
  return '<section class="card"><div class="card-head"><h2 class="card-title">Utilities billed back</h2></div>'
    + '<p class="card-text">Electricity, water and similar bills charged to tenants are collected for the provider — pass-through, not revenue (IFRS 15, agent). They are kept out of revenue, and the utility costs they reimburse are reduced by the same amount, so only the part tenants don\'t pay back counts as an expense.</p>'
    + '<div class="mini-stats"><div><span class="muted">Billed to tenants</span><strong>' + peso(P.billed) + '</strong></div>'
    + '<div><span class="muted">Settled</span><strong>' + peso(P.settled) + '</strong></div>'
    + '<div><span class="muted">Still unpaid</span><strong>' + peso(P.outstanding) + '</strong></div></div>'
    + (utilSpent > 0 ? '<p class="card-text muted">Utility costs paid (Expenses): ' + peso(utilSpent) + '; ' + peso(T.recovered.total) + ' offset by billings to tenants, ' + peso(r2(utilSpent - T.recovered.total)) + ' borne by the property.</p>' : '')
    + '</section>';
}


function _punctualityCard(rg, today) {
  const rel = paymentReliability(allTenants(), rg.from, rg.to, today, graceDays);
  const n = rel.reduce((s, r) => s + r.n, 0);
  if(!n) return '<section class="card"><div class="card-head"><h2 class="card-title">Payment punctuality</h2></div><div class="empty-inline">No bills have fallen due in this period yet.</div></section>';
  const unpaidN = rel.reduce((s, r) => s + (r.unpaidLate || 0), 0);
  const onTime = rel.reduce((s, r) => s + (r.n - r.late), 0);
  const pct = Math.round(onTime / n * 100);
  const late = rel.filter(r => r.late > 0).sort((a, b) => (b.late / b.n) * b.avgLate - (a.late / a.n) * a.avgLate).slice(0, 8);
  const rows = late.map(r => {
    const t = tenants.find(x => x.id === r.id);
    const owed = t ? tenantSummary(t).open : 0;
    return '<tr><td>' + (t ? '<a href="#/tenants/' + encodeURIComponent(r.id) + '">' + esc(r.name) + '</a>' : esc(r.name) + ' <span class="muted">(archived)</span>') + '<div class="muted">Unit ' + esc(r.unit) + '</div></td>'
      + '<td><div class="meter sm" title="' + r.onTimePct + '% on time"><span style="width:' + r.onTimePct + '%"></span></div><div class="muted">' + (r.n - r.late) + ' of ' + r.n + ' on time</div></td>'
      + '<td class="num">' + r.avgLate + ' day' + (r.avgLate !== 1 ? 's' : '') + (r.unpaidLate ? '<div class="muted">' + r.unpaidLate + ' still unpaid</div>' : '') + '</td>'
      + '<td class="num">' + (owed ? peso(owed) : '<span class="muted">&mdash;</span>') + '</td></tr>';
  }).join('');
  return '<section class="card"><div class="card-head"><h2 class="card-title">Payment punctuality</h2></div>'
    + '<p class="card-text"><strong>' + pct + '%</strong> of ' + n + ' bill' + (n !== 1 ? 's' : '') + ' due in this period were paid on or before the due date' + (graceDays ? ' (or within the ' + graceDays + '-day grace period)' : '')
    + (unpaidN ? ' (' + unpaidN + ' past due and still unpaid count as late)' : '') + '.'
    + (late.length ? ' Late payers, most habitual first:' : ' Nobody paid late.') + '</p>'
    + (late.length ? '<div class="table-scroll"><table class="mini-table"><thead><tr><th>Tenant</th><th>On time</th><th class="num">Avg. late by</th><th class="num">Owes now</th></tr></thead><tbody>' + rows + '</tbody></table></div>' : '')
    + '</section>';
}

// billTotalPaid / billRemaining / billCategory / BILL_CATEGORIES live in
// billing-core.js (shared with the reconciliation engine).

// Unpaid remainder per category (mirrors the Math.max(0, billRemaining) rule
// used everywhere outstanding balances are summed).
function outstandingByCategory(bills) {
  const out = { rent:0, utilities:0, other:0, total:0 };
  (bills||[]).forEach(b=>{
    if(b.status==='paid') return;
    const rem = Math.max(0, billRemaining(b));
    if(!rem) return;
    out[billCategory(b)] += rem;
    out.total += rem;
  });
  return out;
}

// ─────────────────────────────────────────────
// SAFE BILL WRITES + RE-RENDER
// ─────────────────────────────────────────────
// Copy → save to DB → commit to local state only on success, so a failed
// request never leaves the UI showing unsaved data.
// Forms remember the tenant object they were drawn from. When the row is
// reloaded (another device changed it and a save hit a rev conflict), the
// object in `tenants` is replaced — so a form still showing the old row
// would write stale fields back, or a remembered bill index could now
// point at a different bill. Such a save is refused instead.
let _editingT = null;   // Edit-tenant form (profile fields)
let _billListT = null;  // bill list inside the edit modal
let _tmplListT = null;  // recurring-charge list inside the edit modal
function _formStale(expectT) {
  if(!expectT) return false;
  if(tenants.find(x => x.id === expectT.id) === expectT) return false;
  showToast('This tenant was changed on another tab or device while this was open. The latest data is loaded — please redo your change.', false);
  return true;
}

async function saveBills(tid, mutate, toastMsg, expectT) {
  await _autoBillIdle(); // never build a write on a row a background run is changing
  return _withTenantLock(tid, async () => {
    if(expectT && _formStale(expectT)){ rerenderAdmin(); return 'conflict'; }
    const t = tenants.find(t=>t.id===tid);
    if(!t) return false;
    const billsCopy = structuredClone(t.bills);
    mutate(billsCopy);
    if(JSON.stringify(billsCopy) === JSON.stringify(t.bills)) return true; // nothing to write
    try {
      await dbUpdateTenantGuarded(t, {bills: billsCopy});
      t.bills = billsCopy;
      if(toastMsg) showToast(toastMsg);
      return true;
    } catch(e) {
      showToast(e.conflict ? e.message : 'Save failed: '+e.message, false);
      if(e.conflict){ rerenderAdmin(); return 'conflict'; }
      return false;
    }
  });
}

// ─────────────────────────────────────────────
// F-12: UNIFIED DUE STATUS UTILITY
// ─────────────────────────────────────────────
function getDueStatus(bill) {
  if(bill.status === 'paid') return 'paid';
  // Logged payments already cover it (a legacy row, or an edit elsewhere).
  if(Number(bill.amount) > 0 && billOpen(bill) <= 0.005) return 'paid';
  // No amount yet (a metered placeholder): never late, it needs a reading.
  if(billAwaitingAmount(bill)) return 'awaiting';
  // No due date: honour a legacy manual 'overdue' flag, otherwise unscheduled.
  if(!bill.due) return bill.status === 'overdue' ? 'overdue' : 'no-date';
  const today = new Date(); today.setHours(0,0,0,0);
  const in3   = new Date(today); in3.setDate(in3.getDate()+3);
  const d     = new Date(bill.due+'T00:00:00');
  if(d < today) {
    const g = new Date(d); g.setDate(g.getDate() + graceDays);
    return g >= today ? 'grace' : 'overdue';
  }
  if(d.getTime()===today.getTime()) return 'due-today';
  if(d <= in3)                   return 'due-soon';
  return 'upcoming';
}
function getDueUrgencyScore(bill) {
  const s = getDueStatus(bill);
  if(s==='overdue'){
    // Older overdue sorts first. Math.round, not floor: both timestamps are
    // local midnights, so a DST change makes the diff 23h/25h per boundary
    // and floor would be off by one.
    const today=new Date(); today.setHours(0,0,0,0);
    const days = bill.due ? Math.round((today-new Date(bill.due+'T00:00:00'))/86400000) : 0;
    return -days;
  }
  if(s==='grace')     return 0.5;
  if(s==='due-today') return 1;
  if(s==='due-soon')  return 2;
  if(s==='upcoming'){
    const today=new Date(); today.setHours(0,0,0,0);
    return 3+Math.round((new Date(bill.due+'T00:00:00')-today)/(86400000));
  }
  if(s==='awaiting') return 800;
  if(s==='no-date') return 900;
  return 1000; // paid sorts last
}
// Days a bill is past due (0 if not overdue / no due date)
function daysOverdue(bill) {
  if(bill.status==='paid' || !bill.due) return 0;
  const today = new Date(); today.setHours(0,0,0,0);
  const d = new Date(bill.due+'T00:00:00');
  return d < today ? Math.round((today-d)/86400000) : 0;
}

// Maps ordinal unit names/numbers to a sortable integer
function unitRank(unit) {
  const s = unit.toLowerCase().trim();
  const words = {'first':1,'second':2,'third':3,'fourth':4,'fifth':5,
                 'sixth':6,'seventh':7,'eighth':8,'ninth':9,'tenth':10};
  for (const [w,n] of Object.entries(words)) { if(s.includes(w)) return n; }
  const m = s.match(/([0-9]+)/);
  return m ? parseInt(m[1]) : 999;
}
// Floor labels rank like units, except ground floor sorts first.
function floorRank(s) {
  return /\bground\b|^g\/?f\b/i.test(s) ? 0 : unitRank(s);
}
// One spelling per floor across tenants (active first) and expense tags —
// '3rd floor' and '3rd Floor' are the same floor (see floorCanon).
function appFloorCanon() {
  return floorCanon(managedFloors.concat(allTenants().map(t => t.floor), expenses.map(x => x.floor)));
}
// Snap a typed floor to the spelling already in use, if any.
function snapFloor(s) {
  const v = String(s || '').trim().replace(/\s+/g, ' ');
  return v ? (appFloorCanon()(v) || v) : '';
}
function _fillFloorSelect(cur) {
  const sel = document.getElementById('m-floor');
  if(!sel) return;
  sel.innerHTML = _floorOptions(cur).replace('>Building-wide<', '>No floor<');
  sel.dataset.last = sel.value;
}
async function tenantFloorPicked(sel) {
  if(sel.value !== '__add__') { sel.dataset.last = sel.value; return; }
  const name = await addFloorPrompt();
  _fillFloorSelect(name || sel.dataset.last || '');
}
// Distinct floor labels currently in use, in floor order.
function floorList() {
  const canon = appFloorCanon();
  const set = new Set();
  tenants.forEach(t=>{ const f=canon(t.floor); if(f) set.add(f); });
  return Array.from(set).sort((a,b)=>floorRank(a)-floorRank(b) || a.localeCompare(b));
}

// ── BILLS TABLE (Billing module) ──
function loadMoreTableRows() { tableRowLimit += 50; renderBillRows(); }

function sortTable(col) {
  if (tableSortCol === col) { tableSortDir = tableSortDir === 'asc' ? 'desc' : 'asc'; }
  else { tableSortCol = col; tableSortDir = 'asc'; }
  tableRowLimit = 50; // reset cap so a fresh sort always starts at the top
  renderBillRows();
}

let tableRowLimit = 50; // initial cap for table rows
const _isPhone = () => window.innerWidth <= 768;

// rows: [{tenant, bill, bi, former}] from billRowsForView(). One grid of
// rows (cards on phones) with a checkbox column for bulk actions.
function renderTableView(c, rows) {
  // Sort by selected column. Rows with no date always sort last, in either
  // direction, so "sort by paid date" doesn't bury real data under blanks.
  const dir = tableSortDir === 'asc' ? 1 : -1;
  const cmpDate = (av, bv) => {
    if (!av && !bv) return 0;
    if (!av) return 1;
    if (!bv) return -1;
    return av.localeCompare(bv) * dir;
  };
  rows.sort((a, b) => {
    let r = 0;
    switch (tableSortCol) {
      case 'status':    r = (getDueUrgencyScore(a.bill) - getDueUrgencyScore(b.bill)) * dir; break;
      case 'tenant':    r = a.tenant.name.localeCompare(b.tenant.name) * dir; break;
      case 'unit':      r = (unitRank(a.tenant.unit) - unitRank(b.tenant.unit)) * dir; break;
      case 'floor':     r = (floorRank(floorKey(a.tenant)||'zz') - floorRank(floorKey(b.tenant)||'zz')) * dir; break;
      case 'label':     r = (a.bill.label || '').localeCompare(b.bill.label || '') * dir; break;
      case 'amount':    r = ((Number(a.bill.amount) || 0) - (Number(b.bill.amount) || 0)) * dir; break;
      case 'remaining': r = (billOpen(a.bill) - billOpen(b.bill)) * dir; break; // paid bills owe 0
      case 'shown':     r = (_billShownAmt(a.bill) - _billShownAmt(b.bill)) * dir; break; // the Amount column
      case 'due':       r = cmpDate(a.bill.due, b.bill.due); break;
      case 'paidDate':  r = cmpDate(a.bill.paidDate, b.bill.paidDate); break;
      case 'remark':    r = (a.bill.remark || '').localeCompare(b.bill.remark || '') * dir; break;
    }
    // Stable tie-breakers: unit, then due date.
    if (r === 0) r = unitRank(a.tenant.unit) - unitRank(b.tenant.unit);
    if (r === 0) r = cmpDate(a.bill.due, b.bill.due);
    return r;
  });

  const totalRows = rows.length;
  const capped = rows.slice(0, tableRowLimit);
  const key = r => r.tenant.id + '|' + r.bi;
  // Only unpaid bills with an amount can be selected; the selection holds
  // rows still on screen, and only while each still is the same bill.
  const selectable = r => !r.former && r.bill.status !== 'paid' && getDueStatus(r.bill) !== 'awaiting';
  const live = new Map(capped.filter(selectable).map(r => [key(r), r.bill]));
  billSelection.forEach((b, k) => { if(live.get(k) !== b) billSelection.delete(k); });
  // Just-paid rows (paid rows outside the Paid / All views) are not part of
  // the count or the total.
  const jpRow = r => billView !== 'paid' && billView !== 'all' && r.bill.status === 'paid';
  const nJp = rows.filter(jpRow).length;
  const sum = r2(rows.reduce((s, r) => s + (jpRow(r) ? 0 : _billShownAmt(r.bill)), 0));
  const selRows = capped.filter(r => billSelection.has(key(r)));
  const selSum = r2(selRows.reduce((s, r) => s + billOpen(r.bill), 0));
  const allSel = live.size > 0 && selRows.length === live.size;
  const kind = b => { const c = billCategory(b); return c === 'rent' ? 'Rent' : c === 'utilities' ? 'Utility' : 'Other charge'; };
  const th = (col, label, cls) => {
    const active = tableSortCol === col;
    return '<span class="oa-thc' + (cls ? ' ' + cls : '') + '" role="columnheader" aria-sort="' + (active ? (tableSortDir === 'asc' ? 'ascending' : 'descending') : 'none') + '">'
      + '<button type="button" class="oa-th' + (active ? ' on' : '') + '" data-col="' + col + '" onclick="sortTable(\'' + col + '\')">' + label
      + (active ? '<span class="sort-arrow" aria-hidden="true">' + (tableSortDir === 'asc' ? '↑' : '↓') + '</span>' : '') + '</button></span>';
  };
  const check = (on, attrs, label, role) => '<label class="oa-check" role="' + (role || 'cell') + '"><input type="checkbox"' + (on ? ' checked' : '') + attrs + '><span class="oa-check-box" aria-hidden="true">' + icon('check') + '</span><span class="sr-only">' + label + '</span></label>';
  const head = selRows.length
    ? '<div class="oa-thead bl-row bl-bulk" role="row">' + check(allSel, ' onchange="billSelectAll(this.checked)"', 'Select all', 'columnheader')
      + '<div class="bl-bulk-bar" role="cell"><strong>' + selRows.length + ' selected · ' + peso(selSum) + '</strong>'
      + '<button type="button" class="btn-pri" onclick="bulkMarkPaid()">' + icon('check') + '<span>Mark paid</span></button>'
      + '<button type="button" class="btn-sec" onclick="bulkCopyReminders()">' + icon('chat') + '<span>Copy reminders</span></button>'
      + '<button type="button" class="btn-sec" onclick="billSelection.clear();renderBillRows()">Clear</button></div></div>'
    : '<div class="oa-thead bl-row" role="row">' + check(false, live.size ? ' onchange="billSelectAll(this.checked)"' : ' disabled', 'Select all', 'columnheader')
      + th('tenant', 'Tenant') + th('label', 'Bill') + th('due', 'Due', 'c-due') + th('status', 'Status') + th('shown', 'Amount', 'r') + '<span role="columnheader"><span class="sr-only">Actions</span></span></div>';
  const phoneSort = _isPhone() ? '<div class="bl-phone-sort"><select class="tb-select sm" aria-label="Sort bills" onchange="tableSortCol=this.value;tableSortDir=(this.value===\'remaining\'||this.value===\'paidDate\')?\'desc\':\'asc\';renderBillRows()">'
    + [['due','Due date'],['status','Urgency'],['tenant','Tenant'],['unit','Unit'],['remaining','Balance'],['paidDate','Paid date']].map(([k,l]) => '<option value="'+k+'"'+(tableSortCol===k?' selected':'')+'>Sort: '+l+'</option>').join('') + '</select></div>' : '';

  const body = capped.map(r => {
    const b = r.bill, t = r.tenant, k = key(r);
    const isPaid = b.status === 'paid';
    const jpe = !r.former && _justPaidEntry(t.id, r.bi), jp = !!jpe;
    const aw = getDueStatus(b) === 'awaiting';
    const where = 'Unit ' + esc(t.unit) + (r.former ? ' · moved out' : t.floor ? ' · ' + esc(t.floor) : '');
    const remark = b.remark && !/pending amount/i.test(b.remark) ? esc(b.remark) : '';
    const rest = [billPeriod(b) ? fmtYM(billPeriod(b), 'short') : '', billTotalPaid(b) > 0.005 && !isPaid ? peso(billTotalPaid(b)) + ' received' : '', remark].filter(Boolean).join(' · ');
    const sub = '<span class="bl-kind">' + kind(b) + (rest ? ' · ' : '') + '</span>' + rest;
    const amt = aw ? '<button type="button" class="link-btn" onclick="const x=this.closest(\'[data-tid]\');openEditBillFromTable(x.dataset.tid,+x.dataset.bi)">Enter amount</button>'
      : r.former ? peso(billOpen(b))
      : '<span class="td-amt-edit" data-tid="' + esc(t.id) + '" data-bi="' + r.bi + '" onclick="enterAmountEdit(this)" title="Click to edit the amount">' + peso(jpe ? jpe.open : _billShownAmt(b)) + '</span>';
    const pill = isPaid && !jp && b.paidDate ? oaPill('paid', 'Paid · ' + shortDate(b.paidDate)) : billPill(b, jp);
    return '<div class="oa-tr bl-row' + (billSelection.has(k) ? ' is-sel' : '') + (jp ? ' is-paid' : '') + '" role="row" data-tid="' + esc(t.id) + '" data-bi="' + r.bi + '">'
      + (selectable(r) ? check(billSelection.has(k), ' data-k="' + esc(k) + '" onchange="billSelectToggle(this.dataset.k,this.checked)"', 'Select ' + esc(b.label) + ' for ' + esc(t.name)) : '<span role="cell"></span>')
      + '<div class="oa-who" role="cell">' + avatar(t.name, 38) + '<div class="oa-who-text">' + (r.former ? '<span class="oa-name">' + esc(t.name) + '</span>' : '<a class="oa-name" href="#/tenants/' + encodeURIComponent(t.id) + '">' + esc(t.name) + '</a>') + '<span class="oa-sub">' + where + '</span></div></div>'
      + '<div class="bl-bill" role="cell"' + (remark ? ' title="' + remark + '"' : '') + '><span class="bl-bill-label">' + esc(b.label || 'Bill') + (billPeriod(b) && b.tmplId ? ' <span title="Recurring charge">' + icon('repeat', 'ico-xs') + '</span>' : '') + '</span><span class="oa-sub">' + sub + '</span></div>'
      + '<span class="oa-cell-due" role="cell">' + (b.due ? shortDateY(b.due) : '&mdash;') + '</span>'
      + '<span class="oa-cell-status" role="cell">' + pill + '</span>'
      + '<span class="oa-cell-amt" role="cell">' + amt + '</span>'
      + '<span class="bl-act" role="cell">' + (r.former ? '<span class="oa-muted-sm bl-moved" title="Restore the tenant (Tenants › Archived) to change this bill">&mdash;</span>'
        : jp ? '<button type="button" class="oa-btn-undo sm" onclick="const x=this.closest(\'[data-tid]\');undoJustPaid(x.dataset.tid,+x.dataset.bi)">Undo</button>'
        : '<button type="button" class="oa-icon-btn ghost sm" aria-label="Actions for ' + esc(b.label || 'bill') + '" aria-haspopup="menu" onclick="const x=this.closest(\'[data-tid]\');openBillMenu(this,x.dataset.tid,+x.dataset.bi)">' + icon('kebab') + '</button>')
      + '</span></div>';
  }).join('');
  const more = totalRows > tableRowLimit ? '<button type="button" class="btn-sec" onclick="loadMoreTableRows()">Show more (' + (totalRows - tableRowLimit) + ' remaining)</button>' : '';
  const nBills = totalRows - nJp;
  c.innerHTML = phoneSort + '<div class="oa-table" role="table" aria-label="Bills">' + head + body + '</div>'
    + '<div class="oa-card-foot"><span>' + (capped.length < totalRows ? 'Showing ' + capped.length + ' of ' + totalRows + ' · ' : '') + nBills + ' bill' + (nBills !== 1 ? 's' : '') + ' · ' + peso(sum) + (nJp ? ' · ' + nJp + ' just marked paid' : '') + '</span>' + more
    + '<button type="button" class="link-btn oa-more" onclick="exportCSV()">' + icon('download') + 'Bills CSV</button></div>';
}
// The amount a bills-table row shows: the face amount once paid, else what is still owed.
function _billShownAmt(b) { return b.status === 'paid' ? Number(b.amount) || 0 : billOpen(b); }
function _billAtKey(k) {
  const i = k.lastIndexOf('|'), tid = k.slice(0, i), bi = Number(k.slice(i + 1));
  const t = tenants.find(x => x.id === tid);
  return { tid, bi, t, bill: t && t.bills[bi] };
}
function billSelectToggle(k, on) {
  const x = _billAtKey(k);
  if(on && x.bill) billSelection.set(k, x.bill); else billSelection.delete(k);
  renderBillRows();
}
function billSelectAll(on) {
  if(!on) billSelection.clear();
  else document.querySelectorAll('#bill-rows .oa-tr [data-k]').forEach(el => { const x = _billAtKey(el.dataset.k); if(x.bill) billSelection.set(el.dataset.k, x.bill); });
  renderBillRows();
}
function _selectedBills() {
  return Array.from(billSelection).map(([k, bill]) => {
    const x = _billAtKey(k);
    return x.bill && x.bill === bill && bill.status !== 'paid' ? x : null;
  }).filter(Boolean);
}
// Bulk "Mark paid": one paid date for every selected bill (the same
// confirm-paid dialog as a single bill), saved tenant by tenant.
function bulkMarkPaid() {
  const items = _selectedBills().filter(x => !billAwaitingAmount(x.bill));
  if(!items.length) { showToast('Nothing to mark paid — enter the amount on bills that need one first.', false); return; }
  _pendingPaid = { bulk: items };
  document.getElementById('paiddate-bill-name').textContent = items.length + ' bill' + (items.length !== 1 ? 's' : '') + ' — ₱' + fmtMoney(r2(items.reduce((s, x) => s + billOpen(x.bill), 0)));
  document.getElementById('paiddate-input').value = todayISO();
  openModal('paiddate-modal');
}
async function _confirmBulkPaid(dateVal) {
  const items = _pendingPaid.bulk;
  const byT = new Map();
  items.forEach(it => { if(!byT.has(it.tid)) byT.set(it.tid, []); byT.get(it.tid).push(it); });
  let done = 0, skipped = 0, conflicts = 0;
  const failedItems = [];
  for(const [tid, list] of byT) {
    const live = tenants.find(x => x.id === tid);
    const ok = list.filter(it => live && live === it.t && live.bills[it.bi] === it.bill && it.bill.status !== 'paid' && !billAwaitingAmount(it.bill));
    skipped += list.length - ok.length;
    if(!ok.length) continue;
    const res = await saveBills(tid, bills => ok.forEach(it => { const x = bills[it.bi]; if(x && x.status !== 'paid') { x.status = 'paid'; x.paidDate = dateVal; } }), null, live);
    if(res === true) { done += ok.length; ok.forEach(it => _noteJustPaid(tid, it.bi)); }
    else if(res === 'conflict') conflicts += ok.length;
    else failedItems.push(...ok);
  }
  // Bills that failed to save stay selected (and in the dialog) for a retry.
  billSelection.clear();
  failedItems.forEach(it => billSelection.set(it.tid + '|' + it.bi, it.bill));
  const failed = failedItems.length, changed = skipped + conflicts;
  const s = n => n + ' bill' + (n !== 1 ? 's' : '');
  if(done) showToast('Marked ' + s(done) + ' paid ✓'
    + (failed ? ' · ' + s(failed) + ' could not be saved (still selected) — try again.' : '')
    + (changed ? ' · ' + changed + ' not changed — they changed in the meantime.' : ''), !(failed + changed));
  else if(changed && !failed) showToast('Nothing was changed — the bills changed in the meantime.', false);
  else if(failed && changed) showToast(s(failed) + ' could not be saved (still selected) · ' + changed + ' changed in the meantime.', false);
  // failed only: saveBills already showed "Save failed: …".
  if(failed && !done && !changed) { _pendingPaid.bulk = failedItems; return false; }
  return true;
}
// One message per tenant with selected bills, copied together.
async function bulkCopyReminders() {
  const ids = Array.from(new Set(_selectedBills().map(x => x.tid)));
  const texts = ids.map(id => buildReminderText(tenants.find(t => t.id === id))).filter(Boolean);
  if(!texts.length) { showToast('No outstanding balance to remind about.'); return; }
  const text = texts.join('\n\n———\n\n');
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px;';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch { ta.remove(); showToast('Could not copy automatically.', false); return; }
    ta.remove();
  }
  showToast(texts.length + ' reminder' + (texts.length !== 1 ? 's' : '') + ' copied — paste into SMS / Messenger / Viber.');
}

// Receipts on a tenant's bills: one Receive-payment receipt spread over
// several bills is one entry (rid); other payments one entry each; a bill
// marked paid beyond its logged payments adds its implied payment.
function tenantReceipts(t) {
  const receipts = [], byRid = new Map();
  (t.bills || []).forEach(b => {
    let logged = 0;
    (b.payments || []).forEach(pay => {
      const v = Number(pay.amount) || 0; logged += v;
      if(!v) return;
      if(pay.rid && v > 0) {
        let g = byRid.get(pay.rid);
        if(!g) { g = { t, date: isoOrEmpty(pay.date), dates: new Set(), amount: 0, note: pay.note || '', bills: [], rid: pay.rid }; byRid.set(pay.rid, g); receipts.push(g); }
        g.dates.add(isoOrEmpty(pay.date));
        g.amount = r2(g.amount + v);
        if(!g.bills.includes(b)) g.bills.push(b);
      } else receipts.push({ t, date: isoOrEmpty(pay.date), amount: v, note: pay.note || '', bills: [b] });
    });
    if(b.status === 'paid') { const resid = r2((Number(b.amount) || 0) - logged); if(resid > 0) receipts.push({ t, date: isoOrEmpty(b.paidDate), amount: resid, note: '', bills: [b] }); }
  });
  return receipts.sort((x, y) => (y.date || '').localeCompare(x.date || ''));
}
// "Rent – Sep, Water – Aug" (no month suffix when the label already names one).
function receiptAppliedTo(x) {
  return x.bills.map(b => { const per = billPeriod(b), m = per ? _monthName(per, 'short') : '';
    return esc(b.label) + (m && !new RegExp('\\b(' + m + '|' + _monthName(per) + '|' + per.slice(0, 4) + ')\\b', 'i').test(b.label || '') ? ' – ' + m : ''); }).join(', ');
}
function _recentPaymentsCard() {
  const today = todayISO(), since = addDaysISO(today, -6);
  const recent = tenants.flatMap(tenantReceipts).filter(x => x.date && x.date >= since && x.date <= today && x.amount > 0).sort((a, b) => b.date.localeCompare(a.date));
  const total = r2(recent.reduce((s, x) => s + x.amount, 0));
  const shown = recent.slice(0, 10);
  return '<section class="card oa-table-card bl-recent">'
    + '<div class="oa-card-head"><h2 class="card-title">Recent payments</h2><span class="oa-muted-sm">Last 7 days · ' + peso(total) + '</span></div>'
    + (shown.length ? '<div class="oa-table"><div class="oa-thead bl-pay" role="row"><span>Date</span><span>Tenant</span><span>Applied to</span><span>Note</span><span class="r">Amount</span></div>'
      + shown.map(x => '<div class="oa-tr bl-pay"><span class="oa-cell-due">' + shortDate(x.date) + '</span>'
        + '<div class="oa-who">' + avatar(x.t.name, 30) + '<a class="oa-name" href="#/tenants/' + encodeURIComponent(x.t.id) + '">' + esc(x.t.name) + '</a></div>'
        + '<span class="oa-cell-bill">' + receiptAppliedTo(x) + '</span><span class="oa-cell-bill bl-note">' + (x.note ? esc(x.note) : '&mdash;') + '</span>'
        + '<span class="oa-cell-amt good">' + peso(x.amount) + '</span></div>').join('') + '</div>'
      : '<div class="oa-empty">No payments recorded in the last 7 days.</div>')
    + '</section>';
}

// ── INLINE TABLE EDITING ──
// Open the tenant edit modal directly on the Bills tab and scroll to the bill.
// Always force-render all paid bills so that targeting a paid bill outside the
// default 3-row preview still works.
function openEditBillFromTable(tid, bi){
  openEditModal(tid, 'bills');
  renderBillListItems(true);
  editBillInline(bi);
  const target = document.getElementById('bill-edit-inline-'+bi);
  if(target && target.scrollIntoView) setTimeout(()=>target.scrollIntoView({behavior:'smooth', block:'center'}), 60);
}

// Convert an amount cell into an inline input. Enter or blur saves; Escape cancels.
function enterAmountEdit(td){
  if(td.querySelector('input')) return; // already editing
  const tid = td.dataset.tid;
  const bi  = Number(td.dataset.bi);
  const t = tenants.find(t=>t.id===tid);
  if(!t || !t.bills[bi]) return;
  const original = Number(t.bills[bi].amount);
  td._tenant = t;
  td.dataset.prev = td.innerHTML; // what the cell showed (a balance, or the amount)
  const got = billTotalPaid(t.bills[bi]);
  td.innerHTML = '<input type="text" inputmode="decimal" value="'+original+'" aria-label="Bill amount"'
    + (got > 0.005 ? ' title="Full bill amount (₱' + fmtMoney(got) + ' received so far)"' : '') + ' '
    + 'class="td-amt-input" onblur="commitAmountEdit(this)" '
    + 'onkeydown="if(event.key===\'Enter\'){this.blur();}else if(event.key===\'Escape\'){this.dataset.cancel=\'1\';this.blur();}">';
  const input = td.querySelector('input');
  input.focus();
  input.select();
}

// After a bill's amount changes, keep its paid status in step with the
// logged payments: covered → paid (on the last payment's date); a bill
// that was settled by its payments and now costs more → open again (no
// phantom cash for the difference). A bill marked paid without logged
// payments stays as the admin set it. Returns 'paid' | 'reopened' | ''.
function _resyncPaidStatus(b, prevAmt) {
  const amt = Number(b.amount) || 0;
  if(amt > 0 && /pending amount/i.test(b.remark || '')) b.remark = '';
  if(amt === Number(prevAmt) || !(b.payments || []).length) return '';
  const paid = billTotalPaid(b);
  if(b.status !== 'paid' && amt > 0 && paid >= amt - 0.005) {
    b.status = 'paid';
    b.paidDate = b.payments.map(p => p.date).filter(Boolean).sort().pop() || todayISO();
    return 'paid';
  }
  if(b.status === 'paid' && amt > paid + 0.005 && Number(prevAmt) <= paid + 0.005) {
    b.status = 'unpaid'; b.paidDate = '';
    return 'reopened';
  }
  return '';
}

// Change a template's amount, remembering the old one for cycles before
// the change so past (unbilled) cycles keep their price. The old rate
// covers everything up to the last posted cycle or last month.
function _recordRateChange(t, tmpl, newAmt) {
  const old = tmplRate(tmpl);
  // A correction of an amount never billed (a typo) isn't history.
  // Cycles already posted keep their bill's amount; unbilled cycles up to
  // last month were priced at the old rate, from this month on the new one.
  const until = addYM(_currentYM(), -1);
  const billedAtOld = old > 0 && templateBills(t, tmpl, false).all.some(i => {
    const b = t.bills[i] || {}; const p = billPeriod(b);
    return isYM(p) && p <= until && r2(b.amount) === old;
  });
  if(billedAtOld && r2(newAmt) !== old) {
    const hist = (Array.isArray(tmpl.rates) ? tmpl.rates : []).filter(r => r && isYM(r.until));
    const maxUntil = hist.reduce((m, r) => r.until > m ? r.until : m, '');
    if(until > maxUntil) hist.push({ until, amount: old });
    tmpl.rates = hist;
  }
  tmpl.amount = newAmt;
}
// First cycle a newly set-up charge applies to: this month, or next month
// when this month's due date has already passed (that cycle predates it).
function _sinceFor(t, tmpl) {
  const cur = _currentYM();
  return templateDueDate(t, tmpl, cur) < todayISO() ? addYM(cur, 1) : cur;
}

async function commitAmountEdit(input){
  const td  = input.closest('td, .td-amt-edit');
  const tid = td.dataset.tid;
  const bi  = Number(td.dataset.bi);
  const t = tenants.find(t=>t.id===tid);
  if(!t || !t.bills[bi]) return;
  const original = Number(t.bills[bi].amount);
  // Put back what the cell showed before editing.
  const restore = () => { td.innerHTML = td.dataset.prev || peso(original); };
  // Cancel path — restore original cell content.
  if(input.dataset.cancel){ restore(); return; }
  const raw = String(input.value).replace(/,/g,'').trim();
  const parsed = Number(raw);
  if(isNaN(parsed) || parsed < 0){
    showToast('Amount must be a non-negative number.', false);
    restore();
    return;
  }
  const next = Math.round(parsed * 100) / 100;
  if(next === original){ restore(); return; }
  // Commit to DB then update local state and re-render. Full re-render so
  // the summary stats, Insights, and Action Required pick up the new amount
  // too — not just the table rows.
  await _autoBillIdle();
  return _withTenantLock(tid, async () => {
    const live = tenants.find(x=>x.id===tid);
    if(!live || !live.bills[bi]){ restore(); return; }
    if(td._tenant && _formStale(td._tenant)){ rerenderAdmin(); return; }
    const billsCopy = structuredClone(live.bills);
    billsCopy[bi].amount = next;
    const sync = _resyncPaidStatus(billsCopy[bi], original);
    try {
      await dbUpdateTenantGuarded(live, {bills: billsCopy});
      live.bills = billsCopy;
      showToast(sync === 'reopened' ? 'Amount updated — the bill is open again: ₱' + fmtMoney(billOpen(billsCopy[bi])) + ' still due.'
        : sync === 'paid' ? 'Amount updated — logged payments cover it, marked paid.' : 'Amount updated.');
      rerenderAdmin();
    } catch(e){
      showToast(e.conflict ? e.message : 'Save failed: '+e.message, false);
      if(e.conflict){ rerenderAdmin(); return; }
      restore();
    }
  });
}

// Pending paid-date action
let _pendingPaid = null; // { tid, bi, t, bill } — or { bulk: [...] } from Billing's bulk select

function closePaidModal(){
  closeModalEl('paiddate-modal');
  _pendingPaid=null;
}

async function confirmPaid(){
  if(!_pendingPaid) return;
  const {tid,bi,t:expectT}=_pendingPaid;
  // Save FIRST, close on success. Closing before the save meant a failed
  // request was only a 2.5-second toast and the admin walked away believing
  // the payment was recorded.
  const btn = document.querySelector('#paiddate-modal .btn-save');
  if(btn && btn.disabled) return; // double-click guard
  if(btn){ btn.disabled=true; btn.textContent='Saving…'; }
  const dateVal=document.getElementById('paiddate-input').value;
  if(!_futureDateOk(dateVal)){ if(btn){ btn.disabled=false; btn.textContent='Confirm Paid'; } return; }
  if(_pendingPaid.bulk){
    const done = await _confirmBulkPaid(dateVal||todayISO());
    if(btn){ btn.disabled=false; btn.textContent='Confirm Paid'; }
    // Every save failed: the dialog stays open so the admin can retry.
    if(done) closePaidModal();
    rerenderAdmin(); return;
  }
  // The remembered index must still point at the same, still-unpaid bill.
  const live = tenants.find(x=>x.id===tid);
  if(live && live === expectT && (live.bills[bi] !== _pendingPaid.bill || live.bills[bi].status === 'paid')){
    if(btn){ btn.disabled=false; btn.textContent='Confirm Paid'; }
    showToast('That bill changed in the meantime — please try again.', false); closePaidModal(); rerenderAdmin(); return;
  }
  const ok = await saveBills(tid, bills=>{
    if(!bills[bi] || bills[bi].status==='paid') return;
    bills[bi].status='paid';
    bills[bi].paidDate=dateVal||todayISO();
  }, 'Marked as paid ✓', expectT);
  if(btn){ btn.disabled=false; btn.textContent='Confirm Paid'; }
  // 'conflict' (truthy) also closes: the tenant row was reloaded, so the
  // remembered bill INDEX may now point at a different bill — retrying the
  // stale index could mark the wrong bill paid. The admin re-taps instead.
  if(ok === true) _noteJustPaid(tid, bi);
  if(ok){ closePaidModal(); rerenderAdmin(); }
  // On a plain failure (no reload) the modal stays open so the admin can retry.
}

async function revertToPending(tid,bi){
  // Destructive: clears the recorded paid date, which the Collected insights
  // key off. A stray tap must not silently rewrite history.
  const t = tenants.find(t=>t.id===tid);
  const b = t && t.bills[bi];
  if(!b) return;
  const when = b.paidDate ? ' (paid '+formatDate(b.paidDate)+')' : '';
  const pays = b.payments||[], logged = billTotalPaid(b);
  // Settled by its logged payments: moving it back means taking one away.
  // Only the most recent entry goes (the usual mistake); earlier genuine
  // payments stay. A Receive-payment entry offers to undo that whole
  // payment (every bill it paid, and bills it posted early).
  if(pays.length && Number(b.amount) > 0 && logged >= Number(b.amount) - 0.005){
    const last = pays[pays.length-1];
    if(last.rid && await _offerUndoReceipt(t, last.rid)) return;
    const others = pays.length - 1;
    if(!confirm('Move this bill back to unpaid?'+when+'\n\nIts most recent payment is removed: ₱'+fmtMoney(last.amount)+(last.date?' on '+formatDate(last.date):'')+(last.note?' ('+last.note+')':'')+'.'
      + (others ? '\nIts other '+others+' payment'+(others!==1?'s':'')+' (₱'+fmtMoney(logged - Number(last.amount||0))+') stay — remove one of those with ✕ under Manage bills instead if that is the mistake.' : ''))) return;
    let still = false;
    const ok = await saveBills(tid, bills=>{
      const x = bills[bi];
      if(!x || !x.payments || !x.payments.length) return;
      x.payments.pop();
      if(billTotalPaid(x) >= Number(x.amount) - 0.005) still = true;
      else { x.status='unpaid'; x.paidDate=''; if(/paid in advance/i.test(x.remark||'') && billTotalPaid(x) <= 0.005) x.remark=''; }
    }, 'Payment removed.', t);
    if(ok === true && still) showToast('Payment removed — the remaining payments still cover this bill, so it stays paid.', false);
    if(ok) rerenderAdmin();
    return;
  }
  const msg = 'Move this bill back to unpaid?'+when+' The recorded paid date will be cleared.'
    + (pays.length ? '\n\nIts logged partial payment'+(pays.length!==1?'s':'')+' (₱'+fmtMoney(logged)+') stay on the bill.' : '');
  if(!confirm(msg)) return;
  const ok = await saveBills(tid, bills=>{
    if(!bills[bi]) return;
    bills[bi].status='unpaid';
    bills[bi].paidDate='';
  }, 'Bill moved back to unpaid.', t);
  if(ok) rerenderAdmin();
}
// A payment entry that came from Receive payment: offer to undo that whole
// payment. true = handled (undone, or the admin backed out entirely).
async function _offerUndoReceipt(t, rid) {
  const res = undoReceipt(t, rid, { today: todayISO() });
  if(!res) return false;
  const also = res.touched > 1 || res.removed;
  if(!also) return false; // it only ever paid this one bill — the single-entry path is the same thing
  if(!confirm('This came from a ₱'+fmtMoney(res.amount)+' payment that paid '+res.touched+' bill'+(res.touched!==1?'s':'')
    + (res.removed ? ' and posted '+res.removed+' bill'+(res.removed!==1?'s':'')+' early for later months' : '')+'.\n\nOK: undo that whole payment — it leaves every bill it paid'
    + (res.removed ? ', and the early bills are removed (they post normally when due)' : '')+'.\nCancel: change only this bill.')) return false;
  await undoPayment(t.id, rid, true);
  return true;
}
async function undoPayment(tid, rid, confirmed) {
  const t = tenants.find(x=>x.id===tid);
  if(!t) return;
  const res = undoReceipt(t, rid, { today: todayISO() });
  if(!res){ showToast('That payment was already removed.', false); rerenderAdmin(); return; }
  if(!confirmed && !confirm('Undo this ₱'+fmtMoney(res.amount)+' payment?\n\nIt is removed from the '+res.touched+' bill'+(res.touched!==1?'s':'')+' it paid'
    + (res.removed ? ', and the '+res.removed+' bill'+(res.removed!==1?'s':'')+' it posted early for later months are removed — they post normally when due' : '')
    + '. Use this for a payment recorded by mistake.')) return;
  const ok = await saveTenantData(tid, x => undoReceipt(x, rid, { today: todayISO() }), 'Payment undone.');
  if(ok) rerenderAdmin();
}
// Archiving is a move-out: the admin gives the last day in the unit, bills
// for cycles after it that were never paid are cancelled, and money paid
// ahead is either refunded (dated) or kept as forfeited. The
// archive date is that last day, so reports stop earning rent and counting
// the tenant from then on (see planMoveOut / billRecognition).
let _moveOut = null; // { tid, t }
function deleteTenant(tid){
  const t = tenants.find(x=>x.id===tid);
  if(!t) return;
  _moveOut = { tid, t };
  const today = todayISO();
  document.getElementById('mo-title').textContent = t.name;
  const d = document.getElementById('mo-date'); d.value = today; d.max = today;
  // A tenant who never moved in (move-in still ahead) can be archived too.
  if(moveInOf(t) && moveInOf(t) <= today) d.min = moveInOf(t); else d.removeAttribute('min');
  const rd = document.getElementById('mo-refund-date'); rd.value = today; rd.max = today;
  const r = document.querySelector('input[name="mo-prepaid"][value="refund"]'); if(r) r.checked = true;
  renderMoveOut();
  openModal('moveout-modal');
}
function _moPrepaidChoice(){ const el = document.querySelector('input[name="mo-prepaid"]:checked'); return el ? el.value : 'refund'; }
function renderMoveOut(){
  if(!_moveOut) return;
  const t = tenants.find(x=>x.id===_moveOut.tid) || _moveOut.t;
  const last = document.getElementById('mo-date').value;
  const box = document.getElementById('mo-summary');
  const pre = document.getElementById('mo-prepaid');
  if(!isISODate(last)){ box.innerHTML = '<p class="muted">Pick the last day they lived in the unit.</p>'; pre.style.display = 'none'; return; }
  const plan = planMoveOut(t, last, {});
  const mi0 = moveInOf(t);
  const nm = b => esc(b.label) + (billPeriod(b) ? ' (' + fmtYM(billPeriod(b), 'short') + ')' : '');
  const items = [];
  if(plan.removed.length) items.push('<li>' + plan.removed.length + ' unpaid bill' + (plan.removed.length!==1?'s':'') + ' for after move-out will be <strong>cancelled</strong> (never owed): ' + plan.removed.slice(0,4).map(nm).join(', ') + (plan.removed.length>4 ? ' +' + (plan.removed.length-4) + ' more' : '') + '.</li>');
  if(plan.owed > 0.005) items.push('<li>' + peso(plan.owed) + ' still owed from before move-out stays on their account (and in receivables).</li>');
  if(plan.awaiting.length) items.push('<li class="txt-bad">' + plan.awaiting.length + ' bill' + (plan.awaiting.length!==1?'s':'') + ' still need' + (plan.awaiting.length===1?'s':'') + ' an amount (final meter reading): '
    + plan.awaiting.map(nm).join(', ') + '. Enter ' + (plan.awaiting.length===1?'it':'them') + ' first — an archived tenant\'s bills can\'t be edited.</li>');
  if(plan.prepaidTotal > 0.005) items.push('<li>' + peso(plan.prepaidTotal) + ' was paid in advance for after move-out (' + plan.prepaid.slice(0,4).map(x => esc(x.label) + (x.period ? ' ' + fmtYM(x.period, 'short') : '')).join(', ') + '). What happens to it?</li>');
  if(!items.length) items.push('<li>Nothing is billed after move-out and nothing is owed.</li>');
  if(mi0 && mi0 > last) items.unshift('<li>They never moved in (move-in ' + formatDate(mi0) + '): the tenancy is cancelled.</li>');
  box.innerHTML = '<ul>' + items.join('') + '</ul><p class="muted">Their history is kept and still counts in past reports. They can be restored.</p>';
  pre.style.display = plan.prepaidTotal > 0.005 ? 'block' : 'none';
  document.getElementById('mo-refund-wrap').style.display = _moPrepaidChoice()==='refund' ? 'block' : 'none';
}
function closeMoveOut(){ closeModalEl('moveout-modal'); _moveOut = null; }
async function confirmMoveOut(){
  if(!_moveOut) return;
  const btn = document.getElementById('mo-confirm');
  if(btn.disabled) return;
  const last = document.getElementById('mo-date').value;
  const today = todayISO();
  if(!isISODate(last) || last > today){ showToast('Pick their last day in the unit (today or earlier).', false); return; }
  const mi = moveInOf(_moveOut.t);
  if(mi && mi <= today && last < mi){ showToast('The last day can\'t be before the move-in date ('+formatDate(mi)+').', false); return; }
  const choice = _moPrepaidChoice();
  const refundDate = document.getElementById('mo-refund-date').value;
  if(choice==='refund' && (!isISODate(refundDate) || refundDate > today)){ showToast('Pick the date the refund was paid (today or earlier).', false); return; }
  btn.disabled = true;
  try {
    await _autoBillIdle();
    const t = tenants.find(x=>x.id===_moveOut.tid);
    if(!t || _formStale(_moveOut.t)){ closeMoveOut(); rerenderAdmin(); return; }
    const plan = planMoveOut(t, last, { prepaid: choice, refundDate });
    if(plan.awaiting.length && !confirm(plan.awaiting.length + ' bill' + (plan.awaiting.length!==1?'s':'') + ' still need' + (plan.awaiting.length===1?'s':'') + ' an amount (final meter reading). Archive anyway?\n\nAn archived tenant\'s bills can\'t be edited; you would need to restore them to enter it.')) return;
    const at = new Date(last + 'T12:00:00').toISOString();
    setLoading(true,'Archiving…');
    try {
      await dbUpdateTenantGuarded(t, { archived_at: at, bills: plan.bills, templates: plan.templates });
    } catch(e){
      setLoading(false);
      showToast(e.conflict ? e.message : 'Archive failed: '+e.message, false);
      if(e.conflict){ closeMoveOut(); rerenderAdmin(); }
      return;
    }
    t.archived_at = at; t.bills = plan.bills; t.templates = plan.templates;
    tenants = tenants.filter(x=>x.id!==t.id);
    archivedTenants = archivedTenants.filter(x=>x.id!==t.id).concat([t]);
    setLoading(false); closeMoveOut();
    showToast('Tenant archived' + (plan.removed.length ? ' — ' + plan.removed.length + ' unpaid bill' + (plan.removed.length!==1?'s':'') + ' after move-out cancelled' : '')
      + (plan.prepaidTotal > 0.005 ? (choice==='refund' ? ', advance refunded' : ', advance kept') : '') + '.');
    if(_adminModule==='tenants' && _tenantDetailId===t.id) go('tenants'); else rerenderAdmin();
  } finally { btn.disabled = false; }
}
async function restoreTenant(tid){
  const a = archivedTenants.find(x=>x.id===tid);
  if(!confirm('Restore '+(a?a.name:'this tenant')+' as an active tenant? This undoes the archive'+(a && (a.bills||[]).some(b=>b&&b.preMoveOut)?', including the move-out refund/forfeit':'')+'.\n\nIf they are moving back in after time away, add them as a new tenant instead — their old record keeps its history.\n\nBills cancelled at move-out come back as they were; recurring bills resume as usual.')) return;
  // Their access code may have been given to someone since (codes are
  // only unique among active tenants): restore with a fresh one.
  if(!a) return;
  // Restore undoes the archive (and its move-out changes). A former tenant
  // coming back after time away is a new stay — add them as a new tenant,
  // so the first stay's dates (and past reports) stay as they were.
  const patch = {archived_at: null};
  const um = undoMoveOut(a);
  if(um.restored) patch.bills = um.bills;
  const holder = tenants.find(x=>x.code===a.code);
  if(holder){
    let fresh = randCode();
    while(tenants.some(x=>x.code===fresh) || archivedTenants.some(x=>x.code===fresh)) fresh = randCode();
    if(!confirm('Access code '+a.code+' is now used by '+holder.name+'.\n\nRestore '+a.name+' with a new code, '+fresh+'? Give them the new code to log in.')) return;
    patch.code = fresh;
  }
  setLoading(true,'Restoring…');
  // Only a row that is still archived, unchanged since this list loaded.
  let q = 'tenants?id=eq.' + tid + '&archived_at=not.is.null';
  if(a.rev != null){ q += '&rev=eq.' + a.rev; patch.rev = Number(a.rev) + 1; }
  let rows;
  try {
    rows = await sbFetch(q, { method:'PATCH', body: JSON.stringify(patch) });
  } catch(e){
    setLoading(false);
    showToast(/idx_tenants_code_active|duplicate key/i.test(e.message||'') ? 'Restore failed: that tenant\'s access code is in use by an active tenant. Refresh the page and try again.' : 'Restore failed: '+e.message, false);
    return;
  }
  if(!rows || !rows.length){
    setLoading(false);
    try { await _refreshTenantLists(); } catch {}
    showToast('This tenant was restored, changed or deleted on another device. The lists have been reloaded — check and try again if needed.', false);
    rerenderAdmin(); renderArchivedList();
    return;
  }
  if(patch.code) a.code = patch.code;
  if(patch.bills) a.bills = patch.bills;
  try {
    tenants = await dbGetAll() || [];
  } catch(e){
    // The row IS restored; only the refresh failed.
    if(a){ a.archived_at = null; tenants = tenants.filter(x=>x.id!==tid).concat([a]); }
  }
  archivedTenants = archivedTenants.filter(x=>x.id!==tid);
  try { archivedTenants = await dbGetArchived() || []; _archivedLoadError = false; } catch { _archivedLoadError = true; }
  setLoading(false); showToast(patch.code ? 'Tenant restored with new access code '+patch.code+'.' : 'Tenant restored.');
  rerenderAdmin(); renderArchivedList();
}
async function permanentlyDeleteTenant(tid){
  const t = archivedTenants.find(x=>x.id===tid);
  if(!t) return;
  // Single, harder-to-misclick confirm: require the admin to type the tenant's name.
  const typed = prompt('This will permanently delete ' + t.name + ' and all their billing data — including their history in past reports. This cannot be undone.\n\nType the tenant\'s name to confirm:');
  if(typed === null) return; // cancelled
  if(typed.trim().toLowerCase() !== String(t.name).trim().toLowerCase()){
    showToast('Name did not match — deletion cancelled.', false);
    return;
  }
  setLoading(true,'Deleting permanently…');
  try {
    // Only a row that is still archived and unchanged since this list
    // loaded — never a tenant another device has restored meanwhile.
    let q = 'tenants?id=eq.' + tid + '&archived_at=not.is.null';
    if(t.rev != null) q += '&rev=eq.' + t.rev;
    const rows = await sbFetch(q, { method:'DELETE' });
    if(!rows || rows.length !== 1){
      setLoading(false);
      try { await _refreshTenantLists(); } catch {}
      showToast('Not deleted: this tenant was restored or changed on another device. The lists have been reloaded.', false);
      rerenderAdmin(); renderArchivedList();
      return;
    }
    archivedTenants = archivedTenants.filter(x=>x.id!==tid);
    setLoading(false); showToast('Tenant permanently deleted.'); renderTenantList(); renderArchivedList();
  } catch(e){ setLoading(false); showToast('Delete failed: '+e.message, false); }
}
// Refresh the archived list from the server (it's also loaded at sign-in
// for reports) and render it into the Tenants module.
async function loadArchivedTenants(){
  try {
    archivedTenants = await dbGetArchived() || [];
    _archivedLoadError = false;
  } catch(e){ showToast('Could not load archived tenants.', false); }
  renderTenantList();
  renderArchivedList();
}
function renderArchivedList(){
  const wrap = document.getElementById('archived-tenants-wrap');
  if(!wrap) return;
  if(!archivedTenants.length){ wrap.innerHTML='<div class="empty-inline">No archived tenants.</div>'; return; }
  wrap.innerHTML = archivedTenants.map(t=>`
    <div class="plain-row" data-tid="${esc(t.id)}">
      <div class="plain-main">
        <div class="plain-title">${esc(t.name)}</div>
        <div class="plain-sub">Unit ${esc(t.unit)}${floorKey(t)?' · '+esc(t.floor):''} · Archived ${formatDate(String(t.archived_at||'').slice(0,10))}</div>
      </div>
      <button type="button" class="btn-mini" onclick="restoreTenant(this.parentNode.dataset.tid)">${icon('undo')}<span>Restore</span></button>
      <button type="button" class="btn-icon del" onclick="permanentlyDeleteTenant(this.parentNode.dataset.tid)" title="Permanently delete" aria-label="Permanently delete">${icon('trash')}</button>
    </div>`).join('');
}

function switchModalTab(tab,btn){
  document.querySelectorAll('.modal-tab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-info').classList.toggle('active',tab==='info');
  document.getElementById('panel-bills').classList.toggle('active',tab==='bills');
  document.getElementById('panel-templates').classList.toggle('active',tab==='templates');
  if(tab==='bills') renderBillListItems();
  if(tab==='templates') renderTemplateList();
}

// Show the flat-rate field only for the all-inclusive billing model; the
// segmented choice and the explanation follow the (hidden) select.
function onBillingModelChange(){
  const model = document.getElementById('m-billing').value;
  document.getElementById('m-flatrate-wrap').style.display = model==='inclusive' ? 'block' : 'none';
  const rentWrap = document.getElementById('m-rent-wrap');
  const canRent = rentWrap && rentWrap.dataset.allowed==='1';
  if(rentWrap) rentWrap.style.display = (model!=='inclusive' && canRent) ? 'block' : 'none';
  document.querySelectorAll('#tenant-modal .bm-opt').forEach(b => { const on = b.dataset.model === model; b.classList.toggle('active', on); b.setAttribute('aria-checked', String(on)); });
  const lead = autoBilling.leadDays, when = lead ? lead + ' day' + (lead !== 1 ? 's' : '') + ' before each due date' : 'on each due date';
  const ex = document.getElementById('m-explain');
  if(ex) ex.textContent = !canRent ? 'Recurring charges for this tenant are set on the Recurring tab.'
    : !autoBilling.enabled ? 'Automatic billing is off in Settings — post recurring bills from Billing.'
    : model === 'inclusive' ? 'One flat rate covers rent and utilities. It posts automatically ' + when + ', and the tenant sees it as their monthly rate.'
    : 'Rent posts automatically ' + when + '. Add water and electricity as metered bills when readings come in.';
}
function setBillingModel(model){ document.getElementById('m-billing').value = model; onBillingModelChange(); }
// The "monthly rent" + "due day" fields create the tenant's recurring rent
// template, so they only show when there is no template yet (new tenants,
// or old tenants set up before templates). Existing templates are edited
// on the Templates tab.
function _syncRecurringFields(t){
  const allowed = !t || !(t.templates||[]).length;
  document.getElementById('m-rent-wrap').dataset.allowed = allowed ? '1' : '0';
  document.getElementById('m-dueday-wrap').style.display = allowed ? 'block' : 'none';
  document.getElementById('m-rent').value = '';
  document.getElementById('m-dueday').value = '';
  onBillingModelChange();
}
function openAddModal(){
  editingId=null; _editingT=null;
  document.getElementById('modal-eyebrow').textContent='New Tenant';
  document.getElementById('modal-title').textContent='Add a tenant';
  document.getElementById('modal-sub').textContent='Rent starts posting from the move-in date';
  const saveBtn=document.getElementById('btn-save-tenant'); if(saveBtn) saveBtn.textContent='Add tenant';
  document.getElementById('m-name').value='';
  document.getElementById('m-unit').value='';
  document.getElementById('m-code').value=randCode();
  document.getElementById('m-phone').value='';
  document.getElementById('m-email').value='';
  document.getElementById('m-movein').value='';
  _fillFloorSelect('');
  document.getElementById('m-billing').value='itemized';
  document.getElementById('m-flatrate').value='';
  _syncRecurringFields(null);
  document.getElementById('modal-tabs').style.display='none';
  document.getElementById('new-tenant-bills').style.display='';
  document.getElementById('panel-info').classList.add('active');
  document.getElementById('panel-bills').classList.remove('active');
  document.getElementById('panel-templates').classList.remove('active');
  // Recurring rent comes from the Monthly Rent field; opening bills are
  // only for balances carried over from before the tenant was added.
  billForms=[];
  renderBillForms();
  openModal('tenant-modal');
}
// tab: 'info' (default) | 'bills' | 'templates'
function openEditModal(tid, tab){
  const t=tenants.find(t=>t.id===tid); if(!t) return; editingId=tid; _editingT=t; _billListT=null; _tmplListT=null;
  _showAllPaidBills = false; // each tenant starts with the compact paid list
  document.getElementById('modal-eyebrow').textContent='Edit Tenant';
  document.getElementById('modal-title').textContent=t.name; // textContent — no HTML-escaping needed
  document.getElementById('modal-sub').textContent=['Unit '+t.unit, floorKey(t)].filter(Boolean).join(' · ');
  const saveBtn=document.getElementById('btn-save-tenant'); if(saveBtn) saveBtn.textContent='Save changes';
  document.getElementById('m-name').value=t.name;
  document.getElementById('m-unit').value=t.unit;
  document.getElementById('m-code').value=t.code;
  document.getElementById('m-phone').value=t.phone||'';
  document.getElementById('m-email').value=t.email||'';
  document.getElementById('m-movein').value=t.move_in_date||'';
  _fillFloorSelect(t.floor||'');
  document.getElementById('m-billing').value=t.billing_model==='inclusive'?'inclusive':'itemized';
  document.getElementById('m-flatrate').value=(t.flat_rate!=null && t.flat_rate!=='')?t.flat_rate:'';
  onBillingModelChange();
  // Bills tab manages bills via its own UI; billForms is only used for new tenants.
  billForms = [];
  document.getElementById('modal-tabs').style.display='flex';
  document.getElementById('new-tenant-bills').style.display='none';
  document.querySelectorAll('.modal-tab').forEach((tab,i)=>tab.classList.toggle('active',i===0));
  document.getElementById('panel-info').classList.add('active');
  document.getElementById('panel-bills').classList.remove('active');
  document.getElementById('panel-templates').classList.remove('active');
  document.getElementById('new-bill-inline').style.display='none';
  _syncRecurringFields(t);
  openModal('tenant-modal');
  if(tab && tab!=='info'){
    const btnEl = document.querySelector('.modal-tab[data-tab="'+tab+'"]');
    if(btnEl) switchModalTab(tab, btnEl);
  }
}
function closeModal(){
  closeModalEl('tenant-modal');
  editingId=null;
  cancelNewBill(); // ensure + Add bill button always reappears
}

function billListItemHtml(b, i, extraClass) {
  const paid = billTotalPaid(b);
  const remaining = billRemaining(b);
  const hasPartial = b.status!=='paid' && paid > 0;
  const paymentsHtml = (b.payments||[]).map((p,pi)=>`
    <div class="payment-entry">
      <span class="payment-entry-date">${formatDate(p.date)}</span>
      <span class="payment-entry-amt">${Number(p.amount)<0?'Refunded &#8369;'+(-Number(p.amount)).toLocaleString():'&#8369;'+Number(p.amount).toLocaleString()+' paid'}</span>
      ${p.note?`<span class="payment-entry-note">${esc(p.note)}</span>`:'<span class="payment-entry-note"></span>'}
      <button class="payment-entry-del" onclick="deletePaymentEntry(${i},${pi})" title="Remove this payment" aria-label="Remove this payment">&#10005;</button>
    </div>`).join('');
  // Use unified due-status so "Upcoming" and "Due Soon" appear instead of red "Unpaid".
  const ds = getDueStatus(b);
  const statusMeta = {
    paid:      {label: 'Paid',      color: 'var(--green)'},
    overdue:   {label: 'Overdue',   color: 'var(--rust)'},
    'due-today':{label:'Due Today', color: 'var(--rust)'},
    'due-soon':{label:'Due Soon',   color: 'var(--orange)'},
    grace:{label:'In grace period', color: 'var(--orange)'},
    upcoming:  {label: 'Upcoming',  color: 'var(--muted)'},
    'no-date': {label: 'Unscheduled', color: 'var(--muted)'},
    awaiting:  {label: 'Needs amount', color: 'var(--orange)'}
  }[ds] || {label: 'Unpaid', color: 'var(--rust)'};
  const statusHtml = b.status==='paid' && b.paidDate
    ? `<span style="color:var(--green);font-weight:600;">Paid ${formatDate(b.paidDate)}</span>`
    : `<span style="color:${statusMeta.color};font-weight:600;">${statusMeta.label}</span>`;
  return `<div class="bill-list-item ${extraClass||''}">
    <div class="bill-list-info" style="flex:1">
      <div class="bill-list-label">${esc(b.label)}</div>
      <div class="bill-list-meta">
        &#8369;${Number(b.amount).toLocaleString()}
        ${b.due?' &nbsp;·&nbsp; Due '+formatDate(b.due):''}
        &nbsp;·&nbsp; ${statusHtml}
      </div>
      ${hasPartial?`<div class="partial-balance${remaining<=0?' settled':''}">&#8369;${paid.toLocaleString()} received &nbsp;·&nbsp; &#8369;${Math.max(0,remaining).toLocaleString()} remaining</div>`:''}
      ${(b.payments&&b.payments.length)?`<div class="payments-log">${paymentsHtml}</div>`:''}
      ${extraClass!=='paid-item'?`<button class="btn-add-payment" onclick="openAddPayment(${i})">+ Add Payment</button><div id="add-payment-form-${i}" style="display:none"></div>`:''}
    </div>
    <div class="bill-list-actions" style="gap:6px;align-self:flex-start;margin-top:2px;">
      <button class="btn-icon" onclick="editBillInline(${i})" aria-label="Edit">&#9998;</button>
      <button class="btn-icon del" onclick="deleteBillFromList(${i})" aria-label="Delete">&#10005;</button>
    </div>
  </div>
  <div id="bill-edit-inline-${i}" style="display:none"></div>`;
}

// Remember the expanded/collapsed choice across the instant-save re-renders,
// so editing a paid bill doesn't collapse the list and hide that very bill.
let _showAllPaidBills = false;
function renderBillListItems(showAllPaid){
  if(showAllPaid===undefined) showAllPaid = _showAllPaidBills;
  else _showAllPaidBills = !!showAllPaid;
  const t=tenants.find(t=>t.id===editingId); if(!t) return;
  _billListT = t;
  const c=document.getElementById('bill-list-items'); if(!c) return;
  if(!t.bills.length){ c.innerHTML='<div style="text-align:center;padding:24px 0;font-size:13px;color:var(--muted);">No bills yet. Add one below.</div>'; return; }

  const unpaid = t.bills.map((b,i)=>({b,i})).filter(({b})=>b.status!=='paid');
  const paid   = t.bills.map((b,i)=>({b,i})).filter(({b})=>b.status==='paid')
                   .sort((a,b)=>(b.b.paidDate||'').localeCompare(a.b.paidDate||''));

  const LIMIT = 3;
  const visiblePaid = showAllPaid ? paid : paid.slice(0, LIMIT);
  const hiddenCount = paid.length - visiblePaid.length;

  let html = unpaid.map(({b,i})=>billListItemHtml(b,i,'')).join('');

  if(paid.length){
    html += `<div class="bill-list-paid-divider">Paid (${paid.length})</div>`;
    html += visiblePaid.map(({b,i})=>billListItemHtml(b,i,'paid-item')).join('');
    if(hiddenCount > 0){
      html += `<button class="bill-list-show-more" onclick="renderBillListItems(true)">Show all paid bills  (${hiddenCount} more)</button>`;
    } else if(showAllPaid && paid.length > LIMIT){
      html += `<button class="bill-list-show-more" onclick="renderBillListItems(false)">Show less</button>`;
    }
  }

  c.innerHTML = html;
}

function editBillInline(i){
  document.querySelectorAll('[id^="bill-edit-inline-"]').forEach(el=>el.style.display='none');
  const t=tenants.find(t=>t.id===editingId); if(!t||!t.bills[i]) return; const b=t.bills[i];
  const el=document.getElementById('bill-edit-inline-'+i); el.style.display='block';
  el.innerHTML=`<div class="bill-edit-form">
    <div class="form-grid">
      <div class="field"><label>Description</label><input type="text" id="bi-label-${i}" value="${esc(b.label)}"></div>
      <div class="field"><label>Amount (&#8369;)</label><input type="text" id="bi-amount-${i}" value="${b.amount}" inputmode="decimal" pattern="[0-9.]*" autocomplete="off"></div>
      <div class="field"><label>Due Date</label><input type="date" id="bi-due-${i}" value="${b.due||''}"></div>
      <div class="field"><label>Status</label>
        <select id="bi-status-${i}" onchange="_paidToggle(this,'bi-pd-wrap-${i}','bi-paidDate-${i}')">
          <option value="unpaid" ${b.status!=='paid'?'selected':''}>Unpaid</option>
          <option value="paid" ${b.status==='paid'?'selected':''}>Paid</option>
        </select>
      </div>
      ${b.tmplId ? '' : _monthField('bi-period-'+i, b.period)}
      ${_catField('bi-cat-'+i, b.category || '', b.label, !!b.tmplId)}
      <div class="field full" id="bi-pd-wrap-${i}" style="display:${b.status==='paid'?'block':'none'}"><label>Date Paid</label><input type="date" id="bi-paidDate-${i}" value="${b.paidDate||''}"></div>
      <div class="field full"><label>Remark <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" id="bi-remark-${i}" value="${esc(b.remark||'')}" placeholder="e.g. Partial payment received"></div>
      <div class="field full"><label>Google Drive Scan Link <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" id="bi-scanLink-${i}" value="${esc(b.scanLink||'')}" placeholder="https://drive.google.com/..."></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn-cancel" style="flex:1;padding:9px;" onclick="document.getElementById('bill-edit-inline-${i}').style.display='none'">Cancel</button>
      <button class="btn-save" style="flex:2;padding:9px;" onclick="saveBillEdit(${i})">Save</button>
    </div>
  </div>`;
}

async function saveBillEdit(i){
  const t=tenants.find(t=>t.id===editingId); if(!t||!t.bills[i]) return;
  const label=document.getElementById('bi-label-'+i).value.trim();
  if(!label){ showToast('Please enter a bill description.', false); return; }
  const _amt = normalizeAmount(document.getElementById('bi-amount-'+i).value);
  const _raw = Number(String(document.getElementById('bi-amount-'+i).value).replace(/,/g,''));
  if(_raw < 0){ showToast('Amount cannot be negative.', false); return; }
  if(_amt===0 && !confirm('Amount is ₱0. Save anyway?')) return;
  const newStatus=document.getElementById('bi-status-'+i).value==='paid'?'paid':'unpaid';
  const pdInput=document.getElementById('bi-paidDate-'+i);
  if(newStatus==='paid' && pdInput && !pdInput.value){ showToast('Enter the date it was paid.',false); return; }
  const paidDate=newStatus==='paid'?(pdInput?pdInput.value:todayISO()):'';
  if(newStatus==='paid' && paidDate!==t.bills[i].paidDate && !_futureDateOk(paidDate)) return;
  let remark=document.getElementById('bi-remark-'+i).value.trim();
  // Auto-clear "pending amount" remark when a real amount is entered
  if(_amt > 0 && remark.toLowerCase().includes('pending amount')) remark = '';
  const due=document.getElementById('bi-due-'+i).value;
  const scanLink=(function(v){return /^https:\/\//i.test(v)?v:'';})(document.getElementById('bi-scanLink-'+i).value.trim());
  const _biCat = _catVal('bi-cat-'+i), _biPeriod = t.bills[i].tmplId ? null : _monthVal('bi-period-'+i);
  // Paid → Unpaid on a bill its logged payments settle: the most recent
  // payment is taken off (earlier genuine ones stay); a Receive-payment
  // entry offers to undo that whole payment instead.
  const cur = t.bills[i];
  const nPay = (cur.payments||[]).length, logged = billTotalPaid(cur);
  const dropPayments = cur.status==='paid' && newStatus!=='paid' && nPay>0 && logged >= _amt - 0.005 && _amt > 0;
  if(dropPayments){
    const last = cur.payments[nPay-1];
    if(last.rid && await _offerUndoReceipt(t, last.rid)){ renderBillListItems(); return; }
    if(!confirm('Moving this bill to Unpaid removes its most recent payment: ₱'+fmtMoney(last.amount)+(last.date?' on '+formatDate(last.date):'')+(last.note?' ('+last.note+')':'')+'.'
      + (nPay>1 ? '\nIts other '+(nPay-1)+' payment'+(nPay-1!==1?'s':'')+' stay — use ✕ on the one that is wrong instead if that is the mistake.' : '')+'\n\nContinue?')) return;
  }
  let sync = '';
  const ok = await saveBills(editingId, bills=>{
    if(!bills[i]) return;
    const prev = bills[i];
    const b = {...prev,label,amount:_amt,due,status:newStatus,remark,scanLink,paidDate};
    if(_biCat) b.category = _biCat; else delete b.category;
    if(_biPeriod !== null){ if(_biPeriod && _biPeriod !== ymOf(due)) b.period = _biPeriod; else delete b.period; }
    if(dropPayments){
      b.payments = (b.payments||[]).slice(0, -1);
      if(billTotalPaid(b) >= _amt - 0.005){ b.status = 'paid'; b.paidDate = prev.paidDate; sync = 'still'; }
    }
    if(b.status !== 'paid' && /paid in advance/i.test(b.remark||'') && billTotalPaid(b) <= 0.005) b.remark = '';
    // A corrected Date Paid moves the settling payment entries with it, so
    // cash reports (which follow payment dates) agree with the bill.
    const pays = b.payments || [];
    if(newStatus==='paid' && prev.status==='paid' && paidDate && prev.paidDate && paidDate!==prev.paidDate && pays.length)
      b.payments = pays.map(p => p.date===prev.paidDate ? {...p, date: paidDate} : p);
    // Amount changed: re-sync paid status with the logged payments.
    if(!dropPayments) sync = _resyncPaidStatus(b, Number(prev.amount));
    bills[i] = b;
  }, 'Bill updated.', _billListT);
  if(ok === true && sync === 'reopened') showToast('Bill updated — the new amount is more than was received, so it is open again.', false);
  if(ok === true && sync === 'still') showToast('Payment removed — the remaining payments still cover this bill, so it stays paid.', false);
  if(ok){ renderBillListItems(); rerenderAdmin(); }
}

async function deleteBillFromList(i){
  if(_formStale(_billListT)){ renderBillListItems(); rerenderAdmin(); return; }
  const ok = await deleteBillAt(editingId, i);
  if(ok){ renderBillListItems(); rerenderAdmin(); }
}

function startNewBill(){
  document.getElementById('btn-start-new-bill').style.display='none';
  const c=document.getElementById('new-bill-inline'); c.style.display='block';
  c.innerHTML=`<div class="bill-edit-form">
    <div class="form-grid">
      <div class="field"><label>Description</label><input type="text" id="nb-label" placeholder="e.g. Monthly Rent" autocomplete="off"></div>
      <div class="field"><label>Amount (&#8369;)</label><input type="text" id="nb-amount" placeholder="0" inputmode="decimal" pattern="[0-9.]*" autocomplete="off"></div>
      <div class="field"><label>Due Date</label><input type="date" id="nb-due"></div>
      <div class="field"><label>Status</label>
        <select id="nb-status" onchange="_paidToggle(this,'nb-pd-wrap','nb-paidDate')">
          <option value="unpaid" selected>Unpaid</option>
          <option value="paid">Paid</option>
        </select>
      </div>
      ${_monthField('nb-period', '')}
      ${_catField('nb-cat', '', '', false)}
      <div class="field full" id="nb-pd-wrap" style="display:none"><label>Date Paid</label><input type="date" id="nb-paidDate"></div>
      <div class="field full"><label>Remark <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" id="nb-remark" placeholder="e.g. Partial payment received"></div>
      <div class="field full"><label>Google Drive Scan Link <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" id="nb-scanLink" placeholder="https://drive.google.com/..."></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn-cancel" style="flex:1;padding:9px;" onclick="cancelNewBill()">Cancel</button>
      <button class="btn-save" style="flex:2;padding:9px;" onclick="saveNewBill()">Add Bill</button>
    </div>
  </div>`;
}

function cancelNewBill(){
  const inlineEl = document.getElementById('new-bill-inline');
  const btnEl    = document.getElementById('btn-start-new-bill');
  if(inlineEl) inlineEl.style.display='none';
  if(btnEl)    btnEl.style.display='block';
}

async function saveNewBill(){
  const label=document.getElementById('nb-label').value.trim(); if(!label){showToast('Please enter a bill description.',false);return;}
  const _rawNb = Number(String(document.getElementById('nb-amount').value).replace(/,/g,''));
  if(_rawNb < 0){ showToast('Amount cannot be negative.', false); return; }
  const _nbAmt = normalizeAmount(document.getElementById('nb-amount').value);
  if(_nbAmt===0 && !confirm('Amount is ₱0. Add this bill anyway?')) return;
  const status=document.getElementById('nb-status').value==='paid'?'paid':'unpaid';
  if(status==='paid' && !document.getElementById('nb-paidDate').value){ showToast('Enter the date it was paid.',false); return; }
  const paidDate=status==='paid'?document.getElementById('nb-paidDate').value:'';
  const bill={label,amount:normalizeAmount(document.getElementById('nb-amount').value),due:document.getElementById('nb-due').value,status,remark:document.getElementById('nb-remark').value.trim(),scanLink:(function(v){return /^https:\/\//i.test(v)?v:'';})(document.getElementById('nb-scanLink').value.trim()),paidDate,payments:[]};
  const _nbPeriod = _monthVal('nb-period'), _nbCat = _catVal('nb-cat');
  if(_nbPeriod && _nbPeriod !== ymOf(bill.due)) bill.period = _nbPeriod;
  if(_nbCat) bill.category = _nbCat;
  const _t = tenants.find(x=>x.id===editingId);
  const ph = _t && bill.amount > 0 ? _placeholderFor(_t, label, bill.due) : -1;
  if(_t && ph < 0 && billPeriod(bill)){
    const _tm = templateOfBill(_t, {label}) || (isRentLabel(label) && _nbCat !== 'utilities' && _nbCat !== 'other' ? primaryTemplate(_t) : null);
    if(_tm && templateBillExists(_t, _tm, billPeriod(bill)) && !confirm(_t.name+' already has a "'+_tm.label+'" bill for '+fmtYM(billPeriod(bill))+'. Add another?')) return;
  }
  if(ph >= 0 && confirm('"'+_t.bills[ph].label+'"'+(billPeriod(_t.bills[ph])?' for '+fmtYM(billPeriod(_t.bills[ph])):'')+' is already posted and waiting for its amount.\n\nOK: fill it with ₱'+fmtMoney(bill.amount)+'.\nCancel: add a separate bill instead.')){
    const ok = await saveBills(editingId, bills=>{
      const b = bills[ph];
      if(!b || !billAwaitingAmount(b)) return;
      if(!isYM(b.period) && billPeriod(b)) b.period = billPeriod(b);
      b.amount = bill.amount; if(bill.due) b.due = bill.due; b.remark = bill.remark; if(bill.scanLink) b.scanLink = bill.scanLink;
      if(status==='paid'){ b.status='paid'; b.paidDate=paidDate; } else _resyncPaidStatus(b, 0);
    }, 'Amount entered.', _billListT);
    if(ok === true){ cancelNewBill(); renderBillListItems(); rerenderAdmin(); }
    return;
  }
  const ok = await saveBills(editingId, bills=>{ bills.push(bill); }, 'Bill added.');
  if(ok === true){ cancelNewBill(); renderBillListItems(); rerenderAdmin(); }
}
function addBillForm(){ billForms.push({label:'',amount:'',due:'',status:'unpaid'}); renderBillForms(); }
function removeBill(i){ billForms.splice(i,1); renderBillForms(); }
function renderBillForms(){
  document.getElementById('bill-forms').innerHTML=billForms.map((b,i)=>`
    <div class="bill-item">
      <div class="field"><label>Description</label><input type="text" value="${esc(b.label)}" placeholder="e.g. Monthly Rent" oninput="billForms[${i}].label=this.value"></div>
      <div class="field"><label>Amount (&#8369;)</label><input type="text" value="${b.amount}" placeholder="0" inputmode="decimal" pattern="[0-9.]*" autocomplete="off" oninput="billForms[${i}].amount=this.value"></div>
      <div class="field"><label>Due Date</label><input type="date" value="${b.due||''}" onchange="billForms[${i}].due=this.value"></div>
      <div class="field"><label>Status</label>
        <select id="bf-status-${i}" onchange="billForms[${i}].status=this.value;document.getElementById('bf-pd-${i}').style.display=this.value==='paid'?'block':'none'">
          <option value="unpaid"  ${b.status!=='paid'?'selected':''}>Unpaid</option>
          <option value="paid"    ${b.status==='paid'?'selected':''}>Paid</option>
        </select>
      </div>
      <div class="field bill-remark-field" id="bf-pd-${i}" style="display:${b.status==='paid'?'block':'none'}">
        <label>Date Paid</label>
        <input type="date" value="${b.paidDate||''}" onchange="billForms[${i}].paidDate=this.value">
      </div>
      <div class="field bill-remark-field"><label>Remark <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" value="${esc(b.remark||'')}" placeholder="e.g. Partial payment of ₱2,000 received" oninput="billForms[${i}].remark=this.value"></div>
      <div class="field bill-remark-field"><label>Google Drive Scan Link <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(optional)</span></label><input type="text" value="${esc(b.scanLink||'')}" placeholder="https://drive.google.com/..." oninput="billForms[${i}].scanLink=this.value"></div>
      <button type="button" class="btn-rm" onclick="removeBill(${i})" aria-label="Remove this balance" title="Remove this balance"><span aria-hidden="true">×</span></button>
    </div>`).join('');
}
async function saveTenant(){
  const name=document.getElementById('m-name').value.trim();
  const unit=document.getElementById('m-unit').value.trim();
  const code=document.getElementById('m-code').value.trim().toUpperCase();
  const phone=document.getElementById('m-phone').value.trim();
  const email=document.getElementById('m-email').value.trim();
  const move_in_date=document.getElementById('m-movein').value||null;
  const _fv=document.getElementById('m-floor').value;
  const floor=_fv==='__add__' ? '' : snapFloor(_fv);
  const billing_model=document.getElementById('m-billing').value==='inclusive'?'inclusive':'itemized';
  const _frRaw=document.getElementById('m-flatrate').value;
  if(billing_model==='inclusive'){
    const _frNum = Number(String(_frRaw).replace(/,/g,'').trim());
    if(String(_frRaw).trim()===''){ showToast('Please enter the monthly flat rate for an all-inclusive tenant.',false); return; }
    // A typo like "6,5o0" must not silently save as ₱0.
    if(!isFinite(_frNum) || _frNum < 0){ showToast('Flat rate must be a non-negative number.',false); return; }
  }
  const flat_rate=billing_model==='inclusive' ? normalizeAmount(_frRaw) : null;
  const _rentRaw=document.getElementById('m-rent').value;
  const rent = billing_model==='itemized' && document.getElementById('m-rent-wrap').dataset.allowed==='1' ? normalizeAmount(_rentRaw) : 0;
  if(billing_model==='itemized' && String(_rentRaw).trim() && !(Number(String(_rentRaw).replace(/,/g,''))>=0)){ showToast('Monthly rent must be a non-negative number.',false); return; }
  const _ddRaw=document.getElementById('m-dueday').value;
  const dueDay = Number(_ddRaw);
  if(String(_ddRaw).trim() && !(Number.isInteger(dueDay) && dueDay>=1 && dueDay<=31)){ showToast('Rent due day must be a whole number from 1 to 31.',false); return; }
  if(!name||!unit||!code){showToast('Please fill in name, unit, and access code.',false);return;}
  if(!editingId && billForms.some(b=>b.label && b.status==='paid' && !b.paidDate)){showToast('Enter the date each paid bill was paid.',false);return;}
  if(tenants.find(t=>t.code===code&&t.id!==editingId)){showToast('That access code is already in use.',false);return;}
  const _archSame = archivedTenants.find(t=>t.code===code&&t.id!==editingId);
  if(_archSame){ showToast('Access code '+code+' belongs to archived tenant '+_archSame.name+' — pick another (Generate makes a new one).',false); return; }
  const savingId = editingId; // capture before closeModal() nullifies it
  await _autoBillIdle();
  if(savingId && _formStale(_editingT)){ closeModal(); rerenderAdmin(); return; }
  // When editing, use the tenant's current bills from memory (not billForms)
  let bills;
  if(savingId) {
    const existing = tenants.find(t=>t.id===savingId);
    bills = existing ? existing.bills : [];
  } else {
    bills = billForms.filter(b=>b.label).map(b=>({
      label:    b.label.trim(),
      amount:   normalizeAmount(b.amount),
      due:      b.due||'',
      status:   b.status==='paid'?'paid':'unpaid',
      remark:   (b.remark||'').trim(),
      scanLink: /^https:\/\//i.test((b.scanLink||'').trim()) ? (b.scanLink||'').trim() : '',
      paidDate: b.status==='paid' ? b.paidDate : '',
      payments: []
    }));
    const negative = billForms.find(b=>b.label && Number(String(b.amount||'').replace(/,/g,'')) < 0);
    if(negative){ showToast('Amount for "' + negative.label + '" cannot be negative.', false); return; }
    const dropped = billForms.filter(b=>!b.label && (b.amount || b.due));
    if(dropped.length){ showToast(dropped.length + ' bill(s) dropped — missing description.', false); }
    const zeroBill = bills.find(b=>Number(b.amount)===0);
    if(zeroBill && !confirm('Bill "' + zeroBill.label + '" has amount ₱0. Save anyway?')) return;
  }
  const prevT = savingId ? tenants.find(t=>t.id===savingId) : null;
  const existingTemplates = prevT ? (prevT.templates||[]) : [];
  // A NEW tenant with no recurring template gets one from the flat rate
  // (all-inclusive) or the Monthly Rent field (itemized), so bills post
  // automatically from the first cycle. On an edit it is never a side
  // effect: only when the admin types a Monthly Rent just now, or confirms
  // it after changing the all-inclusive rate/model. Due day: the field,
  // else the move-in day, else the 1st.
  let templates = structuredClone(existingTemplates);
  let autoTemplate = false;
  const recurringAmt = billing_model==='inclusive' ? flat_rate : rent;
  const _dayOf = s => { const d=Number(String(s||'').slice(8,10)); return d>=1&&d<=31?d:0; };
  const tmplDayNew = (dueDay>=1 && dueDay<=31 ? dueDay : 0) || _dayOf(move_in_date) || 1;
  if(recurringAmt>0 && !templates.length){
    let want = false;
    if(!savingId) want = true;
    else if(billing_model==='itemized') want = String(_rentRaw).trim()!=='';
    else if(prevT && (prevT.billing_model!=='inclusive' || Number(prevT.flat_rate)!==flat_rate))
      want = confirm('Post the all-inclusive rate (₱'+fmtMoney(flat_rate)+') automatically every month?\n\nA recurring "Monthly Rent (All-Inclusive)" charge due on day '+tmplDayNew+' is set up, and each bill posts ahead of its due date. Cancel keeps billing manual.');
    if(want){
      const nt = {id:uid(), label: billing_model==='inclusive' ? 'Monthly Rent (All-Inclusive)' : 'Monthly Rent', amount:recurringAmt, dayOfMonth:tmplDayNew, pendingAmount:false};
      // A new tenant's rent is reckoned from move-in; one set up later for an
      // existing tenant only from now (no back-dated arrears).
      if(savingId) nt.since = _sinceFor({ move_in_date, bills }, nt);
      templates.push(nt);
      autoTemplate = true;
    }
  }
  // Billing model switched: charges from the old model keep posting unless
  // the admin stops them — ask, naming them.
  if(prevT && (prevT.billing_model==='inclusive'?'inclusive':'itemized')!==billing_model && existingTemplates.length){
    const hits = billing_model==='inclusive'
      ? templates.filter(x=>!x.retired && billCategory(x)==='utilities')
      : templates.filter(x=>!x.retired && /all.?inclusive/i.test(x.label||''));
    const names = hits.map(x=>'"'+x.label+'"').join(', ');
    if(hits.length && confirm(billing_model==='inclusive'
        ? 'Utilities are included in an all-inclusive rate, but '+names+' '+(hits.length===1?'is':'are')+' still charged every month.\n\nStop '+(hits.length===1?'it':'them')+'? '+(hits.length===1?'It is':'They are')+' no longer posted or owed; bills already posted are kept.'
        : names+' still charge'+(hits.length===1?'s':'')+' the all-inclusive rate every month.\n\nStop it now that billing is itemized? It is no longer posted or owed (bills already posted are kept). Set up the itemized charges under Recurring.'))
      hits.forEach(x=>{ x.retired=true; });
  }
  // Flat rate changed on an all-inclusive tenant: offer to carry the new
  // rate into the main recurring charge so future cycles bill the right amount.
  if(prevT && billing_model==='inclusive' && flat_rate>0 && Number(prevT.flat_rate)!==flat_rate && !autoTemplate){
    const tp = primaryTemplate({templates, billing_model, flat_rate: prevT.flat_rate});
    if(tp && Number(tp.amount)!==flat_rate){
      if(confirm('Also change the recurring "'+tp.label+'" bill from ₱'+Number(tp.amount).toLocaleString()+' to ₱'+flat_rate.toLocaleString()+'?\n\nOnly bills posted from now on use the new rate; existing bills and past cycles keep their amounts.')) _recordRateChange({ bills, templates }, tp, flat_rate);
    } else if(!tp && templates.length) showToast('No recurring charge follows the new rate — update the amount under Recurring.', false);
  }
  const fields = {name,unit,code,phone,email,move_in_date,floor,billing_model,flat_rate,bills,templates};
  setLoading(true, savingId?'Saving changes…':'Adding tenant…');
  try {
    let savedId = savingId;
    if(savingId){
      const tObj = tenants.find(t=>t.id===savingId);
      await dbUpdateTenantGuarded(tObj, fields);
      Object.assign(tObj, fields);
      setLoading(false);
      closeModal();
      showToast(autoTemplate?'Changes saved — recurring rent set up, due on day '+tmplDayNew+'.':'Changes saved.');
    } else {
      const rec={id:uid(),...fields};
      // Use the returned row so server defaults (rev, etc.) are in memory.
      const inserted = await dbInsert(rec);
      tenants.push(_normalizeTenant((inserted && inserted[0]) || rec));
      savedId = rec.id;
      setLoading(false);
      closeModal();
      showToast(autoTemplate?'Tenant added — recurring rent set up, due on day '+tmplDayNew+'.':'Tenant added.');
    }
    // A new template or move-in date can make a cycle due right away.
    await runAutoBilling({ only: savedId });
    if(!savingId) openTenant(savedId); else rerenderAdmin();
  } catch(e){
    setLoading(false);
    if(e.conflict){ showToast(e.message, false); closeModal(); rerenderAdmin(); }
    else if(/billing_model|flat_rate|floor/.test(e.message||'')) alert(SCHEMA2_NOTE);
    else showToast('Error: '+e.message, false);
    // Modal stays open so the admin can correct and retry without re-typing.
  }
}
function generateCode(){ document.getElementById('m-code').value=randCode(); }

// ─────────────────────────────────────────────
// QUICK ADD BILL
// One-screen flow: pick tenant, describe, amount, due — done. Reachable from
// the toolbar and from every tenant row, so adding a bill never requires
// opening the edit modal and hunting through tabs.
// ─────────────────────────────────────────────
function openQuickBill(tid){
  if(!tenants.length){ showToast('Add a tenant first.', false); return; }
  const sel = document.getElementById('qb-tenant');
  const sorted = tenants.slice().sort((a,b)=>unitRank(a.unit)-unitRank(b.unit));
  sel.innerHTML = sorted.map(t=>`<option value="${esc(t.id)}"${tid===t.id?' selected':''}>${esc(t.name)} · Unit ${esc(t.unit)}${(t.floor||'').trim()?' · '+esc(t.floor):''}</option>`).join('');
  // Label suggestions: template labels first, then distinct recent bill labels.
  const seen = new Set(); const sugg = [];
  const addSugg = s => { const k=(s||'').trim(); if(k && !seen.has(k.toLowerCase())){ seen.add(k.toLowerCase()); sugg.push(k); } };
  tenants.forEach(t=>(t.templates||[]).forEach(x=>addSugg(x.label)));
  tenants.forEach(t=>(t.bills||[]).slice().reverse().forEach(b=>addSugg(b.label)));
  document.getElementById('qb-label-suggestions').innerHTML = sugg.slice(0,12).map(s=>`<option value="${esc(s)}">`).join('');
  // Reset fields
  document.getElementById('qb-label').value='';
  document.getElementById('qb-amount').value='';
  document.getElementById('qb-due').value='';
  document.getElementById('qb-period').value='';
  document.getElementById('qb-cat').value='';
  document.getElementById('qb-remark').value='';
  document.getElementById('qb-scan').value='';
  document.getElementById('qb-paid').checked=false;
  document.getElementById('qb-paiddate-wrap').style.display='none';
  document.getElementById('qb-paiddate').value='';
  const more = document.getElementById('qb-more'); if(more) more.open = false;
  openModal('addbill-modal');
}
function closeQuickBill(){ closeModalEl('addbill-modal'); }
// Show the Date Paid field when a bill is marked paid, pre-filled (visibly) with today.
function _paidToggle(sel, wrapId, inputId){
  const on = sel.value==='paid';
  document.getElementById(wrapId).style.display = on ? 'block' : 'none';
  const inp = document.getElementById(inputId);
  if(on && inp && !inp.value) inp.value = todayISO();
}
function qbTogglePaid(cb){
  document.getElementById('qb-paiddate-wrap').style.display = cb.checked ? 'block' : 'none';
  if(cb.checked && !document.getElementById('qb-paiddate').value){
    document.getElementById('qb-paiddate').value = todayISO();
  }
}
// When the label matches one of this tenant's templates, prefill amount and due date.
function qbAutofill(){
  const label = document.getElementById('qb-label').value.trim().toLowerCase();
  if(!label) return;
  const t = tenants.find(t=>t.id===document.getElementById('qb-tenant').value);
  const _tl = ((t&&t.templates)||[]).filter(x=>(x.label||'').trim().toLowerCase()===label);
  const tmpl = _tl.find(x=>!x.retired) || _tl[0];
  if(!tmpl) return;
  const amtEl = document.getElementById('qb-amount');
  if(!amtEl.value && !tmpl.pendingAmount && Number(tmpl.amount)>0) amtEl.value = tmpl.amount;
  const dueEl = document.getElementById('qb-due');
  if(!dueEl.value && tmpl.dayOfMonth){
    const now = new Date();
    const day = Math.min(Number(tmpl.dayOfMonth), new Date(now.getFullYear(), now.getMonth()+1, 0).getDate());
    dueEl.value = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(day).padStart(2,'0');
  }
}
// Index of an unfilled placeholder (₱0, awaiting its amount) of the same
// charge as a new bill labelled `label` — in the due date's month when one
// is given, else the oldest — or -1.
function _placeholderFor(t, label, due) {
  const probe = { label };
  const tm = templateOfBill(t, probe);
  const ym = due ? String(due).slice(0, 7) : '';
  const cands = (t.bills || []).map((b, i) => ({ b, i })).filter(x => billAwaitingAmount(x.b)
    && (tm ? (templateOfBill(t, x.b) === tm) : normLabel(x.b.label) === normLabel(label)));
  cands.sort((a, b) => (billPeriod(a.b) || '').localeCompare(billPeriod(b.b) || ''));
  const inMonth = ym ? cands.find(x => billPeriod(x.b) === ym) : null;
  return inMonth ? inMonth.i : cands.length ? cands[0].i : -1;
}
async function saveQuickBill(addAnother){
  const tid   = document.getElementById('qb-tenant').value;
  const label = document.getElementById('qb-label').value.trim();
  const t = tenants.find(t=>t.id===tid);
  if(!t){ showToast('Please choose a tenant.', false); return; }
  if(!label){ showToast('Please enter a bill description.', false); return; }
  const rawAmt = Number(String(document.getElementById('qb-amount').value).replace(/,/g,''));
  if(rawAmt < 0){ showToast('Amount cannot be negative.', false); return; }
  const amount = normalizeAmount(document.getElementById('qb-amount').value);
  if(amount===0 && !confirm('Amount is ₱0. Add this bill anyway?')) return;
  const due = document.getElementById('qb-due').value;
  const isPaidQ = document.getElementById('qb-paid').checked;
  // The charge's placeholder for that month is waiting for this amount:
  // fill it instead of adding a second bill.
  const ph = amount > 0 ? _placeholderFor(t, label, due) : -1;
  if(ph >= 0){
    const pb = t.bills[ph];
    if(confirm('"'+pb.label+'"'+(billPeriod(pb)?' for '+fmtYM(billPeriod(pb)):'')+' is already posted and waiting for its amount.\n\nOK: fill it with ₱'+fmtMoney(amount)+'.\nCancel: add a separate bill instead.')){
      if(isPaidQ && !document.getElementById('qb-paiddate').value){ showToast('Enter the date it was paid.',false); return; }
      const paidDateQ = isPaidQ ? document.getElementById('qb-paiddate').value : '';
      const scanQ = document.getElementById('qb-scan').value.trim();
      const remarkQ = document.getElementById('qb-remark').value.trim();
      const ok = await saveBills(tid, bills=>{
        const b = bills[ph];
        if(!b || !billAwaitingAmount(b)) return;
        if(!isYM(b.period) && billPeriod(b)) b.period = billPeriod(b);   // the reading stays in its month
        b.amount = amount;
        if(due) b.due = due;
        b.remark = remarkQ;
        if(/^https:\/\//i.test(scanQ)) b.scanLink = scanQ;
        if(isPaidQ){ b.status = 'paid'; b.paidDate = paidDateQ; }
        else _resyncPaidStatus(b, 0);
      }, 'Amount entered for '+t.name+'.', t);
      if(ok !== true) return;
      rerenderAdmin();
      if(addAnother){ ['qb-label','qb-amount','qb-remark','qb-scan','qb-period','qb-cat'].forEach(id=>{ document.getElementById(id).value=''; }); document.getElementById('qb-paid').checked=false; document.getElementById('qb-paiddate-wrap').style.display='none'; document.getElementById('qb-label').focus(); }
      else closeQuickBill();
      return;
    }
  }
  // Duplicate guard: same label already billed in that month, or a bill
  // that stands for a recurring charge (e.g. "Rent - October") the month
  // already has.
  const qbPeriod = _monthVal('qb-period'), qbCat = _catVal('qb-cat');
  const forYM = qbPeriod || ymOf(due);
  if(forYM && ph < 0){
    const _tm = templateOfBill(t, {label}) || (isRentLabel(label) && qbCat !== 'utilities' && qbCat !== 'other' ? primaryTemplate(t) : null);
    const dup = t.bills.some(b=>(b.label||'').trim().toLowerCase()===label.toLowerCase() && billPeriod(b)===forYM)
      || !!(_tm && templateBillExists(t, _tm, forYM));
    if(dup && !confirm(t.name+' already has a "'+label+'" bill for '+fmtYM(forYM)+'. Add another?')) return;
  }
  const isPaid = document.getElementById('qb-paid').checked;
  if(isPaid && !document.getElementById('qb-paiddate').value){ showToast('Enter the date it was paid.',false); return; }
  const paidDate = isPaid ? document.getElementById('qb-paiddate').value : '';
  const scan = document.getElementById('qb-scan').value.trim();
  const bill = { label, amount, due, status: isPaid?'paid':'unpaid',
    remark: document.getElementById('qb-remark').value.trim(),
    scanLink: /^https:\/\//i.test(scan)?scan:'', paidDate, payments: [] };
  if(qbPeriod && qbPeriod !== ymOf(due)) bill.period = qbPeriod;
  if(qbCat) bill.category = qbCat;
  const ok = await saveBills(tid, bills=>{ bills.push(bill); }, 'Bill added for '+t.name+'.');
  if(ok !== true) return; // form stays filled so the admin can retry
  rerenderAdmin();
  if(addAnother){
    document.getElementById('qb-label').value='';
    document.getElementById('qb-amount').value='';
    document.getElementById('qb-remark').value='';
    document.getElementById('qb-scan').value='';
    document.getElementById('qb-period').value='';
    document.getElementById('qb-cat').value='';
    document.getElementById('qb-paid').checked=false;
    document.getElementById('qb-paiddate-wrap').style.display='none';
    document.getElementById('qb-label').focus();
  } else {
    closeQuickBill();
  }
}


// ─────────────────────────────────────────────
// TENANT PORTAL
// ─────────────────────────────────────────────
// Phones show one view at a time (Home, Bills, How to pay); desktops show
// everything on one page (bills on the left, amount due / how to pay /
// history on the right).
let portalView = 'home';     // phones: 'home' | 'bills' | 'pay'
let portalTab = 'bills';     // Bills view on phones: 'bills' | 'payments'
let _portalAllPays = false;  // payment history: show every receipt
// Phone sub-pages (bills, how to pay) are history entries, so Back returns Home.
function setPortalView(v, fromPop) {
  if(!fromPop && v !== portalView) {
    const inSub = !!(history.state && history.state.pv);
    if(v === 'home' && inSub) { history.back(); return; }
    if(v !== 'home') { if(inSub) history.replaceState({ pv: v }, ''); else history.pushState({ pv: v }, ''); }
  }
  portalView = v; renderTenant(); window.scrollTo(0, 0);
}
window.addEventListener('popstate', e => {
  if(!currentUser || currentUser === 'admin') return;
  setPortalView((e.state && e.state.pv) || 'home', true);
});
function setPortalMonth(ym) { portalMonth = ym; renderTenant(); }
async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px;';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch { ta.remove(); showToast('Could not copy automatically.', false); return; }
    ta.remove();
  }
  showToast((what || 'Text') + ' copied.');
}
// Payment instructions are free text; each "Label: details" line becomes a
// method row with Copy, any other line stays as plain text.
function _payMethods(text) {
  return String(text || '').split(/\n+/).map(l => l.trim()).filter(Boolean).map(l => {
    // "Label: value" — but not a URL, nor a time like "9:00".
    const m = /^[a-z][\w+.-]*:\/\//i.test(l) ? null : /^([^:]{0,39}[^\d\s:])\s*:\s*(.+)$/.exec(l);
    const label = m ? m[1].trim() : '', value = m ? m[2].trim() : l;
    const k = label.toLowerCase();
    const kind = /gcash|maya|paymaya|e-?wallet/.test(k) ? 'wallet' : /bank|bdo|bpi|metrobank|landbank|pnb|unionbank|security|rcbc|chinabank|transfer/.test(k) ? 'bank' : /cash/.test(k) ? 'cash' : 'other';
    return { label, value, kind };
  });
}
function _payMethodsHtml(text) {
  const rows = _payMethods(text);
  if(!rows.length) return '';
  return rows.map(r => {
    const ic = r.kind === 'bank' ? icon('bank') : r.kind === 'cash' ? icon('cash') : '<b>' + esc((r.label || '•').charAt(0).toUpperCase()) + '</b>';
    const copyable = r.label && r.kind !== 'cash' && /\d/.test(r.value);
    return '<div class="pt-method"><span class="pt-method-ic k-' + r.kind + '">' + ic + '</span>'
      + '<span class="pt-method-text">' + (r.label ? '<strong>' + esc(r.label) + '</strong>' : '') + '<span>' + esc(r.value) + '</span></span>'
      + (copyable ? '<button type="button" class="pt-copy" data-copy="' + esc(r.value) + '" data-what="' + esc(r.label) + ' details" onclick="copyText(this.dataset.copy,this.dataset.what)" aria-label="Copy ' + esc(r.label) + ' details">Copy</button>' : '')
      + '</div>';
  }).join('');
}

function renderTenant(){
  const t = currentUser; if(!t) return;
  const today = todayISO(), curYM = today.slice(0, 7);
  const peso2 = v => '&#8369;' + fmtMoney(v);
  const rem = b => Math.max(0, billRemaining(b));
  const first = esc(String(t.name || '').trim().split(/\s+/)[0] || t.name);
  const where = 'Unit ' + esc(t.unit) + ((t.floor || '').trim() ? ' · ' + esc(t.floor) : '');
  const isInclusive = t.billing_model === 'inclusive';
  const monthName = _monthName(curYM);

  // Balances (unpaid = not marked paid; amounts are what's still owed).
  const allActiveBills = t.bills.filter(b => b.status !== 'paid');
  const owing = allActiveBills.filter(b => !billAwaitingAmount(b) && rem(b) > 0.005);
  const thisMonthBills = allActiveBills.filter(b => b.due && b.due.startsWith(curYM));
  const overdueBills = allActiveBills.filter(b => getDueStatus(b) === 'overdue');
  const thisMonthDue = thisMonthBills.reduce((s, b) => s + rem(b), 0);
  const overdueDue = overdueBills.reduce((s, b) => s + rem(b), 0);
  const totalDue = allActiveBills.reduce((s, b) => s + rem(b), 0);
  const catDue = outstandingByCategory(allActiveBills);
  const recon = reconcileTenant(t, { today, leadDays: autoBilling.leadDays });
  const prim = recon.enabled ? recon.charges.find(c => c.tmplId === recon.primaryId) || null : null;
  const mi = moveInOf(t);
  const urgent = owing.slice().sort((a, b) => getDueUrgencyScore(a) - getDueUrgencyScore(b))[0] || null;
  const isLater = b => !!(b.due && b.due.slice(0, 7) > curYM);
  const upcoming = allActiveBills.filter(b => isLater(b) && !billAwaitingAmount(b)).sort((a, b) => a.due.localeCompare(b.due));
  const nextUp = upcoming[0] || null;
  const pastDue = allActiveBills.filter(b => !(b.due && b.due.startsWith(curYM)) && !isLater(b)).reduce((s, b) => s + rem(b), 0);
  // The live rent charge at this month's rate (a retired or stale rate would mislead the tenant).
  const _tmplRate = primaryTemplate(t);
  const flatRate = (_tmplRate ? tmplRateAt(_tmplRate, curYM) : 0) || (!(t.templates || []).length ? Number(t.flat_rate) || 0 : 0);
  const kindOf = b => billCategory(b) === 'rent' ? 'Rent' : esc(b.label || 'Bill');
  // Short kind for the hero pill (the full label is in the text below it).
  const pillKind = b => ({ rent: 'Rent', utilities: 'Utilities' })[billCategory(b)] || 'Bill';
  const ovSince = b => b.due ? 'Overdue since ' + shortDate(b.due) : 'Overdue';
  const paidThru = prim && !prim.variable && prim.paidThrough ? 'Rent is paid through ' + shortDate(prim.paidThrough) + '.' : '';
  const nextCycle = prim && !prim.variable && mi && prim.startYM ? (() => { const w = cycleWindow(mi, addYM(prim.startYM, prim.covered)); return ' Your next cycle runs ' + shortDate(w.start) + ' – ' + shortDate(addDaysISO(w.end, -1)) + '.'; })() : '';

  // ── Hero: amount due ──
  let heroPill = '', heroSub = '', heroLabel = totalDue > 0.005 ? 'Amount due' : 'Nothing owed right now', heroFig = totalDue;
  if(urgent) {
    const ds = getDueStatus(urgent);
    heroPill = ds === 'overdue' ? ovSince(urgent) : ds === 'due-today' ? pillKind(urgent) + ' due today' : ds === 'grace' ? pillKind(urgent) + ' in grace period' : urgent.due ? pillKind(urgent) + ' due ' + shortDate(urgent.due) : pillKind(urgent) + ' to pay';
    heroSub = esc(urgent.label) + ' of ' + peso2(rem(urgent)) + (ds === 'overdue' ? (urgent.due ? ' was due ' + shortDate(urgent.due) + '.' : ' is overdue.') : ds === 'due-today' ? ' is due today.' : urgent.due ? ' is due ' + shortDate(urgent.due) + '.' : ' is open.') + (paidThru ? ' ' + paidThru : '');
  } else if(totalDue <= 0.005 && prim && !prim.variable && prim.nextDue && prim.nextAmount > 0.005) {
    // Paid up: show what comes next for the main rent.
    heroLabel = 'Next payment'; heroFig = prim.nextAmount;
    heroPill = 'Due ' + shortDate(prim.nextDue);
    heroSub = (paidThru ? paidThru + nextCycle : 'Nothing owed right now.');
  } else {
    heroPill = 'All paid up';
    heroSub = (paidThru ? paidThru + nextCycle : 'Nothing owed right now.') + (nextUp ? ' Next bill: ' + peso2(rem(nextUp)) + ' due ' + shortDate(nextUp.due) + '.' : '');
  }
  const hero = '<section class="pt-hero pt-b v-home v-desk">'
    + '<div class="pt-hero-top"><span>' + heroLabel + '</span><span class="pt-hero-pill">' + heroPill + '</span></div>'
    + '<strong class="pt-hero-fig">' + peso2(heroFig) + '</strong>'
    + (isInclusive && flatRate ? '<span class="pt-hero-rate">Monthly rate ' + peso2(flatRate) + ' · utilities included</span>' : '')
    + '<p class="pt-hero-sub">' + heroSub + '</p>'
    + (paymentInstructions ? '<button type="button" class="pt-hero-btn" onclick="setPortalView(\'pay\')">How to pay</button>' : '')
    + '</section>';

  // ── Desktop stat strip ──
  const stat = (label, value, sub, cls) => '<div class="pt-stat"><span class="pt-stat-label">' + label + '</span><strong class="pt-stat-fig ' + (cls || '') + '">' + value + '</strong><span class="pt-stat-sub">' + sub + '</span></div>';
  const listShort = bills => bills.slice(0, 2).map(b => kindOf(b) + ' ' + peso2(rem(b)) + (b.due ? (getDueStatus(b) === 'due-today' ? ' due today' : ' due ' + shortDate(b.due)) : '')).join(', ') + (bills.length > 2 ? ' +' + (bills.length - 2) + ' more' : '');
  const catLine = [catDue.rent ? 'Rent ' + peso2(catDue.rent) : '', catDue.utilities ? 'Utilities ' + peso2(catDue.utilities) : '', catDue.other ? 'Other ' + peso2(catDue.other) : ''].filter(Boolean).join(' · ');
  let strip;
  if(isInclusive) {
    const curMonthBills = t.bills.filter(b => b.due && b.due.startsWith(curYM));
    const cmUnpaid = curMonthBills.filter(b => b.status !== 'paid' && !billAwaitingAmount(b));
    const cmPaid = curMonthBills.filter(b => b.status === 'paid');
    let mv, ms, mc = '';
    if(cmUnpaid.length) {
      const most = cmUnpaid.slice().sort((a, b) => getDueUrgencyScore(a) - getDueUrgencyScore(b))[0];
      const ds = getDueStatus(most);
      mv = peso2(thisMonthDue); mc = ds === 'overdue' ? 'bad' : '';
      ms = ds === 'overdue' ? 'Overdue — was due ' + shortDate(most.due) : ds === 'due-today' ? 'Due today' : 'Due ' + shortDate(most.due);
    } else if(cmPaid.length) {
      const lp = cmPaid.slice().sort((a, b) => (b.paidDate || '').localeCompare(a.paidDate || ''))[0];
      mv = 'Paid'; mc = 'good'; ms = (lp.paidDate ? 'Paid ' + shortDate(lp.paidDate) : 'Thank you!') + (nextUp ? ' · next due ' + shortDate(nextUp.due) : '');
    } else { mv = 'No bill yet'; mc = 'good'; ms = flatRate ? peso2(flatRate) + ' expected for ' + monthName : 'Nothing posted for ' + monthName + ' yet'; }
    strip = stat('Monthly rate', flatRate ? peso2(flatRate) : '&mdash;', 'Utilities included')
      + stat(monthName, mv, ms, mc)
      + stat('Past due', pastDue > 0.005 ? peso2(pastDue) : 'None', pastDue > 0.005 ? 'From earlier months — listed in your bills' : 'You are fully caught up', pastDue > 0.005 ? 'bad' : 'good');
  } else {
    const tmUnpaid = thisMonthBills.filter(b => rem(b) > 0.005 && !billAwaitingAmount(b)).sort((a, b) => getDueUrgencyScore(a) - getDueUrgencyScore(b));
    strip = stat('This month', thisMonthDue > 0.005 ? peso2(thisMonthDue) : 'Settled', tmUnpaid.length ? listShort(tmUnpaid) : 'Nothing left to pay for ' + monthName, thisMonthDue > 0.005 ? '' : 'good')
      + stat('Overdue', overdueDue > 0.005 ? peso2(overdueDue) : 'None', overdueDue > 0.005 ? overdueBills.length + ' bill' + (overdueBills.length !== 1 ? 's' : '') + ' past due' : 'Nothing late. Thank you!', overdueDue > 0.005 ? 'bad' : 'good')
      + stat('Total outstanding', totalDue > 0.005 ? peso2(totalDue) : 'Settled', totalDue > 0.005 ? catLine : 'You are fully caught up', totalDue > 0.005 ? '' : 'good');
  }

  // ── Bills: month pills, rows, footer ──
  const monthSet = new Set();
  allActiveBills.forEach(b => { if(b.due) monthSet.add(b.due.slice(0, 7)); });
  t.bills.forEach(b => { const ym = (b.due || '').slice(0, 7); if(ym && ym <= curYM && ym >= addYM(curYM, -2)) monthSet.add(ym); });
  monthSet.add(curYM);
  const monthList = Array.from(monthSet).sort().reverse();
  const activeYM = portalMonth === 'current' ? curYM : portalMonth;
  const isAll = portalMonth === 'all';
  // Bills with no due date are open obligations in every view.
  const inView = isAll ? allActiveBills.slice() : t.bills.filter(b => (b.due && b.due.startsWith(activeYM)) || (!b.due && b.status !== 'paid'));
  const viewBills = inView.filter(b => b.status !== 'paid').sort((a, b) => getDueUrgencyScore(a) - getDueUrgencyScore(b))
    .concat(inView.filter(b => b.status === 'paid').sort((a, b) => (b.due || '').localeCompare(a.due || '')));
  const due = viewBills.filter(b => b.status !== 'paid').reduce((s, b) => s + rem(b), 0);
  const hiddenLater = isAll ? 0 : allActiveBills.filter(b => b.due && b.due.slice(0, 7) > activeYM).reduce((s, b) => s + rem(b), 0);
  const hiddenEarlier = isAll ? 0 : Math.max(0, totalDue - due - hiddenLater);
  const activeMonthName = isAll ? '' : fmtYM(activeYM);
  const pillFor = b => {
    const ds = getDueStatus(b);
    if(ds === 'paid') return oaPill('paid', b.paidDate ? 'Paid ' + shortDate(b.paidDate) : 'Paid');
    if(ds === 'awaiting') return oaPill('neutral', 'Not billed yet');
    if(ds === 'overdue') return oaPill('late', 'Overdue' + (b.due ? ' · ' + daysOverdue(b) + 'd' : ''));
    if(ds === 'grace') return oaPill('due', 'Grace period');
    if(ds === 'due-today') return oaPill('due', 'Due today');
    if(ds === 'no-date') return oaPill('neutral', 'Open');
    return oaPill('due', 'Due ' + shortDate(b.due));
  };
  const subFor = b => {
    const bits = [];
    if(billAwaitingAmount(b)) bits.push('Waiting for the meter reading');
    else {
      const per = billPeriod(b);
      if(mi && per && prim && b.tmplId === prim.tmplId) { const w = cycleWindow(mi, per); bits.push((isInclusive ? 'All-inclusive · ' : '') + shortDate(w.start) + ' – ' + shortDate(addDaysISO(w.end, -1))); }
      if(b.due) bits.push('due ' + shortDate(b.due));
    }
    const paid = billTotalPaid(b);
    if(paid > 0.005 && b.status !== 'paid') bits.push(peso2(paid) + ' paid · ' + peso2(rem(b)) + ' still due');
    if(b.remark && !/pending amount/i.test(b.remark)) bits.push(esc(b.remark));
    return bits.join(' · ');
  };
  const scan = b => b.scanLink && /^https:\/\//i.test(b.scanLink) ? ' <a class="pt-scan" href="' + esc(b.scanLink) + '" target="_blank" rel="noopener">View bill</a>' : '';
  const billRow = b => '<div class="pt-bill' + (b.status === 'paid' ? ' is-paid' : billAwaitingAmount(b) ? ' is-wait' : '') + '">'
    + '<div class="pt-bill-main"><span class="pt-bill-label">' + esc(b.label) + '</span><span class="pt-bill-sub">' + subFor(b) + scan(b) + '</span></div>'
    + '<span class="pt-bill-status">' + pillFor(b) + '</span>'
    + '<span class="pt-bill-amt">' + (billAwaitingAmount(b) ? '&mdash;' : peso2(b.amount)) + '</span></div>';
  const showPills = monthList.length > 1;
  const pills = showPills ? '<div class="pt-pills" role="group" aria-label="Month">'
    + '<button type="button" class="pt-pill' + (isAll ? ' active' : '') + '" aria-pressed="' + isAll + '" onclick="setPortalMonth(\'all\')">All</button>'
    + monthList.map(ym => { const on = !isAll && activeYM === ym; return '<button type="button" class="pt-pill' + (on ? ' active' : '') + '" aria-pressed="' + on + '" onclick="setPortalMonth(\'' + ym + '\')">' + fmtYM(ym, 'short') + '</button>'; }).join('') + '</div>' : '';
  const emptyMsg = isAll ? 'All bills are settled.'
    : hiddenEarlier > 0 ? 'No bills for ' + activeMonthName + ' — but ' + peso2(hiddenEarlier) + ' is still owed from earlier months. <button type="button" class="link-btn inline" onclick="setPortalMonth(\'all\')">View all bills</button>'
    : hiddenLater > 0 ? 'Nothing due for ' + activeMonthName + '. Your next bill' + (nextUp ? ' (' + peso2(rem(nextUp)) + ', due ' + shortDate(nextUp.due) + ')' : '') + ' is already posted. <button type="button" class="link-btn inline" onclick="setPortalMonth(\'all\')">View all bills</button>'
    : 'No bills for ' + activeMonthName + '.';
  const footNote = !isAll && (hiddenEarlier > 0.005 || hiddenLater > 0.005) ? '<span class="pt-foot-note">' + (hiddenEarlier > 0.005 ? 'Total owed, all months: ' : 'Including bills posted for later months: ') + '<strong>' + peso2(totalDue) + '</strong></span>' : '';

  // ── Payment history ──
  const receipts = tenantReceipts(t).filter(x => x.amount > 0);
  const payRows = list => list.map(x => '<div class="pt-pay"><span class="pt-pay-ic">' + icon('check') + '</span>'
    + '<div class="pt-pay-main"><div class="pt-pay-top"><strong>' + (x.date ? shortDateY(x.date) : 'Date not recorded') + '</strong><strong>' + peso2(x.amount) + '</strong></div>'
    + '<span class="pt-pay-sub">' + [x.note ? esc(x.note) : '', receiptAppliedTo(x)].filter(Boolean).join(' · ') + '</span></div></div>').join('');
  const shownPays = _portalAllPays ? receipts : receipts.slice(0, 3);
  const payList = receipts.length ? '<div class="pt-pays">' + payRows(shownPays) + '</div>'
    + (receipts.length > 3 ? '<button type="button" class="pt-more" onclick="_portalAllPays=!_portalAllPays;renderTenant()">' + (_portalAllPays ? 'Show less' : 'Show all ' + receipts.length + ' payments') + '</button>' : '')
    : '<div class="pt-empty">No payments recorded yet.</div>';
  const stmtBtn = '<button type="button" class="pt-stmt" onclick="openStmtModal(currentUser)">' + icon('download') + '<span>Statement</span></button>';

  const billsCard = '<section class="pt-card pt-bills pt-b v-bills v-desk tab-' + portalTab + '">'
    + '<div class="pt-card-head"><h2>Your bills</h2>' + stmtBtn + '</div>'
    + '<div class="pt-tabs">' + segTabs([['bills', 'Bills'], ['payments', 'Payments']].map(([k, l]) => ({ label: l, active: portalTab === k, onclick: 'portalTab=\'' + k + '\';renderTenant()' })), '', 'Bills or payments') + '</div>'
    + '<div class="pt-billpane">' + pills
    +   (viewBills.length ? '<div class="pt-thead"><span>Bill</span><span>Status</span><span class="r">Amount</span></div>' + viewBills.map(billRow).join('') : '<div class="pt-empty">' + emptyMsg + '</div>')
    +   '<div class="pt-foot"><div><span class="pt-foot-label">' + (due > 0.005 ? (isAll ? 'Total owed' : 'Owed for ' + activeMonthName) : (isAll || totalDue <= 0.005 ? 'Nothing owed' : 'Nothing owed for ' + activeMonthName)) + '</span>' + footNote + '</div><strong>' + (due > 0.005 ? peso2(due) : 'Settled') + '</strong></div></div>'
    + '<div class="pt-paypane">' + payList + '</div>'
    + '</section>';

  // Phone home: what's open now, with a link to every bill.
  const breakdownBills = allActiveBills.slice().sort((a, b) => getDueUrgencyScore(a) - getDueUrgencyScore(b)).slice(0, 4);
  const breakdown = '<section class="pt-card pt-break pt-b v-home">'
    + (breakdownBills.length ? breakdownBills.map(b => { const ds = getDueStatus(b);
        return '<div class="pt-brow"><div><span class="pt-bill-label">' + esc(b.label) + '</span><span class="pt-brow-sub ' + (ds === 'overdue' ? 'bad' : ds === 'due-today' || ds === 'grace' ? 'warn' : '') + '">'
          + (billAwaitingAmount(b) ? 'Waiting for the meter reading' : ds === 'overdue' ? ovSince(b) : ds === 'due-today' ? 'Due today' : b.due ? 'Due ' + shortDate(b.due) : 'Open') + '</span></div>'
          + '<strong>' + (billAwaitingAmount(b) ? '&mdash;' : peso2(rem(b))) + '</strong></div>'; }).join('')
      : '<div class="pt-empty">' + icon('check') + ' Nothing to pay right now.</div>')
    + '<button type="button" class="pt-more" onclick="setPortalView(\'bills\')">See all bills' + icon('next') + '</button></section>';

  const ann = announcements ? '<div class="pt-ann-ic">' + icon('megaphone') + '</div><div><strong>From the building</strong><p>' + esc(announcements) + '</p></div>' : '';
  const howto = paymentInstructions ? _payMethodsHtml(paymentInstructions) : '';
  const howCard = howto ? '<section class="pt-card pt-how pt-b v-pay v-desk"><div class="pt-card-head"><h2>How to pay</h2></div>' + howto
    + '<p class="pt-how-foot">After paying, send your reference number to the admin. Your balance updates once it\'s recorded.</p></section>' : '';
  const history = '<section class="pt-card pt-history pt-b v-home v-desk"><div class="pt-card-head"><h2><span class="only-desk">Payment history</span><span class="only-phone">Recent payments</span></h2>' + stmtBtn + '</div>' + payList + '</section>';
  const back = '<button type="button" class="pt-back pt-b v-bills v-pay" onclick="setPortalView(\'home\')">' + icon('back') + 'Home</button>';
  const payIntro = '<div class="pt-b v-pay pt-pay-intro"><h1 class="pt-title">How to pay</h1><p>' + (totalDue > 0.005 ? 'You owe ' + peso2(totalDue) + '.' + (urgent ? ' ' + heroSub.split('. ')[0].replace(/\.$/, '') + '.' : '') + ' Use any of these:' : 'Nothing is owed right now. When a bill comes, use any of these:') + '</p></div>';
  const afterCard = '<section class="pt-card pt-b v-pay pt-after"><h2>After you pay</h2><ol><li>Send your reference number to the admin.</li><li>Your balance updates here once the payment is recorded.</li></ol></section>'
    + '<p class="pt-b v-pay pt-note">These instructions come from the building\'s settings and can be edited by the admin.</p>';
  const noHow = !howto ? '<section class="pt-card pt-b v-pay"><div class="pt-empty">The admin hasn\'t added payment instructions yet — ask them how to pay.</div></section>' : '';

  document.getElementById('main-content').innerHTML = '<div class="pt-wrap pv-' + portalView + '">'
    + back
    + '<div class="pt-hello pt-b v-home v-desk"><span class="only-phone pt-unit">' + where + '</span><h1 class="pt-title">Hi, ' + first + '</h1>'
    +   '<span class="only-desk pt-hello-sub">' + where + ' · If anything here looks wrong, message the admin.</span></div>'
    + (ann ? '<div class="pt-ann only-desk">' + ann + '</div>' : '')
    + payIntro
    + '<div class="pt-grid"><div class="pt-col">'
    +   '<div class="pt-strip only-desk">' + strip + '</div>'
    +   billsCard
    + '</div><div class="pt-col">'
    +   hero + breakdown
    +   (ann ? '<div class="pt-ann only-phone pt-b v-home">' + ann + '</div>' : '')
    +   howCard + noHow + afterCard
    +   history
    + '</div></div></div>';
}

function uid() {
  if(crypto.randomUUID) return crypto.randomUUID();
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, b=>b.toString(16).padStart(2,'0')).join('');
}
function normalizeAmount(val) {
  // Accept "1,234.50" plus plain numbers; reject negatives and non-finite
  // values ("Infinity" JSON-serializes to null and would wipe the amount).
  if(val == null) return 0;
  const cleaned = String(val).replace(/,/g,'').trim();
  const n = Number(cleaned);
  if(!isFinite(n) || n < 0) return 0;
  return Math.round(n * 100) / 100;
}

// Today as YYYY-MM-DD in the USER'S timezone. toISOString() is UTC, which
// stamped yesterday's date on payments recorded before 8 AM Philippine time.
function todayISO() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0');
}

function randCode(){
  const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  const pick = b => c[b % c.length];
  return Array.from(buf.slice(0,4), pick).join('') + '-' + Array.from(buf.slice(4), pick).join('');
}
function esc(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
const _LONG_DATE_FMT = new Intl.DateTimeFormat('en-PH', { month: 'long', day: 'numeric', year: 'numeric' });
function formatDate(d) {
  if(!d) return '';
  const dateStr = String(d).slice(0,10);
  const dt = new Date(dateStr+'T00:00:00');
  if(isNaN(dt.getTime())) {
    console.warn('formatDate: invalid date', d);
    // Escaped: this return value flows into innerHTML sinks, and echoing a
    // malformed value raw would be a stored-XSS foothold.
    return esc(String(d));
  }
  return _LONG_DATE_FMT.format(dt);
}
const _SHORT_DATE_FMT = new Intl.DateTimeFormat('en-PH', { month: 'short', day: 'numeric' });
// Compact date for tight UI (badges, expense rows): "Aug 5"
function shortDate(d) {
  if(!d) return '';
  const dt = new Date(String(d).slice(0,10)+'T00:00:00');
  if(isNaN(dt.getTime())) return esc(String(d));
  return _SHORT_DATE_FMT.format(dt);
}
let _portalSettingsPromise = null;
document.addEventListener('DOMContentLoaded',()=>{
  const _wire = (id, fn) => { const el=document.getElementById(id); if(el) el.addEventListener('click',e=>{if(e.target===el)fn();}); };
  _wire('tenant-modal',  closeModal);
  _wire('paiddate-modal', closePaidModal);
  _wire('moveout-modal', closeMoveOut);
  _wire('stmt-modal',    closeStmtModal);
  _wire('incstmt-modal', closeIncStmtModal);
  _wire('genbills-modal', closeGenModal);
  _wire('addbill-modal', closeQuickBill);
  _wire('pay-modal',     closePayModal);

  // Apply the cached property name instantly (no flash of the default),
  // then refresh from the server in the background.
  try {
    const cached = JSON.parse(localStorage.getItem('oa_branding'));
    if(cached && cached.name) { propertyName = cached.name; propertySubtitle = cached.sub || propertySubtitle; }
  } catch {}
  applyBranding();
  try { if(localStorage.getItem('oa_login_tab') === 'admin') switchTab('admin'); } catch {}
  _portalSettingsPromise = loadPortalSettings().catch(()=>{});

  // Detect Supabase password recovery redirect
  checkPasswordRecovery();

  // Silent login from a portal link or a remembered code.
  tryAutoLogin();
});

async function checkPasswordRecovery() {
  const hash = window.location.hash.substring(1);
  if(!hash) return;
  const params = new URLSearchParams(hash);
  const type = params.get('type');
  const accessToken = params.get('access_token');
  const refreshToken = params.get('refresh_token');
  if(type !== 'recovery' || !accessToken) return;

  if(!refreshToken) {
    console.warn('Password-recovery link missing refresh_token; the session may not persist.');
  }
  // Set the session from the recovery token
  try {
    await _sbClient.auth.setSession({ access_token: accessToken, refresh_token: refreshToken || '' });
  } catch(e) {
    document.getElementById('login-error').textContent = 'Recovery link expired or invalid. Please request a new one.';
    return;
  }

  // Clear the hash from URL
  history.replaceState(null, '', window.location.pathname);

  // Show password reset form
  const loginWrap = document.querySelector('.login-wrap');
  const pName = esc((propertyName || 'Orange Apartment').trim() || 'Orange Apartment');
  loginWrap.innerHTML = `
    <div class="login-brand">
      <span class="login-logo" aria-hidden="true">${esc(pName.charAt(0).toUpperCase())}</span>
      <div class="login-wordmark">${pName}</div>
      <div class="login-kicker">Property admin</div>
    </div>
    <div class="login-card">
      <h1 class="login-heading">Set a new password</h1>
      <p class="login-sub">Enter your new password below.</p>
      <div class="field"><label for="reset-pw">New password</label><input type="password" id="reset-pw" autocomplete="new-password" placeholder="Enter new password" onkeydown="if(event.key==='Enter')submitPasswordReset()"></div>
      <div class="field"><label for="reset-pw-confirm">Confirm password</label><input type="password" id="reset-pw-confirm" autocomplete="new-password" placeholder="Confirm new password" onkeydown="if(event.key==='Enter')submitPasswordReset()"></div>
      <button class="btn-primary" onclick="submitPasswordReset()">Update password</button>
      <div class="login-error" id="reset-error" role="alert"></div>
    </div>
    <div class="powered-by powered-by-login">Powered by JEZ</div>
  `;
}

async function submitPasswordReset() {
  const pw = document.getElementById('reset-pw').value;
  const confirmValue = document.getElementById('reset-pw-confirm').value;
  const errEl = document.getElementById('reset-error');
  errEl.textContent = '';
  if(!pw || pw.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; return; }
  if(pw !== confirmValue) { errEl.textContent = 'Passwords do not match.'; return; }
  setLoading(true, 'Updating password…');
  try {
    const { error } = await _sbClient.auth.updateUser({ password: pw });
    setLoading(false);
    if(error) { errEl.textContent = error.message; return; }
    await _sbClient.auth.signOut();
    showToast('Password updated. Please sign in with your new password.');
    setTimeout(() => location.reload(), 2000);
  } catch(e) {
    setLoading(false);
    errEl.textContent = 'Update failed: ' + e.message;
  }
}

let _lastWidth = window.innerWidth, _rt;
window.addEventListener('resize',()=>{
  clearTimeout(_rt);
  _rt = setTimeout(()=>{
    const w = window.innerWidth;
    const crossed = (_lastWidth<=768&&w>768)||(_lastWidth>768&&w<=768);
    _lastWidth = w;
    // Phone and desktop layouts differ at 768px (bill sort control, chart range).
    // Only the Dashboard (chart range) and the bills table (sort control) depend on it.
    if(crossed && currentUser==='admin') { if(_adminModule === 'home') _safeRerender(); else if(document.getElementById('bill-rows')) renderBillRows(); }
  }, 250);
});

// ─────────────────────────────────────────────
// PAYMENT REMINDER GENERATOR
// Builds a ready-to-send message with the tenant's outstanding bills and the
// payment instructions, and copies it to the clipboard so the landlord can
// paste it straight into SMS / Messenger / Viber.
// ─────────────────────────────────────────────
function buildReminderText(t){
  const active = t.bills
    .filter(b=>b.status!=='paid' && Math.max(0,billRemaining(b))>0)
    .sort((a,b)=>getDueUrgencyScore(a)-getDueUrgencyScore(b));
  if(!active.length) return null;
  const lines = active.map(b=>{
    const late = daysOverdue(b);
    const partial = billTotalPaid(b) > 0 ? ' (₱'+billTotalPaid(b).toLocaleString()+' already received)' : '';
    return '• '+b.label+' — ₱'+Math.max(0,billRemaining(b)).toLocaleString()
      + (b.due ? ', due '+formatDate(b.due) : '')
      + (late>0 ? ' ('+late+' day'+(late>1?'s':'')+' overdue)' : '')
      + partial;
  });
  const total = active.reduce((s,b)=>s+Math.max(0,billRemaining(b)),0);
  return 'Hi '+t.name+', this is a friendly reminder from '+propertyName+'.\n\n'
    + 'Outstanding bills for Unit '+t.unit+':\n'
    + lines.join('\n') + '\n\n'
    + 'Total due: ₱'+total.toLocaleString()
    + (paymentInstructions ? '\n\nHow to pay:\n'+paymentInstructions : '')
    + '\n\nView your bills anytime: '+portalLinkFor(t)
    + '\n\nThank you!';
}

// One-tap portal link for a tenant — the code in the URL logs them straight in.
function portalLinkFor(t){
  return window.location.origin + window.location.pathname + '?code=' + encodeURIComponent(t.code);
}
async function copyPortalLink(tid){
  const t = tenants.find(t=>t.id===tid); if(!t) return;
  const link = portalLinkFor(t);
  const done = () => showToast('Portal link for '+t.name+' copied — send it via SMS / Messenger / Viber.');
  try {
    await navigator.clipboard.writeText(link);
    done();
  } catch {
    const ta = document.createElement('textarea');
    ta.value = link;
    ta.style.cssText = 'position:fixed;left:-9999px;';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); }
    catch { showToast('Could not copy automatically.', false); }
    ta.remove();
  }
}
async function copyReminder(tid){
  const t = tenants.find(t=>t.id===tid); if(!t) return;
  const text = buildReminderText(t);
  if(!text){ showToast('No outstanding balance for '+t.name+'.'); return; }
  try {
    await navigator.clipboard.writeText(text);
    showToast('Reminder for '+t.name+' copied — paste into SMS / Messenger / Viber.');
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px;';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showToast('Reminder for '+t.name+' copied — paste into SMS / Messenger / Viber.'); }
    catch { showToast('Could not copy automatically.', false); }
    ta.remove();
  }
}

// ─────────────────────────────────────────────
// QUICK MARK PAID (from Action Required)
// ─────────────────────────────────────────────
function quickMarkPaid(tid, bi) {
  const t = tenants.find(t=>t.id===tid);
  if(!t||!t.bills[bi]) return;
  _pendingPaid = {tid, bi, t, bill: t.bills[bi]};
  document.getElementById('paiddate-bill-name').textContent = t.bills[bi].label + ' — ' + t.name;
  document.getElementById('paiddate-input').value = todayISO();
  openModal('paiddate-modal');
}

// ─────────────────────────────────────────────
// TEMPLATE MANAGEMENT
// ─────────────────────────────────────────────
const SCHEMA_NOTE = 'Templates column missing in Supabase. Run this SQL in your Supabase dashboard:\n\nALTER TABLE tenants ADD COLUMN IF NOT EXISTS templates jsonb NOT NULL DEFAULT \'[]\';\n\nThen refresh and try again.';
// Error message for missing templates column
const SCHEMA2_NOTE = 'Your database is missing the v2 columns (billing model / flat rate / floor).\n\nRun supabase-migration-2.sql in the Supabase SQL Editor (Dashboard > SQL Editor), then refresh and try again.';

function renderTemplateList() {
  const t = tenants.find(t=>t.id===editingId); if(!t) return;
  _tmplListT = t;
  const tmpls = t.templates || [];
  const c = document.getElementById('tmpl-list');
  if(!tmpls.length) {
    c.innerHTML = '<div class="tmpl-empty">No templates yet. Add one to auto-generate recurring bills.</div>';
    return;
  }
  c.innerHTML = tmpls.map((tmpl,i) => `
    <div class="tmpl-item">
      <div class="tmpl-info">
        <div class="tmpl-label">${esc(tmpl.label)}</div>
        <div class="tmpl-meta">
          ${tmpl.pendingAmount ? '<span style="color:var(--orange-text);font-weight:600;">Pending amount</span>' : '&#8369;'+Number(tmpl.amount).toLocaleString()}
          &nbsp;·&nbsp; Due on day ${tmplDay(tmpl)} of each month
          &nbsp;·&nbsp; ${tmpl.retired ? '<span style="color:var(--muted);font-weight:600;">Stopped — not billed or owed</span>' : isAutoTemplate(tmpl) ? '<span style="color:var(--green);font-weight:600;">Auto-posts</span>' : 'Manual'}
          ${isYM(tmpl.postedThrough) ? '&nbsp;·&nbsp; posted through '+fmtYM(tmpl.postedThrough,'short') : ''}
        </div>
      </div>
      <div style="display:flex;gap:5px">
        <button class="btn-icon" onclick="editTemplateInline(${i})" aria-label="Edit">&#9998;</button>
        <button class="btn-icon" onclick="setTemplateStopped(${i}, ${tmpl.retired ? 'false' : 'true'})" aria-label="${tmpl.retired ? 'Resume charge' : 'Stop charge'}" title="${tmpl.retired ? 'Resume this charge' : 'Stop this charge (keep its history)'}">${tmpl.retired ? '&#9654;' : '&#10074;&#10074;'}</button>
        <button class="btn-icon del" onclick="deleteTemplate(${i})" aria-label="Delete">&#10005;</button>
      </div>
    </div>
    <div id="tmpl-edit-inline-${i}" style="display:none"></div>
  `).join('');
}

function editTemplateInline(i) {
  document.querySelectorAll('[id^="tmpl-edit-inline-"]').forEach(el=>el.style.display='none');
  const t = tenants.find(t=>t.id===editingId); if(!t||!t.templates||!t.templates[i]) return;
  const tmpl = t.templates[i];
  const el = document.getElementById('tmpl-edit-inline-'+i);
  el.style.display = 'block';
  el.innerHTML = `<div class="tmpl-edit-form">
    <div class="form-grid">
      <div class="field"><label>Description</label><input type="text" id="te-label-${i}" value="${esc(tmpl.label)}" placeholder="e.g. Monthly Rent"></div>
      <div class="field"><label>Amount (&#8369;)</label><input type="text" id="te-amount-${i}" inputmode="decimal" pattern="[0-9.]*" autocomplete="off" value="${tmpl.pendingAmount?'':tmpl.amount}" step="0.01" ${tmpl.pendingAmount?'disabled style="opacity:0.4"':''}></div>
      <div class="field"><label>Due Day of Month <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(auto-caps to last day for shorter months)</span></label><input type="number" id="te-day-${i}" value="${tmpl.dayOfMonth}" min="1" max="31" placeholder="1-31"></div>
      <div class="field full" style="display:flex;align-items:center;gap:10px;padding-top:4px;">
        <input type="checkbox" id="te-pending-${i}" ${tmpl.pendingAmount?'checked':''} onchange="(function(){var a=document.getElementById('te-amount-${i}');a.disabled=this.checked;a.style.opacity=this.checked?'0.4':'1';}).call(this)" style="width:15px;height:15px;accent-color:var(--blue);cursor:pointer;">
        <label for="te-pending-${i}" style="font-size:11px;font-weight:600;letter-spacing:0.05em;color:var(--navy);cursor:pointer;text-transform:uppercase;">Pending amount <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(bill created with no amount; you update it when the bill arrives)</span></label>
      </div>
      <div class="field full check-field">
        <input type="checkbox" id="te-auto-${i}" ${tmpl.auto!==false?'checked':''}>
        <label for="te-auto-${i}">Post automatically each cycle <span class="opt">(ahead of the due date, rent in advance)</span></label>
      </div>
      ${_catField('te-cat-'+i, tmpl.category || '', tmpl.label, true)}
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn-cancel" style="flex:1;padding:9px;" onclick="document.getElementById('tmpl-edit-inline-${i}').style.display='none'">Cancel</button>
      <button class="btn-save" style="flex:2;padding:9px;" onclick="saveTemplateEdit(${i})">Save</button>
    </div>
  </div>`;
}


function templateSaveErr(e) {
  if(e.message.includes('templates')) { alert(SCHEMA_NOTE); }
  else { showToast('Save failed: '+e.message, false); }
}

async function saveTemplateEdit(i) {
  const _isPending = (function(){ const el=document.getElementById('te-pending-'+i); return el?el.checked:false; })();
  // Parse like every other money field: commas allowed, negatives rejected.
  const amtRaw = document.getElementById('te-amount-'+i).value;
  const amtNum = Number(String(amtRaw).replace(/,/g,'').trim());
  if(!_isPending && (isNaN(amtNum) || amtNum < 0)){ showToast('Amount must be a non-negative number.', false); return; }
  const amt = _isPending ? 0 : normalizeAmount(amtRaw);
  if(!_isPending&&amt===0){if(!confirm('The amount is currently set to ₱0. Save anyway?')) return;}
  const day = Number(document.getElementById('te-day-'+i).value);
  if(!day||day<1||day>31){showToast('Due day must be between 1 and 31.',false);return;}
  await _autoBillIdle();
  if(_formStale(_tmplListT)){ renderTemplateList(); rerenderAdmin(); return; }
  const t = tenants.find(t=>t.id===editingId); if(!t||!t.templates||!t.templates[i]) return;
  // Copy → save → commit, so a failed request never leaves the UI diverged.
  const templatesCopy = structuredClone(t.templates);
  const _label = document.getElementById('te-label-'+i).value.trim();
  if(!_label){ showToast('Please enter a template description.',false); return; }
  const _autoEl = document.getElementById('te-auto-'+i);
  // A renamed charge remembers its old name so untagged bills posted under
  // it still count as this charge's history.
  const _prev = templatesCopy[i];
  const _aliases = new Set(Array.isArray(_prev.aliases) ? _prev.aliases : []);
  const _renamed = normLabel(_prev.label) && normLabel(_prev.label) !== normLabel(_label);
  // Renaming back to an earlier name undoes the rename: the name in between
  // is kept only if bills were actually posted under it.
  const _revert = Array.from(_aliases).some(a => normLabel(a) === normLabel(_label));
  // Kept only if hand-typed (untagged) bills got that name while the charge
  // carried it — never for older bills that happened to share it.
  const _live = new Set((t.templates||[]).map(x => x && x.id).filter(Boolean));
  const _typedUnderPrev = isYM(_prev.renamedAt) && (t.bills||[]).some(b => b && !(b.tmplId && _live.has(b.tmplId))
    && normLabel(b.label) === normLabel(_prev.label) && (billPeriod(b) || '') >= _prev.renamedAt);
  if(_renamed && (!_revert || _typedUnderPrev)) _aliases.add(_prev.label);
  // Taking a name hand-typed bills already use makes them this charge's.
  if(_renamed && !_revert) {
    const clash = (t.bills||[]).filter(b => b && !b.tmplId && normLabel(b.label) === normLabel(_label) && (templateOfBill(t, b) || {}).id !== _prev.id);
    if(clash.length && !confirm(clash.length + ' existing bill' + (clash.length !== 1 ? 's are' : ' is') + ' already labelled "' + _label + '". After the rename '
      + (clash.length !== 1 ? 'they' : 'it') + ' will count as this charge\'s bill' + (clash.length !== 1 ? 's' : '') + '.\n\nRename anyway?')) return;
  }
  // An old name that is (now) another charge's name belongs to that charge.
  const _others = new Set(templatesCopy.filter((x,k)=>k!==i && x).map(x=>normLabel(x.label)));
  _aliases.forEach(a => { if(normLabel(a) === normLabel(_label) || _others.has(normLabel(a))) _aliases.delete(a); });
  const _next = {
    ..._prev,
    aliases: Array.from(_aliases),
    label:  _label,
    dayOfMonth: day,
    auto: _autoEl ? _autoEl.checked : _prev.auto !== false
  };
  if(_renamed) _next.renamedAt = _currentYM();
  // A rate change keeps the old amount for past cycles (see tmplRateAt).
  if(!_isPending && !_prev.pendingAmount) _recordRateChange(t, _next, amt); else _next.amount = amt;
  // A metered charge switched to a fixed amount is reckoned from now on.
  if(_prev.pendingAmount && !_isPending) _next.since = _sinceFor(t, _next);
  _next.pendingAmount = _isPending;
  // Category: set on the charge and carried onto every bill of it.
  const _cat = _catVal('te-cat-'+i);
  if(_cat) _next.category = _cat; else delete _next.category;
  let billsCopy = null;
  if((_prev.category || '') !== _cat) {
    billsCopy = structuredClone(t.bills || []);
    billsCopy.forEach((b, k) => {
      if(!b || (templateOfBill(t, t.bills[k]) || {}).id !== _prev.id) return;
      if(_cat) b.category = _cat; else delete b.category;
    });
  }
  templatesCopy[i] = _next;
  try {
    await dbUpdateTenantGuarded(t, billsCopy ? {templates: templatesCopy, bills: billsCopy} : {templates: templatesCopy});
    t.templates = templatesCopy;
    if(billsCopy) t.bills = billsCopy;
    showToast('Template saved.');
    await runAutoBilling({ only: t.id });
    renderTemplateList();
    rerenderAdmin();
  } catch(e){ if(e.conflict){ showToast(e.message,false); renderTemplateList(); rerenderAdmin(); } else templateSaveErr(e); }
}

// Stop a charge: no longer posted, and no longer owed (the checker leaves
// it alone); its bills, waivers and old names stay. Resume restarts it
// from the current cycle.
async function setTemplateStopped(i, stop) {
  await _autoBillIdle();
  if(_formStale(_tmplListT)){ renderTemplateList(); rerenderAdmin(); return; }
  const t = tenants.find(t=>t.id===editingId); if(!t||!t.templates||!t.templates[i]) return;
  const tm = t.templates[i];
  if(!confirm(stop ? 'Stop "' + tm.label + '"?\n\nIt is no longer posted or counted as owed. Bills already posted are kept. You can resume it later.'
                   : 'Resume "' + tm.label + '"?\n\nIt is billed again from the current cycle; the months it was stopped are not billed.')) return;
  const templatesCopy = structuredClone(t.templates);
  const x = templatesCopy[i];
  if(stop) x.retired = true;
  else {
    // Billing resumes from the current cycle (next, if its due date has
    // passed). The months it was stopped are waived — never posted, never
    // owed — while its earlier history still counts.
    delete x.retired;
    const start = _sinceFor(t, x);
    let m = isYM(x.postedThrough) ? addYM(x.postedThrough, 1) : start;
    const skip = new Set(Array.isArray(x.skip) ? x.skip : []);
    for(let n = 0; m < start && n < 60; n++, m = addYM(m, 1)) if(!templateBillExists(t, x, m)) skip.add(m);
    x.skip = Array.from(skip).sort();
    if(!isYM(x.postedThrough) || x.postedThrough < addYM(start, -1)) x.postedThrough = addYM(start, -1);
  }
  try {
    await dbUpdateTenantGuarded(t, {templates: templatesCopy});
    t.templates = templatesCopy;
    showToast(stop ? 'Charge stopped.' : 'Charge resumed.');
    if(!stop) await runAutoBilling({ only: t.id });
    renderTemplateList(); rerenderAdmin();
  } catch(e){ if(e.conflict){ showToast(e.message,false); renderTemplateList(); rerenderAdmin(); } else templateSaveErr(e); }
}

async function deleteTemplate(i) {
  const _t0 = tenants.find(t=>t.id===editingId);
  const _d = _t0 && _t0.templates && _t0.templates[i];
  const _sk = _d && Array.isArray(_d.skip) ? _d.skip : [];
  const _al = _d && Array.isArray(_d.aliases) ? _d.aliases : [];
  const _lost = (_sk.length || _al.length)
    ? '\n\nNot kept: ' + [_sk.length ? 'its waived month' + (_sk.length!==1?'s':'') + ' (' + _sk.map(p => fmtYM(p)).join(', ') + ')' : '', _al.length ? 'its earlier name' + (_al.length!==1?'s':'') + ' (' + _al.join(', ') + ')' : ''].filter(Boolean).join(' and ')
      + ' — a re-added charge would list waived months as unbilled again. To stop billing but keep them, use Stop (❚❚) instead.'
    : '';
  if(!confirm('Delete this recurring charge?\n\nBills already posted are kept. No new bills will post for it. If you add a charge with the same name later, those bills count as its history.' + _lost)) return;
  await _autoBillIdle();
  if(_formStale(_tmplListT)){ renderTemplateList(); rerenderAdmin(); return; }
  const t = tenants.find(t=>t.id===editingId); if(!t||!t.templates) return;
  const templatesCopy = structuredClone(t.templates);
  templatesCopy.splice(i,1);
  try {
    await dbUpdateTenantGuarded(t, {templates: templatesCopy});
    t.templates = templatesCopy;
    showToast('Template deleted.');
    renderTemplateList();
    rerenderAdmin();
  } catch(e){ if(e.conflict){ showToast(e.message,false); renderTemplateList(); rerenderAdmin(); } else templateSaveErr(e); }
}

function startNewTemplate() {
  document.getElementById('btn-start-new-tmpl').style.display='none';
  const c = document.getElementById('new-tmpl-inline'); c.style.display='block';
  c.innerHTML = `<div class="tmpl-edit-form">
    <div class="form-grid">
      <div class="field"><label>Description</label><input type="text" id="nt-label" placeholder="e.g. Monthly Rent"></div>
      <div class="field"><label>Amount (&#8369;)</label><input type="text" id="nt-amount" placeholder="0" inputmode="decimal" pattern="[0-9.]*" autocomplete="off"></div>
      <div class="field"><label>Due Day of Month <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(use 28-31 for end-of-month; auto-caps to last day of shorter months)</span></label><input type="number" id="nt-day" placeholder="e.g. 1" min="1" max="31"></div>
      <div class="field full" style="display:flex;align-items:center;gap:10px;padding-top:4px;">
        <input type="checkbox" id="nt-pending" onchange="(function(){var a=document.getElementById('nt-amount');a.disabled=this.checked;a.style.opacity=this.checked?'0.4':'1';}).call(this)" style="width:15px;height:15px;accent-color:var(--blue);cursor:pointer;">
        <label for="nt-pending" style="font-size:11px;font-weight:600;letter-spacing:0.05em;color:var(--navy);cursor:pointer;text-transform:uppercase;">Pending amount <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)">(bill created with no amount; you update it when the bill arrives)</span></label>
      </div>
      <div class="field full check-field">
        <input type="checkbox" id="nt-auto" checked>
        <label for="nt-auto">Post automatically each cycle <span class="opt">(ahead of the due date, rent in advance)</span></label>
      </div>
      ${_catField('nt-cat', '', '', true)}
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn-cancel" style="flex:1;padding:9px;" onclick="cancelNewTemplate()">Cancel</button>
      <button class="btn-save" style="flex:2;padding:9px;" onclick="saveNewTemplate()">Add Template</button>
    </div>
  </div>`;
}

// Category picker for a charge or bill. '' = decide from the name (shown).
const _CAT_OPTS = [['rent','Rent (revenue)'],['utilities','Utility billed back (not revenue)'],['other','Other charge (revenue)']];
function _catField(id, cur, label, full) {
  const guess = billCategory({ label: label || '' });
  const name = (_CAT_OPTS.find(o => o[0] === guess) || [,''])[1];
  return '<div class="field'+(full?' full':'')+'"><label for="'+id+'">Category</label><select id="'+id+'">'
    + '<option value=""'+(!cur?' selected':'')+'>From the name'+(label?' ('+esc(name)+')':'')+'</option>'
    + _CAT_OPTS.map(o => '<option value="'+o[0]+'"'+(cur===o[0]?' selected':'')+'>'+o[1]+'</option>').join('')
    + '</select></div>';
}
// "For month" on a hand-typed bill: blank = the due date's month.
function _monthField(id, cur) {
  return '<div class="field"><label for="'+id+'">For month <span class="opt">(blank = due date\'s month)</span></label><input type="month" id="'+id+'" value="'+(isYM(cur)?cur:'')+'"></div>';
}
function _monthVal(id) { const el = document.getElementById(id); return el && isYM(el.value) ? el.value : ''; }
function _catVal(id) { const el = document.getElementById(id); const v = el ? el.value : ''; return _CAT_OPTS.some(o => o[0] === v) ? v : ''; }

function cancelNewTemplate() {
  document.getElementById('new-tmpl-inline').style.display='none';
  document.getElementById('btn-start-new-tmpl').style.display='block';
}

async function saveNewTemplate() {
  const label = document.getElementById('nt-label').value.trim();
  if(!label){showToast('Please enter a template description.',false);return;}
  const _ntPending = document.getElementById('nt-pending') && document.getElementById('nt-pending').checked;
  const amtRaw = document.getElementById('nt-amount').value;
  const amtNum = Number(String(amtRaw).replace(/,/g,'').trim());
  if(!_ntPending && (isNaN(amtNum) || amtNum < 0)){ showToast('Amount must be a non-negative number.', false); return; }
  const amt = _ntPending ? 0 : normalizeAmount(amtRaw);
  if(!_ntPending&&amt===0){ showToast('Note: amount is set to ₱0.',true); }
  const day = Number(document.getElementById('nt-day').value);
  if(!day||day<1||day>31){showToast('Due day must be between 1 and 31.',false);return;}
  await _autoBillIdle();
  const t = tenants.find(t=>t.id===editingId); if(!t) return;
  // Copy → save → commit: a failed save must not leave a phantom template
  // in memory that a later save would silently persist.
  const templatesCopy = structuredClone(t.templates || []);
  const _ntAuto = document.getElementById('nt-auto');
  // Another charge's old name equal to this new name now belongs here.
  templatesCopy.forEach(x => { if(x && Array.isArray(x.aliases)) x.aliases = x.aliases.filter(a => normLabel(a) !== normLabel(label)); });
  const _nt = {id:uid(), label, amount:amt, dayOfMonth:day, pendingAmount:_ntPending, auto: _ntAuto ? _ntAuto.checked : true};
  const _ntCat = _catVal('nt-cat'); if(_ntCat) _nt.category = _ntCat;
  // A new charge isn't owed for months before it existed — except the
  // tenant's first rent charge, which is reckoned from move-in.
  const _firstRent = isRentLabel(label) && !templatesCopy.some(x => x && isRentLabel(x.label));
  if(!_firstRent) _nt.since = _sinceFor(t, _nt);
  const _startsNext = _nt.since && _nt.since > _currentYM();
  // A second rent charge (a new rate set up as a new charge): offer to stop
  // the old one so the tenant isn't charged rent twice.
  const _oldRent = isRentLabel(_nt.label) ? templatesCopy.filter(x => x && !x.retired && isRentLabel(x.label)) : [];
  if(_oldRent.length && confirm(t.name + ' already has ' + _oldRent.map(x => '"' + x.label + '"').join(', ') + '.\n\nOK: stop ' + (_oldRent.length === 1 ? 'it' : 'them') + ' so only "' + label + '" is charged from now on (bills already posted stay as history).\nCancel: keep charging both.'))
    _oldRent.forEach(x => { x.retired = true; });
  templatesCopy.push(_nt);
  try {
    await dbUpdateTenantGuarded(t, {templates: templatesCopy});
    t.templates = templatesCopy;
    showToast(_startsNext ? 'Charge added. This month\'s due day has passed, so it starts in '+fmtYM(_nt.since)+'.' : 'Charge added.');
    cancelNewTemplate();
    await runAutoBilling({ only: t.id });
    renderTemplateList();
    rerenderAdmin();
  } catch(e){ if(e.conflict){ showToast(e.message,false); renderTemplateList(); rerenderAdmin(); } else templateSaveErr(e); }
}

// ─────────────────────────────────────────────
// GENERATE BILLS MODAL
// Built to scale: with a handful of tenants it looks like a simple list,
// with dozens it becomes floor sections with check-all toggles under a
// summary bar. Selection state lives in _genState (not DOM checkboxes) so
// collapsing a section can't lose choices, and already-generated bills
// compress to one note per tenant instead of a wall of disabled rows.
// ─────────────────────────────────────────────
let _genState = null;    // {yr, mo, useGroups, groups:[{key, entries:[{t, rows}]}]}
let _genOpenGroups = {}; // group key -> bool; unset keys use the render default

function openGenModal() {
  const now = new Date();
  const ym = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0');
  document.getElementById('gen-month-input').value = ym;
  _genOpenGroups = {};
  openModal('genbills-modal');
  refreshGenPreview();
}
function closeGenModal() { closeModalEl('genbills-modal'); }

function refreshGenPreview() {
  const val = document.getElementById('gen-month-input').value; // "YYYY-MM"
  if(!val) return;
  const [yr, mo] = val.split('-').map(Number);
  const monthName = new Date(yr,mo-1,1).toLocaleString('default',{month:'long',year:'numeric'});
  document.getElementById('genbills-title').textContent = 'Generate Bills — '+monthName;

  const entries = [];
  tenants.forEach(t => {
    const tmpls = activeTemplates(t).filter(x=>normLabel(x.label));
    if(!tmpls.length) return;
    const rows = tmpls.map(tmpl => {
      // Same due-date and duplicate rules as automatic billing: day capped to
      // short months, never before move-in, one bill per template per cycle.
      const dueDate = templateDueDate(t, tmpl, val);
      const waived = Array.isArray(tmpl.skip) && tmpl.skip.includes(val) && !templateBillExists(t, tmpl, val);
      const alreadyExists = waived || templateBillExists(t, tmpl, val);
      return {tmpl, dueDate, alreadyExists, waived, selected: !alreadyExists, amount: tmplRateAt(tmpl, val)};
    });
    entries.push({t, rows});
  });

  if(!entries.length) {
    _genState = null;
    document.getElementById('gen-preview-body').innerHTML = '<div class="gen-empty">No templates found. Open a tenant\'s edit modal and add templates first.</div>';
    _genUpdateButton();
    return;
  }

  const groupMap = {}; const groupOrder = []; const genCanon = appFloorCanon();
  entries.forEach(e => {
    const k = genCanon(e.t.floor);
    if(!(k in groupMap)){ groupMap[k]=[]; groupOrder.push(k); }
    groupMap[k].push(e);
  });
  groupOrder.sort((a,b)=>{ if(!a) return 1; if(!b) return -1; return floorRank(a)-floorRank(b) || a.localeCompare(b); });
  _genState = {
    yr, mo,
    useGroups: groupOrder.length > 1,
    groups: groupOrder.map(k=>({key:k, entries:groupMap[k]}))
  };
  renderGenPreview();
}

function _genAllRows() {
  if(!_genState) return [];
  const out = [];
  _genState.groups.forEach(g=>g.entries.forEach(e=>e.rows.forEach(r=>out.push(r))));
  return out;
}
// Totals over a set of rows: selected count, peso total, pending-amount
// count (no peso value yet), and how many were skipped as already existing.
function _genTotals(rows) {
  let count=0, amount=0, pendingCount=0, skipped=0;
  rows.forEach(r=>{
    if(r.alreadyExists){ skipped++; return; }
    if(!r.selected) return;
    count++;
    if(r.tmpl.pendingAmount) pendingCount++;
    else amount += Number(r.amount)||0;
  });
  return {count, amount, pendingCount, skipped};
}
function _genUpdateButton() {
  const btn = document.getElementById('gen-confirm-btn');
  if(!btn) return;
  const tot = _genTotals(_genAllRows());
  btn.disabled = !tot.count;
  btn.textContent = tot.count ? 'Generate '+tot.count+' Bill'+(tot.count!==1?'s':'') : 'Nothing to Generate';
}

function renderGenPreview() {
  if(!_genState) return;
  const all = _genAllRows();
  const tot = _genTotals(all);
  const selectable = all.filter(r=>!r.alreadyExists).length;
  // Small runs stay fully expanded; big runs start collapsed to their
  // per-floor rollups so the admin reviews totals, not sixty rows.
  const defaultOpen = !_genState.useGroups || selectable <= 10;

  const summary = `<div class="gen-summary">
    <div class="gen-summary-main"><strong>${tot.count} bill${tot.count!==1?'s':''}</strong> selected
      &nbsp;·&nbsp; &#8369;${tot.amount.toLocaleString()}${tot.pendingCount?' + '+tot.pendingCount+' pending-amount':''}
      ${tot.skipped?`&nbsp;·&nbsp; <span class="gen-summary-skip">${tot.skipped} already generated</span>`:''}
    </div>
    ${selectable?`<div class="gen-summary-actions">
      <button class="gen-mini-btn" onclick="genSetAll(true)">Select all</button>
      <button class="gen-mini-btn" onclick="genSetAll(false)">Clear</button>
    </div>`:''}
  </div>`;

  const rowHtml = (r, gi, ei, ri) => r.alreadyExists ? '' : `
    <div class="gen-bill-row">
      <input type="checkbox" ${r.selected?'checked':''} onchange="genToggleRow(${gi},${ei},${ri},this.checked)" aria-label="Include ${esc(r.tmpl.label)}">
      <div class="gen-bill-info">
        <div class="gen-bill-label">${esc(r.tmpl.label)}</div>
        <div class="gen-bill-due">Due ${formatDate(r.dueDate)}</div>
      </div>
      <div class="gen-bill-amount">${r.tmpl.pendingAmount ? '<span style="color:var(--orange);font-size:12px;font-weight:600;">Pending amount</span>' : '&#8369;'+Number(r.amount).toLocaleString()}</div>
    </div>`;

  const tenantHtml = (e, gi, ei) => {
    const skippedRows = e.rows.filter(r=>r.alreadyExists && !r.waived);
    const waivedRows = e.rows.filter(r=>r.waived);
    return `<div class="gen-tenant-group">
      <div class="gen-tenant-name">${esc(e.t.name)} &nbsp;·&nbsp; Unit ${esc(e.t.unit)}</div>
      ${e.rows.map((r,ri)=>rowHtml(r,gi,ei,ri)).join('')}
      ${skippedRows.length?`<div class="gen-bill-skip-note">&#9888; Already generated this month: ${skippedRows.map(r=>esc(r.tmpl.label)).join(', ')}</div>`:''}
      ${waivedRows.length?`<div class="gen-bill-skip-note">Waived this month: ${waivedRows.map(r=>esc(r.tmpl.label)).join(', ')}</div>`:''}
    </div>`;
  };

  let body;
  if(!_genState.useGroups) {
    body = _genState.groups.map((g,gi)=>g.entries.map((e,ei)=>tenantHtml(e,gi,ei)).join('')).join('');
  } else {
    body = _genState.groups.map((g,gi)=>{
      const rows = [];
      g.entries.forEach(e=>e.rows.forEach(r=>rows.push(r)));
      const gt = _genTotals(rows);
      const gSelectable = rows.filter(r=>!r.alreadyExists);
      const open = (g.key in _genOpenGroups) ? _genOpenGroups[g.key] : defaultOpen;
      const allSel = gSelectable.length>0 && gSelectable.every(r=>r.selected);
      const label = g.key ? esc(g.key) : 'No floor set';
      const meta = gSelectable.length
        ? `${gt.count}/${gSelectable.length} bill${gSelectable.length!==1?'s':''} &nbsp;·&nbsp; &#8369;${gt.amount.toLocaleString()}${gt.pendingCount?' +'+gt.pendingCount+' pending':''}`
        : 'all generated &#10003;';
      return `<div class="gen-group">
        <div class="gen-group-head">
          ${gSelectable.length?`<input type="checkbox" ${allSel?'checked':''} onchange="genToggleGroup(${gi},this.checked)" aria-label="Select all bills in ${label}">`:'<span class="gen-group-spacer"></span>'}
          <button class="gen-group-title" onclick="genToggleOpen(${gi})" aria-expanded="${open?'true':'false'}">
            <span class="insights-arrow${open?' open':''}">›</span> ${label}
            <span class="gen-group-meta">${meta}</span>
          </button>
        </div>
        ${open?`<div class="gen-group-body">${g.entries.map((e,ei)=>tenantHtml(e,gi,ei)).join('')}</div>`:''}
      </div>`;
    }).join('');
  }

  document.getElementById('gen-preview-body').innerHTML = summary + body;
  _genUpdateButton();
}

function genToggleRow(gi, ei, ri, checked) {
  const g = _genState && _genState.groups[gi];
  const r = g && g.entries[ei] && g.entries[ei].rows[ri];
  if(!r || r.alreadyExists) return;
  r.selected = !!checked;
  renderGenPreview();
}
function genToggleGroup(gi, checked) {
  const g = _genState && _genState.groups[gi];
  if(!g) return;
  g.entries.forEach(e=>e.rows.forEach(r=>{ if(!r.alreadyExists) r.selected = !!checked; }));
  renderGenPreview();
}
function genToggleOpen(gi) {
  const g = _genState && _genState.groups[gi];
  if(!g) return;
  const selectable = _genAllRows().filter(r=>!r.alreadyExists).length;
  const defaultOpen = !_genState.useGroups || selectable <= 10;
  const cur = (g.key in _genOpenGroups) ? _genOpenGroups[g.key] : defaultOpen;
  _genOpenGroups[g.key] = !cur;
  renderGenPreview();
}
function genSetAll(sel) {
  if(!_genState) return;
  _genState.groups.forEach(g=>g.entries.forEach(e=>e.rows.forEach(r=>{ if(!r.alreadyExists) r.selected = !!sel; })));
  renderGenPreview();
}

async function confirmGenerateBills() {
  if(!_genState){ showToast('No bills selected to generate.', false); return; }

  // Build candidate bill arrays WITHOUT mutating live tenant objects yet.
  const ym = _genState.yr+'-'+String(_genState.mo).padStart(2,'0');
  const pending = []; // [{tenant, newBills, newTemplates}]
  await _autoBillIdle();
  _genState.groups.forEach(g => g.entries.forEach(e => {
    // Work from the live row: a background run may have posted since the
    // preview was built.
    const live = tenants.find(x => x.id === e.t.id);
    if(!live) return;
    const additions = [];
    const templates = structuredClone(live.templates||[]);
    e.rows.forEach(r => {
      if(r.alreadyExists || !r.selected) return;
      const liveTmpl = templates.find(x => x.id && x.id===r.tmpl.id) || templates.find(x => x.label===r.tmpl.label);
      if(!liveTmpl || templateBillExists({ bills: live.bills.concat(additions), templates, billing_model: live.billing_model }, liveTmpl, ym)) return;
      const tmpl = templates.find(x => x.id && x.id===r.tmpl.id) || templates.find(x => x.label===r.tmpl.label);
      if(tmpl && !tmpl.id) tmpl.id = uid();
      const src = tmpl || r.tmpl;
      additions.push(makeTemplateBill(src, ym, r.dueDate));
    });
    if(!additions.length) return;
    const newBills = [...live.bills, ...additions];
    // Automatic billing never re-posts a cycle generated by hand — but
    // postedThrough only advances across months that are really billed, so
    // generating a future month can't make it skip the months before.
    const holder = { bills: newBills, templates, billing_model: live.billing_model };
    templates.forEach(x => bumpPostedThrough(holder, x));
    pending.push({tenant: live, newBills, newTemplates: templates});
  }));

  if(!pending.length){ showToast('Nothing new to generate — those bills are already posted.', false); refreshGenPreview(); return; }

  setLoading(true,'Generating bills…');
  try {
    // Guarded per-tenant: generation must not overwrite payments recorded
    // from another device, nor write without bumping rev (which would let a
    // stale tab clobber the generated bills later without any conflict).
    // allSettled: tenants whose save succeeded keep their new bills in
    // memory even if another tenant's save fails.
    const results = await Promise.allSettled(pending.map(p => dbUpdateTenantGuarded(p.tenant, {bills: p.newBills, templates: p.newTemplates})
      .then(() => { p.tenant.bills = p.newBills; p.tenant.templates = p.newTemplates; })));
    const failedR = results.filter(r => r.status==='rejected');
    if(failedR.length) throw failedR[0].reason;
    setLoading(false);
    closeGenModal();
    showToast('Bills generated ✓');
    rerenderAdmin();
  } catch(e){
    setLoading(false);
    if(e.conflict){ showToast(e.message, false); closeGenModal(); rerenderAdmin(); }
    // Some tenants may have saved: rebuild the preview so they show as done.
    else { showToast('Error: '+e.message, false); refreshGenPreview(); rerenderAdmin(); }
  }
}


// ─────────────────────────────────────────────
// FILTER CONTROLS
// ─────────────────────────────────────────────
// Month options for the Billing module's month filter.
function getAvailableMonths(showAll) {
  const months = new Set();
  tenants.forEach(t => t.bills.forEach(b => {
    const p = billPeriod(b);
    if (p) months.add(p);
  }));
  const sorted = Array.from(months).sort().reverse();
  const limit = showAll ? sorted.length : 12;
  let visible = sorted.slice(0, limit);
  // Always include the currently selected month even if it's older
  if (filterMonth && !visible.includes(filterMonth) && sorted.includes(filterMonth)) {
    visible.push(filterMonth);
    visible.sort().reverse();
  }
  return { months: visible.map(v => ({ value: v, label: new Date(v + '-02').toLocaleString('default', { month: 'long', year: 'numeric' }) })), hasMore: sorted.length > limit };
}
let _showAllMonths = false;
function renderMonthOptions(showAll) {
  const data = getAvailableMonths(showAll || _showAllMonths);
  let html = '<option value="">All Months</option>';
  html += data.months.map(m => '<option value="'+m.value+'" '+(filterMonth===m.value?'selected':'')+'>'+m.label+'</option>').join('');
  if (data.hasMore) html += '<option value="__more__">Show older months\u2026</option>';
  return html;
}
function _currentYM() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0');
}

// ─────────────────────────────────────────────
// PAYMENT INSTRUCTIONS
// ─────────────────────────────────────────────
// Editing settings whose load failed would overwrite the real saved values
// with the blanks on screen — refuse until a reload succeeds.
function _guardSettingsEdit() {
  if(_settingsLoadFailed) {
    showToast('Settings failed to load, so editing now could overwrite your saved values with blanks. Please refresh the page first.', false);
    return false;
  }
  return true;
}
// Portal texts are edited in place on Settings (one at a time).
function _openSetEdit(key) {
  if(!_guardSettingsEdit()) return;
  _setEdit = key; _setEditFocus = true; rerenderAdmin();
}
// Close one inline editor (Cancel, or after its save) and return focus to its Edit button.
function _closeSetEdit(key) {
  delete _setDraft[key];
  if(_setEdit === key) { _setEdit = ''; _setReturn = key; }
  rerenderAdmin();
}
// Shared save flow: one save at a time, closes only its own editor, and a
// failure keeps the draft and says so even if the admin has moved on.
async function _saveSetEdit(key, draft, write, okMsg, what) {
  if(_setSaving) return;
  _setSaving = key;
  const b = document.querySelector('.st-editor .btn-pri');
  if(b) { b.disabled = true; b.textContent = 'Saving…'; }
  try {
    await write();
    _setSaving = '';
    _closeSetEdit(key);
    showToast(okMsg);
  } catch(e) {
    _setSaving = '';
    _setDraft[key] = draft;
    showToast('Could not save ' + what + ': ' + (e && e.message || 'network error'), false);
    if(_setEdit === key) {
      rerenderAdmin();
      requestAnimationFrame(() => {
        const errEl = document.getElementById(key + '-error');
        if(errEl) { errEl.textContent = 'Save failed. Make sure the settings table exists in Supabase.'; errEl.hidden = false; }
      });
    }
  }
}
function openPayInstModal() { _openSetEdit('payinst'); }
function closePayInstModal() { _closeSetEdit('payinst'); }
async function savePayInst() {
  const val = document.getElementById('payinst-textarea').value.trim();
  await _saveSetEdit('payinst', val, async () => { await dbSetSetting('payment_instructions', val); paymentInstructions = val; },
    'Payment instructions saved.', 'payment instructions');
}

// ─────────────────────────────────────────────
// ANNOUNCEMENTS (tenant notice board)
// ─────────────────────────────────────────────
function openAnnounceModal() { _openSetEdit('announce'); }
function closeAnnounceModal() { _closeSetEdit('announce'); }
async function saveAnnouncements() {
  const val = document.getElementById('announce-textarea').value.trim();
  await _saveSetEdit('announce', val, async () => { await dbSetSetting('announcements', val); announcements = val; },
    val ? 'Announcements saved — tenants will see them on their portal.' : 'Announcements cleared.', 'announcements');
}

// ─────────────────────────────────────────────
// BRANDING (property name — makes the portal reusable for any building)
// ─────────────────────────────────────────────
function openBrandingModal() { _openSetEdit('branding'); }
function closeBrandingModal() { _closeSetEdit('branding'); }
async function saveBranding() {
  const name = document.getElementById('branding-name').value.trim();
  const sub  = document.getElementById('branding-sub').value.trim();
  const errEl = document.getElementById('branding-error');
  errEl.hidden = true;
  if(!name){ errEl.textContent = 'Property name cannot be empty.'; errEl.hidden = false; return; }
  await _saveSetEdit('branding', { name, sub }, async () => {
    await dbSetSetting('property_name', name);
    await dbSetSetting('property_subtitle', sub);
    propertyName = name;
    propertySubtitle = sub || 'Tenant Billing Portal';
    try { localStorage.setItem('oa_branding', JSON.stringify({ name: propertyName, sub: propertySubtitle })); } catch {}
    applyBranding();
  }, 'Property name saved.', 'the property name');
}



// ─────────────────────────────────────────────
// PORTAL MONTH FILTER
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// F-15: CSV EXPORT + PRINT VIEW
// ─────────────────────────────────────────────
// Quote a CSV cell. Values that a spreadsheet would execute as a formula
// (=..., +..., @..., tab/CR-prefixed) get a leading apostrophe so a bill
// label like "=HYPERLINK(...)" can never run when the export is opened in
// Excel/Sheets. Plain numbers are exempt so amounts stay numeric.
function csvCell(v){
  let s = String(v==null?'':v).replace(/"/g,'""');
  if(/^[=+@\t\r-]/.test(s) && String(v).trim()!=='' && isNaN(Number(String(v)))) s = "'"+s;
  return '"'+s+'"';
}
function exportCSV() {
  const dsLabel = { paid:'Paid', overdue:'Overdue', 'due-today':'Due Today', 'due-soon':'Due Soon', grace:'In grace period', upcoming:'Upcoming', 'no-date':'Unscheduled', awaiting:'Amount to follow' };
  const rows = [['Tenant Name','Unit','Floor','Tenant Status','Billing Model','Access Code','Bill Label','Cycle','Amount','Amount Paid','Remaining','Due Date','Status','Paid Date','Remark']];
  // Every bill — former (archived) tenants included, since reports count them.
  allTenants().forEach(t => {
    const base = [t.name, t.unit, t.floor||'', t.archived_at ? 'Archived' : 'Active', t.billing_model==='inclusive'?'All-inclusive':'Itemized', t.code];
    if(!t.bills||!t.bills.length){
      rows.push([...base,'','','','','','','','','']);
    } else {
      t.bills.forEach(b => {
        // A bill marked paid is settled in full even when partial payments
        // weren't logged — mirror the statement's paidOf/balOf rules so the
        // export never claims money is still owed on a paid bill.
        const paid = billSettled(b);
        const remaining = billOpen(b);
        const status = dsLabel[getDueStatus(b)] || b.status;
        rows.push([
          ...base,
          b.label, billPeriod(b), r2(b.amount), r2(paid), r2(remaining), b.due||'', status, b.paidDate||'', b.remark||''
        ]);
      });
    }
  });
  const slug = String(propertyName||'bills').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || 'bills';
  _downloadCSV(rows, slug+'-bills-'+todayISO()+'.csv');
  showToast('CSV exported ✓');
}
function _downloadCSV(rows, filename) {
  const csv = rows.map(r=>r.map(csvCell).join(',')).join('\n');
  // UTF-8 BOM so Excel renders ₱ and non-ASCII names correctly.
  const blob = new Blob(['\ufeff'+csv], {type:'text/csv;charset=utf-8'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke after the click has been handled (Safari aborts on sync revoke).
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

// ─────────────────────────────────────────────
// "/" focuses the dashboard search box (unless already typing somewhere)
// ─────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if(e.key !== '/') return;
  const el = document.getElementById('tenant-search') || document.getElementById('bill-search');
  if(!el) return;
  const a = document.activeElement;
  if(a && (a.tagName==='INPUT' || a.tagName==='TEXTAREA' || a.tagName==='SELECT' || a.isContentEditable)) return;
  e.preventDefault();
  el.focus();
  el.select();
});

// ─────────────────────────────────────────────
// F16: Escape key closes modals
// ─────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if(e.key !== 'Escape') return;
  const _el = id => { const el=document.getElementById(id); return el&&el.classList.contains('open')?el:null; };
  if(_el('paiddate-modal')) { closePaidModal();    return; }
  if(_el('moveout-modal'))  { closeMoveOut();      return; }
  if(_el('pay-modal'))      { closePayModal();     return; }
  if(_el('genbills-modal')) { closeGenModal();     return; }
  if(_el('stmt-modal'))     { closeStmtModal();    return; }
  if(_el('incstmt-modal'))  { closeIncStmtModal(); return; }
  if(_el('addbill-modal'))  { closeQuickBill();    return; }
  if(_el('tenant-modal'))   { closeModal();        return; }
});

// ─────────────────────────────────────────────
// Focus trap: keep Tab inside the open dialog. The modals declare
// aria-modal, but without this the background stayed keyboard-reachable —
// Tab could land on (and activate) destructive controls behind the overlay.
// ─────────────────────────────────────────────
const _MODAL_IDS = ['paiddate-modal','moveout-modal','pay-modal','genbills-modal','stmt-modal','incstmt-modal','addbill-modal','tenant-modal'];
document.addEventListener('keydown', function(e) {
  if(e.key !== 'Tab') return;
  let openEl = null;
  for(const id of _MODAL_IDS){
    const el = document.getElementById(id);
    if(el && el.classList.contains('open')){ openEl = el; break; }
  }
  if(!openEl) return;
  const focusables = Array.from(openEl.querySelectorAll(
    'button, [href], input:not([type=hidden]), select, textarea, [tabindex]:not([tabindex="-1"])'
  )).filter(el => !el.disabled && el.offsetParent !== null);
  if(!focusables.length) return;
  const first = focusables[0], last = focusables[focusables.length-1];
  const active = document.activeElement;
  if(e.shiftKey) {
    if(active === first || !openEl.contains(active)) { e.preventDefault(); last.focus(); }
  } else {
    if(active === last || !openEl.contains(active)) { e.preventDefault(); first.focus(); }
  }
});



// ─────────────────────────────────────────────
// HEADER TOOLS (2026 redesign): global search, due/overdue bell, phone FAB
// ─────────────────────────────────────────────
function _greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}
function _initials(n) {
  const w = String(n || '?').trim().split(/\s+/);
  return ((w[0] || '?').charAt(0) + (w.length > 1 ? w[w.length - 1].charAt(0) : '')).toUpperCase();
}
// Bills due today, plus bills that became overdue (past the grace period) within the last week.
function _bellItems() {
  const today = new Date(todayISO() + 'T00:00:00');
  const out = [];
  tenants.forEach(t => (t.bills || []).forEach(b => {
    if(billOpen(b) <= 0.005) return;
    const s = getDueStatus(b);
    if(s === 'due-today') out.push({ t, b, kind: 'due', title: 'Due today', when: 'Today' });
    else if(s === 'overdue' && b.due) {
      const late = Math.round((today - new Date(b.due + 'T00:00:00')) / 86400000);
      if(late - graceDays <= 7) out.push({ t, b, kind: 'late', title: 'Now overdue', when: late + (late === 1 ? ' day late' : ' days late') });
    }
  }));
  return out;
}
let _closeBell = () => {};
function renderHeaderTools() {
  try {
    const right = document.querySelector('header .nav-right');
    if(!right) return;
    let tools = document.getElementById('hdr-tools');
    if(!tools) {
      tools = document.createElement('div');
      tools.id = 'hdr-tools';
      tools.className = 'hdr-tools';
      tools.innerHTML = '<div class="hdr-search">' + icon('search')
        + '<input type="search" id="hdr-q" placeholder="Search tenants, units or bills" autocomplete="off" aria-label="Search tenants, units or bills">'
        + '<div class="hdr-pop" id="hdr-results" hidden></div></div>'
        + '<div class="hdr-bell"><button type="button" class="hdr-bell-btn" id="hdr-bell-btn" aria-haspopup="true" aria-expanded="false" aria-label="Notifications"></button>'
        + '<div class="hdr-pop" id="hdr-bell-pop" hidden></div></div>';
      right.insertBefore(tools, right.firstChild);
      const q = document.getElementById('hdr-q'), results = document.getElementById('hdr-results');
      const resBtns = () => Array.from(results.querySelectorAll('.hdr-res'));
      const outside = el => !el || !el.closest('.hdr-search');
      q.addEventListener('input', () => hdrSearch(q.value));
      q.addEventListener('focus', () => { if(q.value.trim()) hdrSearch(q.value); });
      q.addEventListener('keydown', e => {
        if(e.key === 'Escape') { q.value = ''; hdrSearch(''); q.blur(); }
        else if(e.key === 'Enter') { const f = resBtns()[0]; if(f) { e.preventDefault(); f.click(); } }
        else if(e.key === 'ArrowDown') { const f = resBtns()[0]; if(f) { e.preventDefault(); f.focus(); } }
      });
      // Results stay open while focus moves into them (keyboard users).
      q.addEventListener('blur', () => setTimeout(() => { if(outside(document.activeElement)) hdrSearch(''); }, 150));
      results.addEventListener('focusout', e => { if(outside(e.relatedTarget)) setTimeout(() => { if(outside(document.activeElement)) hdrSearch(''); }, 0); });
      results.addEventListener('keydown', e => {
        const list = resBtns(), i = list.indexOf(document.activeElement);
        if(e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const n = i + (e.key === 'ArrowDown' ? 1 : -1);
          if(n < 0) q.focus(); else if(list[n]) list[n].focus();
        } else if(e.key === 'Escape') { q.value = ''; hdrSearch(''); q.focus(); }
      });
      const bellPop = () => document.getElementById('hdr-bell-pop'), bellBtn = () => document.getElementById('hdr-bell-btn');
      // Close the notifications popover; focus goes back to the bell when
      // it was inside the popover (or when asked).
      _closeBell = refocus => {
        const p = bellPop(), b = bellBtn();
        if(!p || p.hidden) return;
        const had = p.contains(document.activeElement);
        p.hidden = true; b.setAttribute('aria-expanded', 'false');
        if(refocus || (had && refocus !== false)) { try { b.focus(); } catch {} }
      };
      bellBtn().addEventListener('click', e => {
        e.stopPropagation();
        const p = bellPop();
        p.hidden = !p.hidden;
        e.currentTarget.setAttribute('aria-expanded', String(!p.hidden));
      });
      document.addEventListener('click', e => { if(!e.target.closest('.hdr-bell')) _closeBell(false); });
      document.addEventListener('keydown', e => { if(e.key === 'Escape') _closeBell(); });
      tools.querySelector('.hdr-bell').addEventListener('focusout', e => { if(e.relatedTarget && !e.currentTarget.contains(e.relatedTarget)) _closeBell(false); });
      // Picking a notification or "View open bills" navigates: close first.
      bellPop().addEventListener('click', e => { if(e.target.closest('button')) _closeBell(false); });
    }
    if(!document.getElementById('fab-pay')) {
      const f = document.createElement('button');
      f.type = 'button'; f.id = 'fab-pay'; f.className = 'fab-pay';
      f.innerHTML = icon('cash') + '<span>Receive payment</span>';
      f.addEventListener('click', () => openPayModal());
      document.getElementById('app').appendChild(f);
    }
    const items = _bellItems();
    const btn = document.getElementById('hdr-bell-btn');
    btn.innerHTML = icon('bell') + (items.length ? '<span class="hdr-bell-count">' + items.length + '</span>' : '');
    btn.setAttribute('aria-label', items.length ? items.length + (items.length === 1 ? ' notification' : ' notifications') : 'Notifications');
    document.getElementById('hdr-bell-pop').innerHTML = '<div class="hdr-pop-head"><strong>Notifications</strong><span>Due today and newly overdue</span></div>'
      + (items.length
        ? items.map(n => '<button type="button" class="hdr-note" data-tid="' + esc(n.t.id) + '" onclick="openTenant(this.dataset.tid)">'
            + '<span class="hdr-note-ic ' + n.kind + '">' + icon(n.kind === 'due' ? 'clock' : 'alert') + '</span>'
            + '<span class="hdr-note-main"><span class="hdr-note-top">' + n.title + '<span>' + n.when + '</span></span>'
            + '<span class="hdr-note-body">' + esc(n.t.name) + ' · Unit ' + esc(n.t.unit) + ' · ' + esc(n.b.label || 'Bill') + ' · ' + peso(billOpen(n.b)) + '</span></span></button>').join('')
        : '<div class="hdr-empty">Nothing due today and nothing newly overdue.</div>')
      + '<button type="button" class="hdr-pop-foot" onclick="goBills(\'open\')">View open bills</button>';
  } catch(e) { console.warn('header tools:', e); }
}
function hdrSearch(raw) {
  const box = document.getElementById('hdr-results');
  if(!box) return;
  const ql = String(raw || '').trim().toLowerCase();
  if(!ql) { box.hidden = true; box.innerHTML = ''; return; }
  const res = [], LIMIT = 6;
  for(const t of tenants) {
    if(res.length >= LIMIT) break;
    if([t.name, t.unit, t.code, t.phone, t.email, t.floor].some(v => String(v || '').toLowerCase().includes(ql))) {
      const open = tenantSummary(t).open;
      res.push('<button type="button" class="hdr-res" data-tid="' + esc(t.id) + '" onmousedown="event.preventDefault()" onclick="hdrGo(this.dataset.tid)">'
        + '<span class="hdr-res-ic">' + esc(_initials(t.name)) + '</span><span class="hdr-res-main"><span class="hdr-res-title">' + esc(t.name) + '</span>'
        + '<span class="hdr-res-sub">Unit ' + esc(t.unit) + (t.floor ? ' · ' + esc(t.floor) : '') + (open ? ' · owes ' + peso(open) : '') + '</span></span><span class="hdr-res-kind">Tenant</span></button>');
    }
  }
  outer: for(const t of tenants) for(const b of (t.bills || [])) {
    if(res.length >= LIMIT) break outer;
    if(billOpen(b) <= 0.005) continue;
    if([b.label, t.name].some(v => String(v || '').toLowerCase().includes(ql)))
      res.push('<button type="button" class="hdr-res" data-tid="' + esc(t.id) + '" onmousedown="event.preventDefault()" onclick="hdrGo(this.dataset.tid)">'
        + '<span class="hdr-res-ic bill">&#8369;</span><span class="hdr-res-main"><span class="hdr-res-title">' + esc(b.label || 'Bill') + '</span>'
        + '<span class="hdr-res-sub">' + esc(t.name) + ' · Unit ' + esc(t.unit) + ' · ' + peso(billOpen(b)) + (b.due ? ' · due ' + shortDate(b.due) : '') + '</span></span><span class="hdr-res-kind">Bill</span></button>');
  }
  box.innerHTML = res.length ? res.join('') : '<div class="hdr-empty">Nothing matches \u201c' + esc(String(raw).trim()) + '\u201d.</div>';
  box.hidden = false;
}
function hdrGo(tid) {
  const q = document.getElementById('hdr-q');
  if(q) { q.value = ''; q.blur(); }
  hdrSearch('');
  openTenant(tid);
}
