// The live view.
//
// Plain ES modules, no build step: "go build" ships the whole product, and a
// user who downloads one binary gets one binary that works.
//
// Two things here are worth understanding before changing anything.
//
// 1. The table is virtual. `all` holds every record; the DOM holds only the
//    rows on screen. A CUBE under load emits thousands of records a minute and
//    a real session runs to six figures, so a row per record in the DOM would
//    make the tool unusable exactly when it is needed.
//
// 2. Filtering is done here, not on the server. The whole session is already
//    in memory, and a scan over it per keystroke is a few milliseconds —
//    faster and steadier than a round trip, and it keeps working while the
//    socket is down.

'use strict';

const ROW_H = 22;      // must match --row-h in style.css
const OVERSCAN = 12;   // rows rendered beyond the viewport, to hide scrolling
const MAX_RECORDS = 200000; // the browser's own ring; the server has its own

const $ = (id) => document.getElementById(id);

const el = {
  conn: $('conn'), filter: $('filter'), severity: $('severity'), kind: $('kind'),
  source: $('source'), incomplete: $('incomplete'),
  pause: $('pause'), follow: $('follow'), clear: $('clear'), count: $('count'),
  viewport: $('viewport'), spacer: $('spacer'), rows: $('rows'), empty: $('empty'),
  detail: $('detail'), detailTitle: $('detail-title'), detailMeta: $('detail-meta'),
  detailRaw: $('detail-raw'), detailClose: $('detail-close'),
  statusStore: $('status-store'), statusSources: $('status-sources'),
};

const state = {
  all: [],            // every record received, oldest first
  view: [],           // the filtered slice the table shows
  held: [],           // records arriving while paused
  lastId: 0,          // highest record id seen, for resuming after a drop
  paused: false,
  follow: true,
  selected: null,
  sources: new Set(),
  filter: { text: '', severity: -1, kind: '', source: '', incomplete: false },
  firstRendered: -1,
  lastRendered: -1,
};

// ---------------------------------------------------------------- rendering

// A record's own description, matching what the CLI prints so that the two
// never disagree about what a record says.
function summary(r) {
  if (r.notice) return r.notice;
  if (r.sip) {
    const arrow = r.sip.direction === 'received' ? '<--' : '-->';
    return `${arrow} ${r.sip.startLine || ''}`;
  }
  if (r.cover) {
    const c = r.cover;
    return `Cover Buffer: ${c.callingNumber || '-'} -> ${c.calledNumber || '-'} (call ${c.callId || '-'})`;
  }
  if (r.log) {
    const tag = `%${r.log.facility}-${r.log.severity}-${r.log.mnemonic}`;
    return `${tag}: ${r.log.text || ''}`;
  }
  if (r.debug) {
    const path = (r.debug.component || []).join('/');
    return `${path}${r.debug.detail ? ' ' + r.debug.detail : ''}`.trim();
  }
  return r.text || (r.cont && r.cont[0]) || '';
}

// The row class that carries the type colour.
function kindClass(r) {
  if (r.notice) return 'notice';
  if (r.sip) return r.sip.direction === 'received' ? 'k-sip-received' : 'k-sip-sent';
  if (r.cover) return 'k-cover';
  if (r.kind === 'debug') return 'k-debug';
  if (r.kind === 'log') return 'k-log';
  return 'k-other';
}

function kindLabel(r) {
  if (r.notice) return 'notice';
  if (r.sip) return 'sip';
  if (r.cover) return 'cover';
  return r.kind || '';
}

// A record's clock reading, which comes from its head line. A continuation
// line has no timestamp of its own, so there is only ever one time per record.
function clock(r) {
  if (!r.time) return '';
  const t = new Date(r.time);
  if (isNaN(t)) return '';
  const p = (n, w = 2) => String(n).padStart(w, '0');
  // The device's own clock, printed as the device printed it. It is shown in
  // UTC because that is the zone the parser put it in; converting to the
  // laptop's zone would invent an accuracy the log does not have.
  return `${p(t.getUTCHours())}:${p(t.getUTCMinutes())}:${p(t.getUTCSeconds())}.${p(t.getUTCMilliseconds(), 3)}`;
}

function severityCell(r) {
  if (r.notice) return '';
  if (typeof r.severity !== 'number' || r.severity < 0) return '-';
  return r.severityName ? r.severityName.slice(0, 5) : String(r.severity);
}

// A failed call is worth seeing without reading: a 4xx/5xx/6xx response, or a
// log line the router itself flagged as an error.
function isFailure(r) {
  if (r.sip && r.sip.status >= 400) return true;
  if (r.log && r.log.severity <= 3) return true;
  return false;
}

function makeRow() {
  const row = document.createElement('div');
  row.className = 'row';
  for (const c of ['c-time', 'c-src', 'c-sev', 'c-kind', 'c-call', 'c-msg']) {
    const s = document.createElement('span');
    s.className = c;
    row.appendChild(s);
  }
  row.addEventListener('click', () => {
    const i = Number(row.dataset.index);
    if (!isNaN(i) && state.view[i]) select(state.view[i]);
  });
  return row;
}

// render draws the slice of `view` that the scroll position exposes, reusing
// the row elements already there. Reuse is what keeps scrolling from
// allocating: the DOM never grows past a screenful.
function render() {
  const total = state.view.length;
  el.spacer.style.height = (total * ROW_H) + 'px';
  el.empty.hidden = total > 0;

  const top = el.viewport.scrollTop;
  const visible = Math.ceil(el.viewport.clientHeight / ROW_H);
  let first = Math.max(0, Math.floor(top / ROW_H) - OVERSCAN);
  let last = Math.min(total, first + visible + OVERSCAN * 2);

  const need = last - first;
  while (el.rows.children.length < need) el.rows.appendChild(makeRow());
  while (el.rows.children.length > need) el.rows.lastChild.remove();

  el.rows.style.transform = `translateY(${first * ROW_H}px)`;

  for (let i = 0; i < need; i++) {
    const r = state.view[first + i];
    const row = el.rows.children[i];
    row.dataset.index = String(first + i);
    row.className = 'row ' + kindClass(r)
      + (r.incomplete ? ' incomplete' : '')
      + (isFailure(r) ? ' failed' : '')
      + (state.selected && state.selected.id === r.id ? ' sel' : '');
    const [t, s, sev, k, call, msg] = row.children;
    t.textContent = clock(r);
    s.textContent = r.source || '';
    sev.textContent = severityCell(r);
    sev.className = 'c-sev' + (typeof r.severity === 'number' && r.severity >= 0 ? ' s' + r.severity : '');
    k.textContent = kindLabel(r);
    call.textContent = r.call || '';
    msg.textContent = summary(r);
  }

  state.firstRendered = first;
  state.lastRendered = last;
  updateCount();
}

function updateCount() {
  const shown = state.view.length, total = state.all.length;
  let s = shown === total ? `${total.toLocaleString()} records`
                          : `${shown.toLocaleString()} of ${total.toLocaleString()}`;
  if (state.held.length) s += ` · ${state.held.length.toLocaleString()} held`;
  el.count.textContent = s;
}

function scrollToEnd() {
  el.viewport.scrollTop = el.viewport.scrollHeight;
}

// ---------------------------------------------------------------- filtering

function matches(r) {
  const f = state.filter;
  // A notice — a sequence gap, records the ring overwrote — is never filtered
  // out by severity or type. It explains what is *not* on screen, so hiding it
  // would defeat its purpose.
  if (r.notice) return !f.text || haystack(r).includes(f.text);
  if (f.source && r.source !== f.source) return false;
  if (f.incomplete && !r.incomplete) return false;
  // Severity -1 means the datagram carried no priority. There is nothing to
  // compare, so a severity filter must not silently hide it.
  if (f.severity >= 0 && typeof r.severity === 'number' && r.severity >= 0
      && r.severity > f.severity) return false;
  if (f.kind) {
    if (f.kind === 'sip' && !r.sip) return false;
    if (f.kind !== 'sip' && r.kind !== f.kind) return false;
  }
  if (f.text && !haystack(r).includes(f.text)) return false;
  return true;
}

// The whole record is searchable, not just its first line: a number is in an
// SDP body or a To header, not in the debug prefix. The string is built once
// and cached, because the filter runs over every record on every keystroke.
function haystack(r) {
  if (r._hay === undefined) {
    const parts = [r.source || '', r.call || '', summary(r)];
    if (r.raw) parts.push(r.raw.join('\n'));
    r._hay = parts.join('\n').toLowerCase();
  }
  return r._hay;
}

function applyFilter() {
  state.filter = {
    text: el.filter.value.trim().toLowerCase(),
    severity: Number(el.severity.value),
    kind: el.kind.value,
    source: el.source.value,
    incomplete: el.incomplete.checked,
  };
  state.view = state.all.filter(matches);
  render();
  if (state.follow) scrollToEnd();
}

// ---------------------------------------------------------------- ingesting

function addRecords(records) {
  if (!records.length) return;
  if (state.paused) {
    for (const r of records) {
      if (r.id > state.lastId) state.lastId = r.id;
      state.held.push(r);
    }
    trim(state.held);
    updateCount();
    return;
  }
  let grew = false;
  for (const r of records) {
    if (r.id && r.id <= state.lastId) continue; // a resync may repeat records
    if (r.id) state.lastId = r.id;
    if (r.source) state.sources.add(r.source);
    state.all.push(r);
    if (matches(r)) { state.view.push(r); grew = true; }
  }
  trim(state.all);
  if (state.all.length < state.view.length) state.view = state.all.filter(matches);
  refreshSources();
  if (grew || records.length) render();
  if (state.follow) scrollToEnd();
}

// The browser keeps its own ring. Without one, a session left open overnight
// eats the machine's memory; the server still has whatever it has room for.
function trim(list) {
  if (list.length <= MAX_RECORDS) return;
  const drop = list.length - MAX_RECORDS;
  list.splice(0, drop);
  if (list === state.all) state.view = state.all.filter(matches);
}

// A notice is a synthetic row that explains something the records cannot: a
// gap in the numbering, or this tool running out of room. It is deliberately
// distinct from a record, and from a loss on the wire.
function notice(text) {
  addRecords([{
    id: 0,
    time: new Date().toISOString(),
    notice: text,
    kind: 'notice',
    severity: -1,
  }]);
}

function refreshSources() {
  const want = [''].concat([...state.sources].sort());
  if (el.source.options.length === want.length) return;
  const cur = el.source.value;
  el.source.innerHTML = '';
  for (const s of want) {
    const o = document.createElement('option');
    o.value = s;
    o.textContent = s === '' ? 'all devices' : s;
    el.source.appendChild(o);
  }
  el.source.value = cur;
}

// ---------------------------------------------------------------- detail

function select(r) {
  state.selected = r;
  el.detail.hidden = false;
  el.detailTitle.textContent = summary(r).slice(0, 80) || 'record';

  const rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') rows.push([k, v]); };
  add('time', r.time ? new Date(r.time).toISOString().replace('T', ' ').replace('Z', '') : '');
  if (r.timeTrusted === false) add('clock', 'not synchronised — the device flagged it with *');
  add('received', r.received ? new Date(r.received).toLocaleTimeString() : '');
  add('source', r.source);
  add('severity', r.severityName ? `${r.severityName} (${r.severity})` : undefined);
  add('record seq', r.hasSeq ? r.seq : undefined);
  add('line seq', r.hasLineSeq ? `${r.firstLineSeq}–${r.lastLineSeq} (${r.lines} datagram${r.lines === 1 ? '' : 's'})` : undefined);
  add('call', r.call);
  if (r.debug) {
    add('call entry id', r.debug.callId === -1 ? '-1 (none yet)' : r.debug.callId);
    add('guid', r.debug.guid);
  }
  if (r.sip) {
    add('sip call-id', r.sip.callId);
    add('cseq', r.sip.cseqNum ? `${r.sip.cseqNum} ${r.sip.cseqMethod || ''}` : undefined);
    if (r.sip.from) add('from', r.sip.from.uri || r.sip.from.user);
    if (r.sip.to) add('to', r.sip.to.uri || r.sip.to.user);
    add('content-length', r.sip.hasContentLength
      ? `${r.sip.contentLength} (body ${r.sip.bodyBytes})` : undefined);
  }
  if (r.missingLines) add('missing', `${r.missingLines} line(s) lost or rate-limited`);

  let html = '<dl>';
  for (const [k, v] of rows) {
    html += `<dt>${escape(k)}</dt><dd>${escape(String(v))}</dd>`;
  }
  html += '</dl>';
  for (const w of r.warnings || []) html += `<p class="warn">⚠ ${escape(w)}</p>`;
  if (r.sip && r.sip.truncated) {
    html += '<p class="warn">⚠ the body is shorter than its Content-Length: '
          + 'lines of this message did not arrive</p>';
  }
  el.detailMeta.innerHTML = html;
  el.detailRaw.textContent = (r.raw || [r.text || r.notice || '']).join('\n');
  render();
}

function escape(s) {
  return s.replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function closeDetail() {
  el.detail.hidden = true;
  state.selected = null;
  render();
}

// ---------------------------------------------------------------- status bar

function showStatus(st) {
  const s = st.store || {};
  const bits = [];
  if (st.listen) bits.push(`listening ${st.listen}`);
  if (st.allow && st.allow !== 'any') bits.push(`allow ${st.allow}`);
  bits.push(`${(s.records || 0).toLocaleString()} / ${(s.cap || 0).toLocaleString()} held`);
  if (s.evicted) bits.push(`${s.evicted.toLocaleString()} aged out of the ring`);
  if (st.listener && st.listener.blocked) bits.push(`${st.listener.blocked} blocked`);
  el.statusStore.textContent = bits.join(' · ');

  const parts = [];
  for (const src of st.sources || []) {
    let t = `<span class="src">${escape(src.source)}</span> `
          + `${src.records.toLocaleString()} rec / ${src.lines.toLocaleString()} lines`;
    // "lost or rate-limited", never "lost": this router rate-limits its own
    // logging, and telling an engineer they have a network problem while their
    // router throttles itself sends them looking in the wrong place.
    const lost = [];
    if (src.lostLines) lost.push(`${src.lostLines} line(s)`);
    if (src.lostRecords) lost.push(`${src.lostRecords} record(s)`);
    if (lost.length) t += ` · <span class="lost">${lost.join(', ')} lost or rate-limited</span>`;
    if (src.held) t += ` · ${src.held} held`;
    if (src.noSeq) t += ` · <span class="lost">no sequence numbers</span>`;
    parts.push(t);
  }
  el.statusSources.innerHTML = parts.join(' &nbsp; ');
}

// ---------------------------------------------------------------- socket

let sock = null;
let retry = 500;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  // Resuming by id is what makes a dropped socket invisible: the server sends
  // what was missed instead of the browser starting over.
  const since = state.lastId ? `?since=${state.lastId}` : '';
  setConn('connecting', '');
  sock = new WebSocket(`${proto}//${location.host}/ws${since}`);

  sock.onopen = () => { retry = 500; setConn('live', 'live'); };

  sock.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch { return; }
    switch (m.type) {
      case 'hello':
        if (m.status && m.status.title) {
          document.title = `${m.status.title} — cube-logger`;
        }
        showStatus(m.status || {});
        break;
      case 'records':
        addRecords(m.records || []);
        break;
      case 'stats':
        showStatus(m.status || {});
        break;
      case 'resync':
        // Records existed that this browser will never see, because the
        // server's ring overwrote them. That is this tool running out of room,
        // not the router or the network losing output, and it says so.
        notice(`${m.missed.toLocaleString()} record(s) are not shown: `
             + `they were dropped from the server's buffer before this view could catch up. `
             + `This is the tool's buffer filling, not loss on the wire.`);
        break;
    }
  };

  sock.onclose = () => {
    setConn('offline', 'down');
    setTimeout(connect, retry);
    retry = Math.min(retry * 2, 10000);
  };
  sock.onerror = () => { try { sock.close(); } catch {} };
}

function setConn(text, cls) {
  el.conn.textContent = text;
  el.conn.className = 'pill' + (cls ? ' ' + cls : '');
}

// ---------------------------------------------------------------- controls

function setPaused(p) {
  state.paused = p;
  el.pause.textContent = p ? 'Resume' : 'Pause';
  el.pause.classList.toggle('on', p);
  if (!p && state.held.length) {
    const held = state.held;
    state.held = [];
    addRecords(held);
  }
  updateCount();
}

function setFollow(f) {
  state.follow = f;
  el.follow.classList.toggle('on', f);
  if (f) scrollToEnd();
}

el.pause.addEventListener('click', () => setPaused(!state.paused));
el.follow.addEventListener('click', () => setFollow(!state.follow));
el.clear.addEventListener('click', () => {
  state.all = []; state.view = []; state.held = [];
  closeDetail();
  render();
});
el.detailClose.addEventListener('click', closeDetail);

for (const c of [el.severity, el.kind, el.source, el.incomplete]) {
  c.addEventListener('change', applyFilter);
}

// Debounced, because a keystroke rescans the whole session.
let filterTimer = null;
el.filter.addEventListener('input', () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, 80);
});

el.viewport.addEventListener('scroll', () => {
  // Scrolling up turns following off, which is what an engineer reaching for
  // the scrollbar means. Scrolling back to the bottom turns it on again.
  const atEnd = el.viewport.scrollHeight - el.viewport.scrollTop
              - el.viewport.clientHeight < ROW_H;
  if (state.follow && !atEnd) setFollow(false);
  else if (!state.follow && atEnd) setFollow(true);
  render();
}, { passive: true });

window.addEventListener('resize', render);

document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  if (e.key === ' ') { e.preventDefault(); setPaused(!state.paused); }
  else if (e.key === 'Escape') closeDetail();
  else if (e.key === '/') { e.preventDefault(); el.filter.focus(); }
  else if (e.key === 'End') { setFollow(true); }
});

render();
connect();
