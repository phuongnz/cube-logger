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
  open: $('open'), save: $('save'), openfile: $('openfile'), notice: $('notice'),
  viewport: $('viewport'), spacer: $('spacer'), rows: $('rows'), empty: $('empty'),
  detail: $('detail'), detailTitle: $('detail-title'), detailMeta: $('detail-meta'),
  detailRaw: $('detail-raw'), detailClose: $('detail-close'),
  statusStore: $('status-store'), statusSources: $('status-sources'),
  calls: $('calls'), callsToggle: $('calls-toggle'), callsList: $('calls-list'),
  callsEmpty: $('calls-empty'), callsCount: $('calls-count'),
  callsKeepalives: $('calls-keepalives'),
  ladder: $('ladder'), ladderTitle: $('ladder-title'), ladderSub: $('ladder-sub'),
  ladderBody: $('ladder-body'),
  callCopy: $('call-copy'), callDownload: $('call-download'), callClose: $('call-close'),
};

const state = {
  all: [],            // every record received, oldest first
  byId: new Map(),    // record id -> record, for the ladder's arrows
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

  // The call side. `calls` is the list the server keeps in step by revision;
  // `call` is the one opened, with its record references and its ladder, and
  // `callRefs` is what narrows the table to it.
  hasIndex: false,
  calls: new Map(),
  callId: null,
  call: null,
  callRefs: null,
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
function clock(r) { return clockTime(r.time); }

function clockTime(iso) {
  if (!iso) return '';
  const t = new Date(iso);
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
  // A call is selected: the table is that call and nothing else, notices
  // included. A row from somewhere else in the session, sitting inside what
  // says it is one call, is worse than not being shown at all.
  if (state.callRefs && !state.callRefs.has(r.id)) return false;
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
    if (r.id) state.byId.set(r.id, r);
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
  const gone = list.splice(0, drop);
  if (list === state.all) {
    for (const r of gone) state.byId.delete(r.id);
    state.view = state.all.filter(matches);
  }
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

// ---------------------------------------------------------------- calls

// The call list is the other half of this tool: a table of records tells you
// what the router said, a list of calls tells you which call to look at. The
// server keeps it in step by revision, so what arrives here is what changed.

const CALL_ROWS = 400;   // rows drawn in the pane; the index holds far more

function applyCallUpdate(u) {
  state.hasIndex = true;
  if (u.reset) state.calls.clear();
  for (const c of u.calls || []) {
    c._t = Date.parse(c.start) || 0;
    state.calls.set(c.id, c);
  }
  for (const id of u.removed || []) {
    // A removed call is either evicted or merged into its other leg. If it is
    // the one on screen, the server tells us which call it became in the next
    // "call" message, so the pane is left alone here.
    state.calls.delete(id);
  }
  showCallsPane();
  renderCalls();
}

function callRows() {
  const keep = el.callsKeepalives.checked;
  const rows = [];
  for (const c of state.calls.values()) {
    if (c.keepalive && !keep) continue;
    rows.push(c);
  }
  // Newest first: the call an engineer is asking about is the one that just
  // happened.
  rows.sort((a, b) => b._t - a._t);
  return rows;
}

function renderCalls() {
  const rows = callRows();
  const shown = rows.slice(0, CALL_ROWS);
  el.callsEmpty.hidden = rows.length > 0;
  el.callsCount.textContent = rows.length
    ? (rows.length > shown.length ? `${shown.length} of ${rows.length}` : String(rows.length))
    : '';

  const list = el.callsList;
  while (list.children.length < shown.length) list.appendChild(makeCallRow());
  while (list.children.length > shown.length) list.lastChild.remove();

  for (let i = 0; i < shown.length; i++) {
    const c = shown[i], row = list.children[i];
    row.dataset.id = c.id;
    row.className = 'call-row'
      + (c.failed ? ' failed' : '')
      + (c.state !== 'ended' ? ' active' : '')
      + (c.keepalive ? ' keepalive' : '')
      + (c.id === state.callId ? ' sel' : '');
    const [line1, line2] = row.children;
    const [from, arrow, to] = line1.children;
    const [time, dur, res] = line2.children;
    from.textContent = c.calling || '-';
    arrow.textContent = '→';
    to.textContent = c.called || '-';
    time.textContent = clockTime(c.start);
    dur.textContent = duration(c);
    res.textContent = result(c);
    row.title = `${c.id}${c.guid ? ' · ' + c.guid : ''}`
      + `\n${c.legs} leg(s), ${c.records} record(s)`
      + (c.warnings && c.warnings.length ? '\n⚠ ' + c.warnings.join('\n⚠ ') : '');
  }
}

function makeCallRow() {
  const row = document.createElement('div');
  row.className = 'call-row';
  row.setAttribute('role', 'listitem');
  const line1 = document.createElement('div');
  line1.className = 'cl-who';
  for (const cls of ['cl-from', 'cl-arrow', 'cl-to']) {
    const s = document.createElement('span');
    s.className = cls;
    line1.appendChild(s);
  }
  const line2 = document.createElement('div');
  line2.className = 'cl-meta';
  for (const cls of ['cl-time', 'cl-dur', 'cl-res']) {
    const s = document.createElement('span');
    s.className = cls;
    line2.appendChild(s);
  }
  row.append(line1, line2);
  row.addEventListener('click', () => {
    if (row.dataset.id === state.callId) closeCall();
    else openCall(row.dataset.id);
  });
  return row;
}

// duration is how long the call lasted, at the precision an engineer reads:
// milliseconds for a setup that failed, seconds for a call that connected.
function duration(c) {
  const ms = c.durationMs || 0;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60000), s = Math.round((ms % 60000) / 1000);
  return `${m}m${String(s).padStart(2, '0')}s`;
}

// result is the answer to "what happened to it", in one cell.
function result(c) {
  if (c.iec) return `${c.result || c.cause || 'failed'} · IEC`;
  const r = [c.result, c.cause].filter(Boolean).join(' ');
  if (r) return r;
  return c.state === 'ended' ? 'ended' : (c.state || '');
}

// ---------------------------------------------------------------- one call

function openCall(id) {
  state.callId = id;
  state.call = null;
  state.callRefs = new Set();   // nothing until the detail arrives
  tellServer();
  renderCalls();
  showCall(null);
  applyFilter();
  // If the socket is down the list is still on screen and still clickable, so
  // the call is fetched instead. The view should not stop working because the
  // stream did.
  if (!sock || sock.readyState !== WebSocket.OPEN) {
    fetch(`/api/calls/${encodeURIComponent(id)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (d && state.callId === id) gotCall(d); })
      .catch(() => {});
  }
}

function closeCall() {
  state.callId = null;
  state.call = null;
  state.callRefs = null;
  tellServer();
  renderCalls();
  showCall(null);
  applyFilter();
}

// tellServer says which call this browser is looking at, so the server pushes
// that call as it grows instead of the browser asking once a second.
function tellServer() {
  if (sock && sock.readyState === WebSocket.OPEN) {
    sock.send(JSON.stringify({ type: 'select', call: state.callId || '' }));
  }
}

function gotCall(d) {
  // Two legs that turn out to be one call are merged under one id, so the call
  // that comes back is not always the one that was asked for.
  state.callId = d.id;
  state.call = d;
  state.callRefs = new Set(d.recordRefs || []);
  renderCalls();
  showCall(d);
  applyFilter();
}

function showCall(d) {
  el.ladder.hidden = !d && !state.callId;
  if (!state.callId) return;
  if (!d) {
    el.ladderTitle.textContent = 'loading…';
    el.ladderSub.textContent = '';
    el.ladderBody.textContent = '';
    return;
  }
  el.ladderTitle.textContent = `${d.calling || '-'} → ${d.called || '-'}`;
  const bits = [d.id];
  if (d.guid) bits.push(d.guid);
  bits.push(duration(d));
  const r = result(d);
  if (r) bits.push(r);
  if (d.iec) bits.push(`IEC ${d.iec}`);
  bits.push(`${d.recordRefs ? d.recordRefs.length : 0} record(s)`);
  // A ladder drawn from records the ring has overwritten is a ladder with
  // messages missing from it, and it says so rather than reading as complete.
  if (d.ladder && d.ladder.missing) {
    bits.push(`${d.ladder.missing} no longer held`);
  }
  el.ladderSub.textContent = bits.join(' · ');
  el.ladderSub.className = 'muted' + (d.ladder && d.ladder.missing ? ' lost' : '');
  drawLadder(d.ladder);
}

// ---------------------------------------------------------------- ladder

const SVG = $('ns').namespaceURI;   // see the note in index.html
const LAD = { top: 34, row: 26, gutter: 74, pad: 12, minCol: 130 };

function svg(name, attrs, text) {
  const e = document.createElementNS(SVG, name);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  return e;
}

// drawLadder draws one column per endpoint — the CUBE in the middle, a peer on
// each side — and one row per message, in time order. It is the picture an
// engineer draws on a whiteboard when asked who sent what first.
function drawLadder(l) {
  el.ladderBody.textContent = '';
  if (!l || !l.columns || !l.columns.length) {
    el.ladderBody.appendChild(note('nothing to draw: this call has no SIP messages in the buffer'));
    return;
  }
  const items = ((l.arrows || []).map((a) => ({ a })))
    .concat((l.notes || []).map((n) => ({ n })))
    .sort((x, y) => {
      const tx = Date.parse((x.a || x.n).time) || 0, ty = Date.parse((y.a || y.n).time) || 0;
      if (tx !== ty) return tx - ty;
      return ((x.a || x.n).ref || 0) - ((y.a || y.n).ref || 0);
    });

  const cols = l.columns.length;
  const avail = Math.max(el.ladderBody.clientWidth - LAD.gutter - LAD.pad * 2, 240);
  const colW = Math.max(LAD.minCol, avail / cols);
  const width = LAD.gutter + colW * cols + LAD.pad * 2;
  const height = LAD.top + Math.max(items.length, 1) * LAD.row + LAD.pad;
  const x = (i) => LAD.gutter + LAD.pad + colW * (i + 0.5);

  const s = svg('svg', {
    width, height, viewBox: `0 0 ${width} ${height}`, class: 'ladder-svg',
  });

  for (let i = 0; i < cols; i++) {
    const c = l.columns[i];
    const label = svg('text', {
      x: x(i), y: 14, 'text-anchor': 'middle',
      class: 'lad-col' + (c.kind === 'cube' ? ' cube' : ''),
    }, fit(c.label || '?', colW));
    label.appendChild(svg('title', {}, `${c.kind === 'cube' ? 'this CUBE' : 'peer'}: ${c.label || 'unknown'}`
      + (c.legs && c.legs.length ? `\nleg(s): ${c.legs.join(', ')}` : '')));
    s.appendChild(label);
    s.appendChild(svg('line', {
      x1: x(i), y1: 20, x2: x(i), y2: height - 4,
      class: 'lad-life' + (c.kind === 'cube' ? ' cube' : ''),
    }));
  }

  items.forEach((it, i) => {
    const y = LAD.top + i * LAD.row + LAD.row / 2;
    const g = svg('g', { class: 'lad-item', 'data-ref': src.ref || 0 });
    const src = it.a || it.n;
    g.appendChild(svg('text', { x: 4, y: y + 4, class: 'lad-time' }, clockTime(src.time)));

    if (it.n) {
      // A % log line: it belongs to the call but is not a message between two
      // endpoints, so it spans the diagram rather than pointing anywhere.
      g.appendChild(svg('line', {
        x1: LAD.gutter, y1: y, x2: width - LAD.pad, y2: y, class: 'lad-note-line',
      }));
      g.appendChild(svg('text', {
        x: LAD.gutter + 6, y: y - 4,
        class: 'lad-note' + (it.n.severity >= 0 && it.n.severity <= 3 ? ' bad' : ''),
      }, fit(it.n.text, width - LAD.gutter - 20)));
    } else {
      const a = it.a;
      const from = x(a.from), to = x(a.to);
      const dir = to >= from ? 1 : -1;
      const head = to - dir * 6;
      g.appendChild(svg('line', {
        x1: from, y1: y, x2: head, y2: y, class: 'lad-arrow ' + (a.class || 'request'),
      }));
      g.appendChild(svg('polygon', {
        points: `${to},${y} ${head},${y - 4} ${head},${y + 4}`,
        class: 'lad-head ' + (a.class || 'request'),
      }));
      g.appendChild(svg('text', {
        x: (from + to) / 2, y: y - 5, 'text-anchor': 'middle',
        class: 'lad-label ' + (a.class || 'request'),
      }, fit(a.label || '', Math.abs(to - from))));
      if (a.incomplete) {
        g.appendChild(svg('text', { x: width - LAD.pad - 4, y: y + 4, 'text-anchor': 'end', class: 'lad-warn' }, '⚠'));
      }
    }

    const tip = it.a
      ? `${it.a.label}${it.a.cseq ? '\nCSeq ' + it.a.cseq : ''}${it.a.leg ? '\nleg ' + it.a.leg : ''}`
        + (it.a.incomplete ? '\n⚠ lines of this message are missing' : '')
      : it.n.text;
    g.appendChild(svg('title', {}, tip + '\n(click to open the record)'));
    g.addEventListener('click', () => openRef(src.ref));
    s.appendChild(g);
  });

  el.ladderBody.appendChild(s);
  markLadder();
}

// markLadder keeps the ladder and the table pointing at the same record, from
// whichever side it was clicked.
function markLadder() {
  const want = state.selected ? String(state.selected.id) : '';
  for (const g of el.ladderBody.querySelectorAll('.lad-item')) {
    g.classList.toggle('sel', g.dataset.ref === want);
  }
}

function note(text) {
  const p = document.createElement('p');
  p.className = 'muted lad-empty';
  p.textContent = text;
  return p;
}

// fit shortens a label to what its column can hold. The monospaced font makes
// the estimate good enough, and a label that overlaps its neighbour is worse
// than one that is cut.
function fit(text, px) {
  const n = Math.max(4, Math.floor((px - 8) / 6.2));
  return text.length <= n ? text : text.slice(0, n - 1) + '…';
}

// openRef opens the record an arrow was drawn from, and scrolls the table to
// it: the ladder is the map, the table is the territory.
function openRef(ref) {
  const r = state.byId.get(ref);
  if (!r) {
    // Said here rather than as a notice row: with a call open the table is
    // that call, and a notice row would be filtered out of the one place the
    // engineer is looking.
    el.ladderSub.textContent = `record ${ref} is no longer in this browser's buffer`;
    el.ladderSub.className = 'muted lost';
    return;
  }
  select(r);
  const i = state.view.indexOf(r);
  if (i >= 0) {
    setFollow(false);
    el.viewport.scrollTop = Math.max(0, i * ROW_H - el.viewport.clientHeight / 2);
    render();
  }
}

// ---------------------------------------------------------------- export

// Copy and download both take the server's rendering rather than building one
// here, so that what is pasted into a ticket and what is saved to a file are
// the same text, holes and all.
function callText() {
  return fetch(`/api/calls/${encodeURIComponent(state.callId)}/text`)
    .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`status ${r.status}`))));
}

function copyCall() {
  if (!state.callId) return;
  callText().then((text) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(() => flash(el.callCopy, 'Copied'));
    }
    return Promise.reject(new Error('no clipboard'));
  }).catch(() => {
    // A browser that will not give the page the clipboard still has to let the
    // engineer have the text, so it goes on screen to be selected by hand.
    callText().then((text) => {
      el.detail.hidden = false;
      el.detailTitle.textContent = state.callId;
      el.detailMeta.innerHTML = '<p class="warn">This browser would not let the page write to '
        + 'the clipboard. Select the text below and copy it.</p>';
      el.detailRaw.textContent = text;
    }).catch(() => flash(el.callCopy, 'Failed'));
  });
}

function flash(button, text) {
  const was = button.textContent;
  button.textContent = text;
  setTimeout(() => { button.textContent = was; }, 1200);
}

function downloadCall() {
  if (!state.callId) return;
  const a = document.createElement('a');
  a.href = `/api/calls/${encodeURIComponent(state.callId)}/text`;
  a.download = `${state.callId}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
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
  markLadder();
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
  markLadder();
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
  if (st.calls) {
    state.hasIndex = true;
    let c = `${st.calls.calls.toLocaleString()} call(s)`;
    if (st.calls.active) c += `, ${st.calls.active} up`;
    if (st.calls.evicted) c += `, ${st.calls.evicted.toLocaleString()} aged out`;
    bits.push(c);
  }
  showCallsPane();
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

  sock.onopen = () => {
    retry = 500;
    setConn('live', 'live');
    // The server does not remember a browser across a dropped socket, so the
    // open call is announced again rather than quietly going stale.
    tellServer();
  };

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
      case 'calls':
        applyCallUpdate(m);
        break;
      case 'call':
        if (m.gone) {
          // The call is not there any more: evicted, or the session was
          // cleared. Saying so and showing everything again beats an empty
          // table with a filter on it that cannot be explained.
          if (state.callId === m.gone) {
            notice(`call ${m.gone} is no longer held: the tool dropped it to stay within its limit`);
            closeCall();
          }
        } else if (m.call && state.callId) {
          // The id may have changed under us: two legs that turn out to be one
          // call are merged, and the survivor is what comes back.
          gotCall(m.call);
        }
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
  state.byId.clear();
  closeDetail();
  render();
});

// The call pane can be put away: on a narrow screen the table is the thing
// being read, and the list is a second window into the same session.
function showCallsPane() {
  const on = state.hasIndex && el.callsToggle.classList.contains('on');
  el.calls.hidden = !on;
  el.callsToggle.hidden = !state.hasIndex;
}
el.callsToggle.addEventListener('click', () => {
  el.callsToggle.classList.toggle('on');
  showCallsPane();
});
el.callsKeepalives.addEventListener('change', renderCalls);
el.callClose.addEventListener('click', closeCall);
el.callCopy.addEventListener('click', copyCall);
el.callDownload.addEventListener('click', downloadCall);
el.detailClose.addEventListener('click', closeDetail);

// ----------------------------------------------------------------- files
//
// Saving is a download and opening is an upload, both of the server's own
// session format. Nothing is read or written by this page directly: the server
// owns the ring, so a file opened here goes in through the same door the
// listener uses and comes back over the socket like any other record.

let noticeTimer = null;

function notice(text, bad) {
  el.notice.textContent = text;
  el.notice.classList.toggle('bad', !!bad);
  el.notice.title = text;
  clearTimeout(noticeTimer);
  if (text) noticeTimer = setTimeout(() => notice(''), 12000);
}

el.save.addEventListener('click', () => {
  // A navigation rather than fetch(): a long session is hundreds of megabytes
  // and the browser streams it to disk instead of holding it in memory.
  notice('saving this session…');
  location.href = '/api/session';
});

el.open.addEventListener('click', () => el.openfile.click());

el.openfile.addEventListener('change', async () => {
  const f = el.openfile.files[0];
  if (!f) return;
  el.openfile.value = '';        // so the same file can be opened twice
  notice(`reading ${f.name}…`);
  try {
    const r = await fetch(`/api/load?name=${encodeURIComponent(f.name)}`,
                          { method: 'POST', body: f });
    const text = await r.text();
    if (!r.ok) { notice(text.trim() || `could not read ${f.name}`, true); return; }
    const res = JSON.parse(text);
    let msg = `${res.name}: ${res.records.toLocaleString()} record(s), ${res.format}`;
    if (res.sources && res.sources.length) msg += ` — ${res.sources.join(', ')}`;
    if (res.notes && res.notes.length) msg += ` · ${res.notes.join(' · ')}`;
    notice(msg);
  } catch (e) {
    notice(`could not read ${f.name}: ${e}`, true);
  }
});

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

window.addEventListener('resize', () => {
  render();
  // The ladder is sized to the pane, so it is redrawn rather than stretched.
  if (state.call) drawLadder(state.call.ladder);
});

document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  if (e.key === ' ') { e.preventDefault(); setPaused(!state.paused); }
  else if (e.key === 'Escape') { if (!el.detail.hidden) closeDetail(); else closeCall(); }
  else if (e.key === 'c' || e.key === 'C') { el.callsToggle.click(); }
  else if (e.key === '/') { e.preventDefault(); el.filter.focus(); }
  else if (e.key === 'o' || e.key === 'O') { el.open.click(); }
  else if (e.key === 'End') { setFollow(true); }
});

showCallsPane();
render();
connect();
