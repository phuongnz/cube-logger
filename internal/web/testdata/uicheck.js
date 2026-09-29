// uicheck runs the page's own script, ui/app.js, in node, feeds it what a real
// server sent over the socket, and checks what the page makes of it.
//
//   node uicheck.js <app.js> <transcript.json>
//
// ui_test.go writes the transcript from a live test server:
//
//   stream   the messages a new socket received, in order: hello, records, calls
//   calls    optional: for each call id, the "call" message the server pushed
//            once the page had selected that call
//   restart  optional: a second server, standing in for the first one restarted.
//            path is the socket path it was dialled on, which must be what the
//            page asks for when it reconnects; open is a call to have open when
//            the first socket drops; stream is what the second server sent
//
// The Go tests check what the server sends. Nothing checked what the page then
// does with it, and the ladder threw on its first arrow from the day it was
// written while every test passed. The DOM here is a stand-in that models only
// what the checks read. It is not a browser, so layout and styling are out of
// reach, but an exception, a filter that shows the wrong rows, or a ladder that
// is never drawn are not.
'use strict';

const fs = require('fs');
const vm = require('vm');

const [appPath, transcriptPath] = process.argv.slice(2);
const transcript = JSON.parse(fs.readFileSync(transcriptPath, 'utf8'));

// ---------------------------------------------------------------- a stand-in DOM

// fakeEl is an element that keeps its children, attributes, classes and text,
// and answers every method it does not model with a no-op, so the page can
// build status bars and menus without the checks having to care about them.
function fakeEl(tag = 'div') {
  const store = {
    tagName: tag.toUpperCase(), children: [], dataset: {}, style: {}, attrs: {},
    value: '', checked: false, hidden: false, options: [],
    clientWidth: 900, clientHeight: 600, scrollHeight: 0, scrollTop: 0,
    namespaceURI: 'http://www.w3.org/2000/svg',
  };
  let text = '';
  const classes = new Set();
  const self = new Proxy(store, {
    get(t, k) {
      switch (k) {
        case 'appendChild': return (c) => { t.children.push(c); c.__parent = t; return c; };
        case 'append': return (...cs) => cs.forEach((c) => { t.children.push(c); c.__parent = t; });
        case 'prepend': return (...cs) => { cs.forEach((c) => { c.__parent = t; }); t.children.unshift(...cs); };
        case 'replaceChildren': return (...cs) => { t.children = cs; };
        case 'remove': return () => { const p = t.__parent; if (p) p.children = p.children.filter((x) => x !== self); };
        case 'lastChild': return t.children[t.children.length - 1] ?? null;
        case 'firstChild': return t.children[0] ?? null;
        case 'setAttribute': return (a, v) => { t.attrs[a] = String(v); };
        case 'getAttribute': return (a) => t.attrs[a];
        case 'querySelectorAll': return () => [];
        case 'querySelector': return () => null;
        case 'textContent': return text;
        case 'classList': return {
          add: (...c) => c.forEach((x) => classes.add(x)),
          remove: (...c) => c.forEach((x) => classes.delete(x)),
          toggle: (c, on) => ((on ?? !classes.has(c)) ? classes.add(c) : classes.delete(c)),
          contains: (c) => classes.has(c),
        };
      }
      if (k in t) return t[k];
      if (typeof k === 'symbol') return undefined;
      return () => fakeEl();
    },
    set(t, k, v) {
      if (k === 'textContent') { text = String(v); t.children = []; return true; }
      t[k] = v;
      return true;
    },
  });
  return self;
}

const elements = new Map();
const document = {
  getElementById: (id) => { if (!elements.has(id)) elements.set(id, fakeEl()); return elements.get(id); },
  createElement: (tag) => fakeEl(tag),
  createElementNS: (_ns, tag) => fakeEl(tag),
  addEventListener: () => {},
  title: '',
};

// Every socket the page opens, newest last. The checks play the server.
const sockets = [];
class FakeWebSocket {
  constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
  send(m) { this.sent.push(JSON.parse(m)); }
  close() {}
}
FakeWebSocket.OPEN = 1;

const timers = [];
const ctx = vm.createContext({
  document, console, WebSocket: FakeWebSocket,
  // Timers are held rather than run, so nothing fires behind the checks' back.
  setTimeout: (f) => { timers.push(f); return timers.length; },
  clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
  location: { host: '127.0.0.1:8514', protocol: 'http:' },
  window: { addEventListener: () => {} },
  fetch: () => new Promise(() => {}),
  requestAnimationFrame: () => 0,
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  Blob: class {}, URL: { createObjectURL: () => '', revokeObjectURL: () => {} },
  navigator: { clipboard: { writeText: async () => {} } },
});

// The checks need the page's state and the two things a click on the call list
// does. They are top-level bindings of the script, so they are handed out by a
// line appended to it rather than by changing the page.
const src = fs.readFileSync(appPath, 'utf8')
  + '\n;globalThis.__page = { state, el, openCall, closeCall };\n';
vm.runInContext(src, ctx, { filename: 'app.js' });
const page = ctx.__page;
// What the page starts with: the first option of each drop-down in index.html.
page.el.severity.value = '-1';
page.el.kind.value = '';

// ---------------------------------------------------------------- checks

let failures = 0;
function check(ok, what) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
  if (!ok) failures++;
}

// deliver hands one server message to the page the way the browser does. An
// exception is a failure in its own right: in a browser it goes to a console
// nobody is watching, and the page carries on half-updated.
function deliver(sock, msg) {
  try {
    sock.onmessage({ data: JSON.stringify(msg) });
  } catch (e) {
    check(false, `the page threw on a "${msg.type}" message: ${e.name}: ${e.message}`);
  }
}

// ladderArrows counts what drawLadder put on screen: one group per message or
// note, inside the one SVG it appends.
function ladderArrows() {
  const svg = page.el.ladderBody.children.find((c) => c.tagName === 'SVG');
  return svg ? svg.children.filter((c) => c.tagName === 'G').length : 0;
}

const sock = sockets[0];
check(!!sock, 'the page opens a socket when it loads');
sock.readyState = FakeWebSocket.OPEN;
if (sock.onopen) sock.onopen();

let total = 0;
for (const msg of transcript.stream) {
  if (msg.type === 'records') total += msg.records.length;
  deliver(sock, msg);
}
check(total > 0, `the server sent ${total} record(s)`);
check(page.state.view.length === total, `with no call selected, the table shows all ${total} record(s)`);

// Selecting each call narrows the table to it and draws its ladder; closing it
// brings everything back.
function checkCalls() {
  const ids = Object.keys(transcript.calls);
  check(ids.length > 1, `${ids.length} calls to select, so selecting one has something to leave out`);
  for (const id of ids) {
    const call = transcript.calls[id].call;
    page.openCall(id);
    const last = sock.sent[sock.sent.length - 1];
    check(last && last.type === 'select' && last.call === id, `${id}: selecting it tells the server`);

    deliver(sock, transcript.calls[id]);
    const refs = new Set(call.recordRefs);
    const shown = page.state.view.map((r) => r.id);
    check(shown.length === refs.size && shown.every((x) => refs.has(x)),
      `${id}: the table shows its ${refs.size} record(s) and nothing else (shows ${shown.length})`);
    check(page.el.empty.hidden === true, `${id}: the table does not say it is waiting for syslog`);
    const want = (call.ladder.arrows || []).length + (call.ladder.notes || []).length;
    check(ladderArrows() === want, `${id}: the ladder draws ${want} message(s) (draws ${ladderArrows()})`);

    page.closeCall();
    check(page.state.view.length === total, `${id}: closing it shows all ${total} record(s) again`);
  }
}

// The server goes away with a call open and comes back as a new process: its
// records and calls are numbered from 1 again. The page reconnects on its own
// timer and has to end up showing the new server's records, all of them and
// nothing else.
function checkRestart() {
  const r = transcript.restart;
  page.openCall(r.open);

  const before = timers.length;
  sock.onclose();
  timers.slice(before).forEach((f) => f());
  const next = sockets[sockets.length - 1];
  check(next !== sock, 'the page reconnects when its socket drops');
  check(next.url.endsWith(r.path), `it asks for ${r.path} (asks for ${next.url})`);

  next.readyState = FakeWebSocket.OPEN;
  if (next.onopen) next.onopen();
  const want = [];
  for (const msg of r.stream) {
    if (msg.type === 'records') want.push(...msg.records.map((x) => x.id));
    deliver(next, msg);
  }
  const shown = page.state.view.map((x) => x.id);
  check(want.length > 0 && shown.length === want.length && shown.every((x, i) => x === want[i]),
    `after the restart the table shows the new server's ${want.length} record(s) and nothing else `
    + `(shows ${shown.length}: ${shown.slice(0, 5).join(',')}${shown.length > 5 ? ',…' : ''})`);
  check(page.state.callId === null, `the call open before the restart (${r.open}) is closed`);
  check(!next.sent.some((m) => m.type === 'select' && m.call === r.open),
    `the page does not ask the new server for ${r.open}, which is not that call there`);
  const calls = r.stream.filter((m) => m.type === 'calls').flatMap((m) => m.calls || []).map((c) => c.id);
  check(page.state.calls.size === calls.length, `the call list is the new server's ${calls.length} call(s) `
    + `(has ${page.state.calls.size})`);
  check(/restarted/.test(page.el.notice.textContent), `the page says why its view started over `
    + `("${page.el.notice.textContent}")`);
}

if (transcript.calls) checkCalls();
if (transcript.restart) checkRestart();

process.exit(failures ? 1 : 0);
