# cube-logger — design

What the tool is for, how it is built and the decisions that shaped it. The log and debug
format it reads is in [log-format.md](log-format.md); how to run it is in the
[README](../README.md).

## 1. Goal

A tool for voice engineers that receives syslog and debug output from a Cisco CUBE and shows
it live, the way the AudioCodes Syslog Viewer does for AudioCodes devices:

- Log and debug lines appear in real time, color-coded and filterable.
- Every call is one unit: pick a call and see only its lines.
- Each call has a SIP ladder diagram.
- Saved logs, including `show logging` output, open in the same views.

## 2. Not in v1

- Long-term storage or search across days. This is a troubleshooting tool, not a SIEM.
- Changing CUBE configuration, such as turning debugs on over SSH.
- Reading pcap files in the product.
- A hosted or multi-user service. It runs on the engineer's own machine, or on a server of
  their own that only they reach (§5).

## 3. How it works

```
CUBE ──UDP or TLS──▶ Listener ──┐
Saved file ────────▶ Reader ────┤
                                ▼
                  Parser (no I/O: text in, records out)
                    1. syslog frame: priority, sequence number, timestamp, host
                    2. line type: log (%FACILITY-SEV-MNEMONIC) or debug (//call-id/GUID/module/...)
                    3. multi-line SIP messages joined back together
                                ▼
                  Correlator: records → calls and call legs
                    (debug call ID / GUID ↔ SIP Call-ID)
                                ▼
                  In-memory store (capped) ──WebSocket──▶ Local web UI
```

The parser and correlator are the core of the tool and do no I/O. Live traffic and saved files
go through the same code, and both can be tested with plain-text fixtures. Everything else is a
thin shell around them.

Two things the format forced, both explained in [log-format.md](log-format.md):

- **One datagram is one line, never a message.** A SIP message arrives as some twenty
  datagrams. The reassembler rejoins them into records by the per-line counter rather than by
  arrival, starts a record at a head line and ends it at the next one, keeps empty datagrams
  (they separate SIP headers from the body) and confirms completeness against
  `Content-Length`. A record whose lines are incomplete is shown as incomplete, never
  silently as whole. The device is the datagram's source address: there is no hostname in
  the frame.
- **Gaps are counted per source and on two counters.** The outer counter advances per line,
  the inner one per record: a gap in the first counts lost lines, a gap in the second lost
  records. Differencing across sources is meaningless. A gap is reported as "lost or
  rate-limited", because a router rate-limits its own logging.

## 4. Sensitive data

- This repository is public. Raw captures stay in `captures/`, which git ignores, and so are
  `*.log`, `*.pcap` and `*.pcapng` anywhere in the repository.
- Only sanitized, reviewed fixtures go into `testdata/`, and a test rejects any address or
  domain in them that is not from a reserved range.
- The app keeps everything local: no telemetry, and the UI listens on 127.0.0.1 by default.

## 5. Decisions

- **Stack: Go with a browser UI** (2026-09-24). Go runs the listener, parser and server. The
  web UI is embedded in the binary. The result is one self-contained executable for Windows,
  macOS and Linux: download and run, like the AudioCodes tool.
- **Standard library only.** Each dependency past it is a decision worth making on purpose, and
  the UI stays something `go:embed` can ship in one binary. The checkpoint fails on an
  accidental one.
- **Syslog over TLS, ahead of plain TCP** (2026-09-29). It was asked for so that a CUBE can
  log to this machine across the internet. UDP syslog there is readable by anyone on the path,
  and it can be forged by anyone. Plain TCP would fix neither, so it stays under §6.
  - The design is RFC 5425 on port 6514, from IOS-XE 17.2.1.
  - cube-logger keeps its own certificate authority. A router trusts the authority once, and
    the server certificate can then be remade whenever this machine's addresses change without
    touching the router.
  - `cube-logger cert` prints the router's side of the setup.
  - The whole path is written from Cisco's documentation and has not yet met a real router.
    The unknowns are open questions 8–14 in [log-format.md](log-format.md#open-questions).
- **It can also run on a server** (2026-09-29), so that a CUBE can log somewhere that is
  always on. `deploy/` runs `live` in a container, and the tool itself is unchanged.
  - The web UI still binds loopback and refuses anyone else. The engineer reaches it through
    an SSH tunnel, so it stays one person's tool and not a hosted service.
  - `-allow` is required there. On a public address, an open syslog port takes forged lines
    from anyone who finds it.
- **A session file holds the raw lines**, so a later, better parser re-reads an old session
  rather than being stuck with today's understanding.

## 6. Not yet

Plain TCP syslog, highlight rules and bookmarks, exporting a ladder as SVG or PNG, and signed
Windows and macOS builds.

## 7. Open decisions

1. **Users and OS.** Is this for one engineer on macOS, or for colleagues on Windows too? The
   answer sets how early packaging matters.
2. **TCP syslog framing** depends on what IOS-XE sends. The TLS path reads RFC 5425 octet
   counting and LF-terminated framing both, per message, so plain TCP would need a listener but
   no new framing. Still worth confirming against a real stream (log-format.md question 9).
3. **Storage.** An in-memory ring (the last million lines, say) should be enough. Add SQLite
   only if sessions get too big.
