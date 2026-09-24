# cube-logger

A live syslog and debug viewer for Cisco CUBE (Cisco Unified Border Element). Point your
CUBE's syslog at it and watch calls as they happen. Log lines are color-coded and filterable,
each call can be viewed on its own, and each call has a SIP ladder diagram.

It is modelled on the AudioCodes Syslog Viewer, which does the same for AudioCodes gateways and
SBCs.

> **Status: in progress.** The live view, the call list, the ladder diagram, saved files and
> saved sessions work. See [docs/PLAN.md](docs/PLAN.md) for the roadmap.

```
go build ./cmd/cube-logger
./cube-logger live                      # listens on :5514/udp, opens on http://127.0.0.1:8514
./cube-logger live -save today.cubelog  # …and keeps every record, to open again later
./cube-logger open capture.txt          # a saved log or session, in the same views
```

## Features

- Receives syslog and debug output from a CUBE over UDP, live. **Working.**
- Log table with colors by severity and type, text and severity filters, and pause and
  auto-scroll. It stays fast with 100k+ lines. **Working.**
- Call list with time, from, to, duration and result; pick a call to see only its lines.
  **Working.**
- SIP ladder diagram per call, one column for the CUBE and one per peer, and the call's
  messages can be copied or downloaded as text. **Working.**
- Flags syslog output that was lost or rate-limited, using IOS sequence numbers. **Working.**
- Opens saved logs in the same views: a `show logging` capture, a datagram dump, or a file
  written by rsyslog, syslog-ng or Kiwi. `cube-logger open <file>…`, or the **Open…** button in
  the browser. `cube-logger parse <file>` prints the same thing to a terminal. **Working.**
- Saves and reloads a session. A session file holds the **raw lines**, so a later, better parser
  re-reads an old session rather than being stuck with today's understanding. `-save` while
  listening, the **Save** button in the browser, or `cube-logger open -o session.cubelog <file>`
  to convert a big capture into one. **Working.**
- Several CUBEs at once, told apart by source address or hostname, each with its own sequence
  numbering and its own line in the status bar. `-name 198.51.100.9=cube-a` puts a name on an
  address. **Working.**
- Runs locally. Nothing leaves your machine. **Working.**

## Sending CUBE logs to cube-logger

Global configuration:

```
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service sequence-numbers
logging buffered 10000000 debugging
logging host <cube-logger-ip> transport udp port 5514
logging trap debugging
no logging console
voice iec syslog
```

`logging trap debugging` is required. Without it, debug output never reaches the syslog server.
`no logging console` protects the router: sending debug output to the console can make a busy box
unresponsive.

Then turn on the debugs you need, for example:

```
debug ccsip messages
debug voip ccapi inout
```

Debugs use CPU. On a busy production CUBE, keep them short and switch them off afterwards with
`undebug all`.

## Opening saved files

```
cube-logger open capture.txt                 # a "show logging" capture, or any file below
cube-logger open -name 198.51.100.9=cube-a syslog.log
cube-logger open a.log b.log                 # several files, merged in clock order
cube-logger open -o session.cubelog big.log  # convert, instead of serving
```

Recognised without being told which is which: IOS output with no framing (a terminal capture or
`show logging`), a saved datagram dump with `<PRI>` in front, RFC 3164 and RFC 5424 from a
syslog server, rsyslog's and syslog-ng's ISO format, Kiwi's tab-separated file, and a session
file this tool saved (gzipped or not). One file may hold more than one device: each keeps its
own sequence numbering, because differencing across two routers' counters invents losses that
never happened.

See [docs/log-format.md](docs/log-format.md#what-a-file-adds-in-front-of-the-line) for what each
framing looks like and how they are told apart.

## Sensitive data

Debug output contains phone numbers, IP addresses, hostnames and SIP authentication headers.
Keep raw captures in `captures/`. Git ignores that folder, as well as `*.log`, `*.pcap` and
`*.pcapng` files anywhere in the repo. Only sanitized test data belongs in the repository.

## Disclaimer

Not affiliated with or endorsed by Cisco or AudioCodes. Product names are used only to describe
what this tool works with and what inspired it.

## License

[MIT](./LICENSE)
