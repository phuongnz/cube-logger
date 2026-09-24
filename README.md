# cube-logger

A live syslog and debug viewer for Cisco CUBE (Cisco Unified Border Element). Point your
CUBE's syslog at it and watch calls as they happen. Log lines are color-coded and filterable,
each call can be viewed on its own, and each call has a SIP ladder diagram.

It is modelled on the AudioCodes Syslog Viewer, which does the same for AudioCodes gateways and
SBCs.

> **Status: planning.** Nothing works yet. See [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Planned features

- Receives syslog and debug output from one or more CUBEs over UDP, live.
- Log table with colors by severity and type, text and severity filters, and pause and
  auto-scroll. It stays fast with 100k+ lines.
- Call list: pick a call to see only its lines.
- SIP ladder diagram per call.
- Flags lost syslog packets, using IOS sequence numbers.
- Opens saved logs, including `show logging` output.
- Runs locally. Nothing leaves your machine.

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

## Sensitive data

Debug output contains phone numbers, IP addresses, hostnames and SIP authentication headers.
Keep raw captures in `captures/`. Git ignores that folder, as well as `*.log`, `*.pcap` and
`*.pcapng` files anywhere in the repo. Only sanitized test data belongs in the repository.

## Disclaimer

Not affiliated with or endorsed by Cisco or AudioCodes. Product names are used only to describe
what this tool works with and what inspired it.

## License

[MIT](./LICENSE)
