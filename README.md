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
./cube-logger live -tls :6514           # …and receives syslog over TLS too (see below)
./cube-logger open capture.txt          # a saved log or session, in the same views
```

## Features

- Receives syslog and debug output from a CUBE over UDP, live. **Working.**
- Receives it over TLS too (RFC 5425, IOS-XE 17.2.1 or later), for a CUBE that reaches this
  machine across a network you do not control. `cube-logger cert` makes the certificates and
  prints the router configuration. **Working, but not yet tried against a real router.**
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

## Sending CUBE logs over TLS

UDP syslog is plain text. Anyone on the path can read the phone numbers, addresses and SIP
headers in it, and anyone can send datagrams that look like they came from your router. That is
fine on a lab network or over a VPN. When the CUBE reaches this machine across the internet, use
TLS instead. It needs IOS-XE 17.2.1 or later.

> Not yet tried against a real router. The router side below follows Cisco's documentation, and
> the tool is tested against a client that behaves the way that documentation describes. What is
> still unknown is listed in [the open questions](docs/log-format.md#open-questions).

**1. Make the certificates** on the machine that runs cube-logger, naming the address the router
will connect to:

```
cube-logger cert -tls-name 203.0.113.5
```

The first run makes a certificate authority and a server certificate issued by it, and keeps them
in `cube-logger/tls` under your configuration directory: `%AppData%` on Windows,
`~/Library/Application Support` on macOS, `~/.config` on Linux. `-tls-dir` puts them somewhere
else. It prints the authority's fingerprints, the certificate to paste, and the router
configuration below with your address and port filled in. Running it again prints the same thing
and makes nothing new.

**2. Make the router trust the authority.** Once per router, in configuration mode:

```
crypto pki trustpoint CUBE-LOGGER
 enrollment terminal
 revocation-check none
 chain-validation stop
crypto pki authenticate CUBE-LOGGER
```

Paste the certificate that `cube-logger cert` printed, then an empty line. Answer yes only if the
fingerprints the router shows are the ones `cube-logger cert` printed.

**3. Send logging over TLS:**

```
logging tls-profile CUBE-LOGGER
 tls-version TLSv1.2
 ciphersuite ecdhe-rsa-aes-gcm-sha2
logging host 203.0.113.5 transport tls port 6514 profile CUBE-LOGGER
```

Keep the rest of the configuration from the section above: `logging trap debugging`,
`service sequence-numbers` and the timestamps. Remove the UDP `logging host`. With both, the router
sends every line twice, and one copy in the clear.

The cipher suite is not a preference. It is the one IOS-XE keyword that matches what cube-logger
serves over TLS 1.2 with its RSA certificate.

**4. Listen:**

```
cube-logger live -tls :6514 -listen off -allow 198.51.100.7
```

`-allow` is the router's address as it arrives at this machine. A connection from anywhere else is
closed before any TLS is spoken. `-listen off` turns UDP off. Leave it out to receive both.

The router opens a TCP connection to port 6514, so let that through this machine's firewall.
Behind NAT, forward the port from the public address to this machine, and name the public address
with `-tls-name`. The certificate always names this machine's own addresses. It has to name the
one the router connects to as well. Whether IOS-XE checks this is one of the open questions, and
naming it costs nothing.

**When it does not connect**, the terminal says why. Each failed handshake is printed with what the
router offered and the line to change on the router: a missing `transport tls`, a cipher suite
the two sides do not share, or a certificate the router does not trust. The same failure from the
same address is printed once every five minutes, so a retrying router or a port scanner does not
bury the screen. The count at exit includes every one.

**Other flags** for `live`:

| Flag | What it does |
| --- | --- |
| `-tls-name` | Another address or host name for the certificate (repeatable). The first one is its common name. |
| `-tls-dir` | Where the certificates are kept. |
| `-tls-cert`, `-tls-key` | Serve your own certificate, issued by your own CA, instead of the one cube-logger makes. |
| `-tls-client-ca` | Accept only routers that present a certificate issued by this CA. On the router, that is `client-id-trustpoint` in the tls-profile. |

**About the certificates.** A router's trust rests on `ca-key.pem`, so it never leaves this
machine. cube-logger never replaces the authority on its own. If `ca.pem` is unreadable, has
expired or does not match its key, cube-logger stops and says so rather than making a new one,
because every router would have to import it. If `ca.pem` is gone, a new authority is made, and
the startup banner says no router trusts it yet. The server certificate is different. It is remade whenever this machine's addresses or the `-tls-name` list
change, and 30 days before it expires. Routers need nothing for that, because they trust the
authority.

**Try it without a router:**

```
cube-logger live -tls :6514
cube-logger replay -tls testdata/basic_call.txt
```

`replay -tls` checks the certificate the way a router does, against the authority and for the
address it dials. It offers only TLS 1.2 and the cipher suites the router configuration names.

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
