# CUBE log and debug format

Phase 0 notes. What CUBE output actually looks like, written for whoever implements the parser
and the correlator.

**Every value in this document is made up.** Hostnames, IP addresses, phone numbers, Call-IDs,
GUIDs, sequence numbers and timestamps below are invented placeholders that keep the real
structure. Nothing is copied from the capture.

## What this is based on

One capture, taken 2026-09-24 from a production CUBE running IOS-XE 17.12.x: ~885k lines,
34 MB. It is a **captured terminal session**, not a pcap of UDP syslog:

```
cube-lab-01#terminal length 0
cube-lab-01#show log
```

...followed by the whole 100 MB log buffer being paged out, covering about 2h13m of wall clock.
Roughly 42k of the lines are framed log/debug records; the other ~840k are the bare continuation
lines of SIP messages (see [Line frame](#line-frame)).

That makes it a good source for the **text** format and a useless one for **packetisation**.
Everything about UDP datagram boundaries is an [open question](#open-questions).

The only debugs running were `debug ccsip messages` (40,903 records) and a small amount of CUBE
voice-trace output (~500 records, see [Two devices in one file](#two-devices-in-one-file)).
No `debug voip ccapi inout`, no media debugs.

## Line frame

Every log and debug record starts with a frame produced by `service sequence-numbers` and
`service timestamps`:

```
<seq>: <Mon> <DD> <HH:MM:SS.mmm>: <payload>
```

```
4211001: Sep 24 10:11:02.100: //1234567/0A8B2C00000B/SIP/Msg/ccsipDisplayMsg:
4211188: Sep 24 10:11:36.512: %SIP-5-DIALPEER_STATUS: VoIP dial-Peer <1000> is Partially Up
```

- `<seq>` is the IOS sequence number. In this capture it ran 7 digits and increased by one per
  record. It is the loss detector the README promises: a gap means records went missing.
- The timestamp is `Mon DD HH:MM:SS.mmm` — millisecond resolution, **no year, no timezone, no
  `*` prefix**. So:
  - The parser must supply the year itself, and must handle a year rollover in a long capture.
  - This box was NTP-synced (IOS writes a leading `*` when it is not) — the parser must still
    accept `*Sep 24 10:11:02.100` and treat it as "clock unreliable".
  - `service timestamps ... localtime show-timezone` (which the README recommends) would add a
    timezone token. This capture did not have it, so **the parser must treat the timezone as
    optional** and not assume UTC.
- Two payload kinds follow the frame: a **debug** line (starts `//`) or a **log** line (starts
  `%FACILITY-SEVERITY-MNEMONIC:`).

### Continuation lines

Only the **first** line of a multi-line record carries the frame. Every following line is bare,
with no sequence number and no timestamp. In this capture 840k of 885k lines were bare — i.e.
the bare case is the common case, not the exception.

The parser rule is therefore:

> A record starts at a line matching `^\d+: \w{3} +\d+ \d\d:\d\d:\d\d\.\d\d\d: `.
> Every line after it that does not match belongs to it.

Two cautions:

1. **The regex must be anchored and complete.** A loose `^\d+:` also matches SIP body and header
   text, and a loose `^\d{6}:` fails on 7-digit sequence numbers. Require sequence number,
   month, day and time together.
2. **Line endings are mixed.** Most lines end `CRLF`; a minority end `LF` only. Strip an optional
   trailing `\r` from every line before matching or comparing. Lines also carry meaningful
   leading spaces (`Min-SE:  1800`, indented voice-trace fields), so do not trim the left side.

## Debug lines

### Header grammar

```
//<call-id>/<GUID>/<component...>/<function>:
```

Observed forms:

```
//1234567/0A8B2C00000B/SIP/Msg/ccsipDisplayMsg:
//-1/xxxxxxxxxxxx/SIP/Msg/ccsipDisplayMsg:
//1234567/0A8B2C00000B/CUBE_VT/SIP/Msg/ccsipDisplayMsg:
//1234567/0A8B2C00000B/CUBE_VT/SIP/FSM/SPI-State-Change:
//1234567/0A8B2C00000B/CUBE_VT/SIP/API:
//1234567/0A8B2C00000B/CUBE_VT/SIP/MISC/Error:
```

- `<call-id>` — the IOS **call entry ID**, a decimal integer (7 digits here), or the literal
  `-1` when no call leg is associated with the line yet.
- `<GUID>` — 12 hex characters (upper case), or the literal `xxxxxxxxxxxx` when unassigned.
  `-1` and `xxxxxxxxxxxx` always occur together.
- **The component path is variable length.** `SIP/Msg/ccsipDisplayMsg` is three segments;
  `CUBE_VT/SIP/FSM/SPI-State-Change` is four. Parse the header by splitting on `/` and treating
  the first two fields as the IDs and *the rest* as the component path — do not hard-code a
  field count. Some lines end after the component with no trailing function name.
- The header may be the whole payload (the `ccsipDisplayMsg` case, where the SIP message follows
  on the next lines) or be followed by ` ` and free text on the same line.

### SIP messages (`debug ccsip messages`)

A SIP message is a `ccsipDisplayMsg` record: header line, then a direction line, then the
verbatim SIP message.

```
7654321: Sep 24 10:14:20.640: //1234567/0A8B2C00000B/SIP/Msg/ccsipDisplayMsg:
Sent:
INVITE sip:+441234567890@192.0.2.10 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK0A1B2C3D4E
From: <sip:+449876543210@10.0.0.1>;tag=11AA22BB-333
To: <sip:+441234567890@192.0.2.10>
Date: Thu, 24 Sep 2026 10:14:20 GMT
Call-ID: 0A1B2C3D-4E5F6071-8293A4B5-C6D7E8F9@10.0.0.1
Cisco-Guid: 0176892928-0000065536-0000761543-0378877706
User-Agent: Cisco-SIPGateway/IOS-17.12.5a
CSeq: 101 INVITE
Contact: <sip:+449876543210@10.0.0.1:5060>
P-Asserted-Identity: <sip:+449876543210@10.0.0.1>
Content-Type: application/sdp
Content-Length: 247

v=0
o=CiscoSystemsSIP-GW-UserAgent 1111 2222 IN IP4 10.0.0.1
s=SIP Call
c=IN IP4 10.0.0.1
t=0 0
...

<next framed record>
```

- **Direction line.** Two forms, both bare lines immediately after the header:
  - `Sent:` / `Received:` — the plain form, 40,903 of 41,007 messages.
  - `Sent: SIP TLS message from 10.0.0.1:5061 to 192.0.2.10:38208` — the CUBE voice-trace form,
    which also carries the transport and both socket addresses. Parse the first token before
    `:` for direction and treat the remainder as optional detail.
  - No `Sent`/`Received` of any other spelling occurred. Direction is always explicit; the
    parser never has to guess it from the header.
- **Start of message** is unambiguous: the line after the direction line is the SIP request line
  or status line.
- **End of message**: the blank line ends the headers, the body follows, and the record ends at
  the next framed line. After the body come **one or more blank lines** as separator — one in
  38.7k messages, three or five in the rest. Strip trailing blank lines.
- SDP `v=0` bodies were present on INVITE/200-class messages; `Content-Length: 0` messages have
  no body at all.

### Messages are complete, not truncated

Checked mechanically over all 41,007 messages: body length measured as CRLF-terminated bytes
equals `Content-Length` **exactly** in every single message, once the trailing blank separator
lines are discarded. Zero short bodies. There are also no `...`, no "truncated" markers, and the
longest line in the whole file is 453 characters, with nothing beyond 500 — so there is no fixed
line-length cut either.

Two conclusions for the parser:

1. On this path CUBE loses nothing, and **`Content-Length` is a usable end-of-body check** — a
   body shorter than `Content-Length` is a real signal (lost packet) worth surfacing in the UI,
   not normal behaviour to tolerate silently.
2. Whether this survives UDP syslog is untested. See [open questions](#open-questions).

### Messages do not interleave

Also established by the `Content-Length` check: had another record's lines ever been spliced into
a SIP message, the measured bodies would not have matched. 41,007 exact matches means every
`ccsipDisplayMsg` block was emitted atomically, even while several calls were up at once
(the capture has plenty of simultaneous calls — 18.7k INVITEs in 2h13m).

So a naive "bare lines continue the previous framed line" reassembler is correct here. It is
still worth writing the reassembler defensively — it is cheap to detect a bare line that looks
like a new SIP request line inside an unfinished body — because a UDP path may not preserve this.

## Log lines (`%FACILITY-SEVERITY-MNEMONIC`)

```
4213377: Sep 24 10:22:04.418: %VOICE_IEC-3-GW: SIP: Internal Error (): IEC=1.1.180.1.29.0 on callID 1234567
4211188: Sep 24 10:11:36.512: %SIP-5-DIALPEER_STATUS: VoIP dial-Peer <1000> is Partially Up
4211205: Sep 24 10:11:51.733: %SIP-5-TLS_CONNECTION: Connection closed due to SOCKET_REMOTE_CLOSURE for addr=192.0.2.10, port=48219, connId=90210
```

839 such lines in the capture, all single-line, severities 3, 5 and 6 only. Mnemonics seen, by
frequency: `%SIP-5-TLS_CONNECTION`, `%SIP-5-DIALPEER_STATUS`, `%SSH-5-SSH2_SESSION`,
`%SSH-5-SSH2_CLOSE`, `%VOICE_IEC-3-GW`, `%SSH-5-SSH2_USERAUTH`, `%SEC_LOGIN-5-LOGIN_SUCCESS`,
`%SSH-3-NO_MATCH`, `%SSH-5-SSH_CLOSE`, `%SYS-6-LOGOUT`, `%SEC-6-IPACCESSLOGS`.

Two of these matter to the tool:

- **`%VOICE_IEC-3-GW`** (from `voice iec syslog`) carries an Internal Error Code *and the debug
  `callID`* — `on callID 1234567`. It is the clearest machine-readable "this call failed and
  here is why" line, and it is directly attachable to a call. Worth parsing specifically.
- **`%SIP-5-DIALPEER_STATUS`** is trunk state, not call state, but voice engineers want it on the
  timeline.

## Identifiers and correlation

Four identifiers are in play.

| ID | Where | Shape |
| --- | --- | --- |
| Call entry ID (`callID`) | debug header field 1; `%VOICE_IEC` text | decimal int, `-1` if none |
| Debug GUID | debug header field 2 | 12 hex chars, `xxxxxxxxxxxx` if none |
| SIP `Call-ID` | inside the SIP message | `<hex>-<hex>-<hex>-<hex>@<ip>` from IOS; anything from other vendors |
| `Cisco-Guid` header | inside CUBE-originated SIP messages | four zero-padded decimal words |

### What the capture proves

- **The call entry ID identifies one call *leg*, not a call.** Measured across all messages:
  1,602 GUIDs covered exactly 2 distinct call entry IDs and exactly 2 distinct SIP Call-IDs —
  that is the normal CUBE back-to-back shape, inbound leg plus outbound leg. 1,277 GUIDs had a
  single leg (keepalives, and calls whose second leg never formed).
- **The GUID groups the legs of one call — usually.** It is shared by both legs, which is exactly
  what the correlator needs. But it is **not unique over time**: in this 2h13m capture about
  30 GUIDs covered 13–17 distinct call entry IDs, spread over several minutes. The GUID is 12 hex
  characters, which looks like a truncation of the 128-bit Cisco GUID, so collisions between
  calls started close together are plausible. Treat the GUID as a grouping key **scoped by
  time**, not as a primary key, and split a GUID group when its legs do not overlap in time.
- **`Cisco-Guid` links the debug GUID to the SIP layer**, on the 4,097 messages (10%) that carry
  the header. It prints the 128-bit GUID as four zero-padded decimal words, and the 12-character
  debug GUID is built from it: the first 8 characters are the first word in hex, and the last 4
  are the top 16 bits of the third word. With the example message above, debug GUID
  `0A8B2C00000B` against `Cisco-Guid: 0176892928-0000065536-0000761543-0378877706`, the first
  word 176892928 = 0x0A8B2C00 gives `0A8B2C00`, and the third word 761543 = 0x000B9EC7 gives
  `000B`. Useful as a cross-check, not as the main path — 90% of messages lack the header, and a
  non-Cisco peer never sends it.
- **The voice-trace "Cover Buffer" block states the mapping outright.** The CUBE voice-trace
  feature dumps a per-call summary record:

  ```
  1234567: Sep 24 10:22:05.902: //1234567/0A8B2C00000B/
  ------------------ Cover Buffer ---------------
  Search-key       = +449876543210:+441234567890:1234567
    Timestamp      = Sep 24 10:22:04.415
    CallID         = 1234567
    Peer-CallID    = NA
    Correlator     = NA
    Called-Number  = +441234567890
    Calling-Number = +449876543210
    SIP CallID     = 0a1b2c3d-4e5f6071-8293a4-b5c6d7e8@10.0.0.1
    SIP SessionID  =
    GUID           = 0A8B2C00000B
    Tenant         = 300
    Cause-code     = n/a
  -----------------------------------------------
  ```

  This single block ties call entry ID, GUID, SIP Call-ID, both numbers, tenant and cause code
  together, and has a `Peer-CallID` field for the other leg (`NA` in every block here). When
  present it is the cheapest correlation source there is. Only 32 blocks appeared, all from the
  second device — it depends on voice trace being configured, so **the correlator must not
  depend on it**. Note the header line ends with a bare `/` and no component: the header parser
  must tolerate an empty component path.

### Correlation recipe

1. **Leg key** = `(device, call entry ID)`. Every framed debug line with a call entry ID other
   than `-1` belongs to that leg. `%VOICE_IEC-3-GW ... on callID <n>` joins the same leg.
2. **Leg → SIP Call-ID.** The first `ccsipDisplayMsg` on a leg gives the `Call-ID` header. Record
   it both ways; incoming messages on an existing dialog are then attributable by Call-ID alone,
   which is what lets `-1` records be placed.
3. **Call** = legs sharing a GUID, **within a time window**. Open a new call when a GUID reappears
   after its previous legs have all ended. Fall back to Call-ID identity when the GUID is
   `xxxxxxxxxxxx`.
4. **`-1` / `xxxxxxxxxxxx` records (6,021 messages, 15%)** always still contain a SIP message with
   a `Call-ID`, so route them by Call-ID. By method they are 3,460 OPTIONS (keepalives — no call
   at all, and the UI should be able to hide them), 1,972 INVITEs (arriving before a call leg
   exists), then ACK, BYE, CANCEL, NOTIFY, REFER. So an inbound call's *first* INVITE has no call
   entry ID: the correlator must be able to create a call from a Call-ID and adopt a call entry ID
   later.
5. **Cross-checks** when available: `Cisco-Guid` (§ above) and a Cover Buffer block.
6. **Failure modes to expect:** GUID reuse (handled by the time window); a leg whose only records
   are `-1`; call entry IDs reused after a long capture; a Call-ID appearing on both legs when a
   peer reflects it.

Lifecycle boundaries come from the SIP messages themselves — INVITE/200/ACK for setup and
connect, BYE or CANCEL plus the final status code for teardown — plus `%VOICE_IEC-3-GW` for
failures. The CSeq method mix in the capture was INVITE 18,780, PRACK 5,680, BYE 5,347, ACK 4,769,
OPTIONS 4,521, CANCEL 1,650, UPDATE 226, NOTIFY 26, REFER 8. **PRACK and UPDATE are routine here,
and REFER and NOTIFY do occur** — the ladder diagram has to render all of them.

## Two devices in one file

The capture contains records from **two** CUBEs, in two disjoint sequence-number spaces (one
around 5.97M, one around 43.3M), with different IP ranges and different transports (UDP vs TLS).
The second device's records appear as ~30 blocks of about 95 lines each, interleaved between the
first device's records at block granularity, not line granularity.

Only one `show log` was typed, so how the two came to be in one file is not certain from the file
itself — most likely two sessions written to one file. Whatever the cause, the lesson holds:

- **Sequence numbers are per device.** A global "gap = packet loss" check across a file produces
  nonsense: naively differencing every sequence number here reports ~974M missing records, all of
  it from crossing between the two spaces. Track sequence continuity per source.
- A saved file is not guaranteed to be one device, and is not guaranteed to be monotonic in time
  or sequence. The store should key records by source.

## What syslog loses compared with `show logging`

The capture's own `show logging` header answers this, and the answer is blunt. Sanitized, it
looks like this:

```
cube-lab-01#show log
Syslog logging: enabled (0 messages dropped, 412 messages rate-limited, 0 flushes, 2 overruns, xml disabled, ...)
    Console logging: level debugging, 9123456 messages logged, xml disabled,
                     filtering disabled
    Monitor logging: level debugging, 118 messages logged, xml disabled,
                     filtering disabled
    Buffer logging:  level debugging, 9123604 messages logged, xml disabled,
                    filtering disabled
    Exception Logging: size (4096 bytes)
    Count and timestamp logging messages: disabled
    Persistent logging: disabled
    Trap logging: level informational, 104233 message lines logged
        Logging Source-Interface:       VRF Name:
    TLS Profiles:

Log Buffer (100000000 bytes):
```

1. **Severity filtering is the big loss.** Buffer logging was at `debugging` and had taken 18.5M
   messages; **trap logging — the path to a syslog server — was at `informational`** and had sent
   282k lines. Debug output is severity 7, so at `informational` **none of it ever leaves the
   box**. cube-logger would have received only the 839-ish `%...` lines and not one SIP message.
   The README is right that `logging trap debugging` is required; this capture is the evidence.
   The tool should detect this: a session receiving only `%` lines and no debug lines almost
   certainly has `logging trap informational` set, and saying so in the UI saves an engineer an
   afternoon.
2. **Rate limiting drops records silently.** The counters name three separate losses — messages
   dropped, messages rate-limited, overruns — and this box had rate-limited a few hundred
   messages and overrun once. `logging rate-limit` applies to the trap path too, so a busy CUBE
   under debug will lose lines, and the sequence number is the only way to know. This is why
   flagging sequence gaps per source is a v1 feature and not a nicety.
3. **The buffer starts mid-record.** When the 100 MB buffer has wrapped, its first line is the
   tail of whatever record was being overwritten — here a stray hex fragment, then a partial SIP
   message with no header line above it. The file reader must discard leading bare lines until
   the first framed line, rather than attributing them to nothing or crashing.
4. **What `show logging` loses instead:** it has no record of what was *sent* to a syslog server
   or arrived there, and it is a snapshot — anything older than the buffer is gone. Live syslog is
   the only path that sees a record at the moment it happens.

So the two sources are complementary, and the tool needs both, which the plan already assumes.

## Open questions

These need a capture nobody has made yet. None of them blocks the parser, because the text format
above is the same on both paths.

1. **UDP packetisation — the whole of it.** The capture is a terminal session, so it cannot show:
   how CUBE splits a multi-line SIP message across datagrams (one datagram per message, or one
   per line?); whether each datagram repeats the RFC 3164 `<PRI>` header, timestamp and hostname,
   or only the first; and what the PRI/facility value actually is. **This is the one phase-0
   question that is still open**, and it decides how the listener reassembles. Needs
   `tcpdump -w <scenario>.pcap udp port 5514` while a call runs.
2. **Truncation on the UDP path.** Nothing was truncated over the terminal. IOS-XE is reported to
   cap a syslog datagram (~1024 or ~1500 bytes); a SIP INVITE with SDP exceeds that. Whether CUBE
   splits or truncates is unknown, and it is the difference between a usable ladder diagram and a
   broken one. The `Content-Length` check in this document is the test to re-run against a pcap.
3. **Interleaving on the UDP path.** Atomic per message here. Under load, with two calls setting
   up in the same millisecond, datagrams may arrive interleaved or out of order. The reassembler
   should be written so this is detectable.
4. **GUID uniqueness.** Is the 13–17-legs-per-GUID observation a truncation collision, or a real
   CUBE behaviour (call forking, rollover to a second dial-peer)? A lab capture of two calls
   started in the same second would settle it, as would one capture of a known REFER transfer.
5. **Scenario coverage.** This capture is whatever production was doing. Not represented, and all
   wanted per the plan's scenario list: a deliberate busy/404/503 failure, hold and resume, a
   REFER transfer, and a few genuinely idle minutes. There were only 8 REFERs and no
   `debug voip ccapi inout` at all, so call-control lines are undocumented here.
6. **`Peer-CallID` and `Correlator`** were `NA` in every Cover Buffer block. When are they
   populated, and does `Peer-CallID` give a leg-to-leg link better than the GUID?
