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

A second capture, the same day, fills that in: an Embedded Packet Capture taken on the CUBE of
1,288 syslog datagrams carrying 66 records of one TLS SIP call. Everything about the live path —
the frame, the counters, what one datagram holds — comes from that one and is in
[The UDP path](#the-udp-path).

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

5. **No syslog destination is configured on this box.** The `Logging Source-Interface:` /
   `VRF Name:` line is empty and no `Logging to <host>` entries follow it. Nothing has ever been
   sent over UDP from this router, so the absence of evidence about the UDP path below is not a
   gap in the analysis — there is no data to analyse, and there will not be until someone
   configures a destination and captures the result.

So the two sources are complementary, and the tool needs both, which the plan already assumes.

## The UDP path

Settled by a second capture, 2026-09-24: an Embedded Packet Capture on the CUBE itself, of
1,288 syslog datagrams carrying 66 records of one TLS SIP call. Every value below is invented;
the counts are measurements.

**One datagram per line.** Not per message. The 66 records arrived as 1,288 datagrams, about 19
lines each, and not one datagram contained a newline. This is the single most important fact
about the live path: what the listener receives is never a SIP message, it is one line of one,
and the reassembler is not optional.

**The frame is not RFC 3164.** Not one datagram had the `MMM DD HH:MM:SS HOSTNAME TAG:` form.
All 1,288 had this instead:

```
<191>400001: 7200001: Sep 24 12:00:00.123 UTC: //-1/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:
<191>400002: Received:
<191>400003: INVITE sip:+449876543210@192.0.2.10:5060 SIP/2.0
<191>400004: Via: SIP/2.0/TLS 192.0.2.20:5061;branch=z9hG4bK+1234abcd
...
<191>400020:
```

- `<191>` is local7 (facility 23) at severity 7, debug. 1,282 of the 1,288 were 191; the rest
  were 190, 189 and 187 — informational, notice and error `%` lines. Severity is carried on
  every line, and a continuation line inherits the severity of the record it belongs to.
- **There is no hostname and no syslog-layer timestamp.** A record's time comes from its head
  line and nothing else; a continuation line's only clock is the moment it arrives.
- Device identity therefore comes from the **datagram's source address** and nothing in the
  payload. § Two devices in one file says sequence continuity must be tracked per device; on
  the live path "per device" means per source address.

**Two counters, and they count different things.** This is better than the plan assumed:

| | where | increments | a gap means |
|---|---|---|---|
| outer, after `<PRI>` | every datagram | +1 per **line** | lines lost, exactly countable |
| inner, on record heads only | record heads | +1 per **record** | whole records lost |

In the capture the outer counter ran unbroken across all 1,288 datagrams, and the inner across
all 66 records — no loss, no reordering. Because the outer counter covers every line, a receiver
can say not just that something was lost but *how much and where inside which message*, which is
what makes a half-received SIP message safe to show as incomplete rather than wrong.

**No fragmentation and no truncation, and the reason matters.** No IP fragment appeared, and the
largest payload was 214 bytes against a longest-line-ever of 453 bytes in the terminal capture.
The earlier worry — that a quarter of SIP messages exceed 1024 bytes and 7.6% exceed 1472 — is
void, because a message never travels as a unit. Lines do, and lines are small. Nothing here
approaches an MTU or an IOS datagram cap.

**Line endings.** 1,162 of 1,288 payloads ended with a bare CR, 126 with nothing at all. No LF
anywhere, and no CRLF. Strip one optional trailing CR; never require it.

**What reassembly has to do.**

1. Sort by the outer counter, not by arrival. UDP may reorder even though this capture did not.
2. A record starts at a head line (`<seq>: <seq>: <timestamp>: ` followed by `//` or `%`) and
   runs until the next head line. Between two heads in this capture, every line belonged to the
   first record: records were emitted atomically, so no interleaving was observed — at one call
   and low load. Under concurrency it is unproven, which is question 1 below. Attributing lines
   by the head that precedes them in *sequence* order rather than in arrival order is correct
   either way.
3. An empty line is a real datagram (65 of them here), and it is what separates SIP headers from
   the body. Do not discard empty payloads.
4. A message is complete when the bytes after its blank line match its `Content-Length`. That is
   also the check that detects a message with lines missing in the middle.

## What a file adds in front of the line

A CUBE line reaches a file by one of several routes, and each route puts its own framing in
front of the line the device emitted. The tool peels that off and hands `internal/parse` the
same IOS line either way, so the views do not have to know where a record came from.

| What wrote it | What the line looks like |
| --- | --- |
| A terminal capture of `show logging` | `400020: Sep 24 10:00:01.123: %SIP-5-…` |
| A saved datagram dump | `<191>400020: Sep 24 10:00:01.123: %SIP-5-…` |
| A syslog server writing RFC 3164 | `Sep 24 10:00:01 cube-a 400020: Sep 24 …` |
| rsyslog's file format, syslog-ng's ISO template | `2026-09-24T10:00:01+02:00 cube-a 400020: …` |
| RFC 5424 | `<191>1 2026-09-24T10:00:01Z cube-a - - - 400020: …` |
| Kiwi's tab-separated file | `2026-09-24⇥10:00:01⇥Local7.Debug⇥cube-a⇥400020: …` |

Three things make this safe to do by shape alone, and all three matter:

- **The IOS frame wins.** A line that already starts with `<seq>: <Mon DD HH:MM:SS.mmm>: ` had
  nothing put in front of it, and nothing is taken off.
- **A peel has to leave something plausible behind.** A foreign framing is only recognised when
  what remains is itself an IOS frame, a `%FACILITY-n-MNEMONIC` log line or a `//call/guid/…`
  debug header. A SIP body can contain any shape at all, including something that reads like a
  timestamp and a hostname.
- **A file is locked to one format.** Once a file has shown which framing it uses, only that one
  is tried, so a capture of a terminal session is never "corrected". The one exception is a
  syslog priority — `<191>` — which an IOS line never starts with, so that is peeled wherever it
  appears and a concatenation of a dump and a paste still reads.

The framing also carries two things the IOS line does not repeat: the **device** (a hostname or
an address, where a terminal capture has only the prompt to go on) and the **severity**, which
is otherwise only knowable for `%`-tagged log lines.

### The `show logging` preamble

`show logging` prints a page of configuration before the buffer, ending at `Log Buffer (N
bytes):`. It is not log content and does not belong in the table, but it is worth keeping: it is
the first thing to read when the debug output someone expected is not in the file — it says the
trap level, what was rate-limited and what was dropped. It is recognised only in the preamble:
before the first record, or straight after this device's own prompt. The prompt line itself
(`cube-a#show logging`) is the only place a terminal capture names the router.

### A device with no timestamps

`no service timestamps` leaves a line the parser cannot frame at all. When a syslog server
timestamped it on arrival, the frame is rebuilt from the server's clock — but only for a line
that would start a record, because giving every line its own frame would turn one SIP message
into nineteen records. The times are then the server's, not the router's, and the tool says so.

## Open questions

Questions 1-3 of the first draft — packetisation, truncation and the frame layout — are closed
by § The UDP path. What is left needs captures nobody has made yet, and none of it blocks the
parser.

1. **Interleaving under concurrent calls.** In the UDP capture every line between two record
   heads belonged to the first record: records were emitted atomically. That was one call at low
   load. Two calls setting up in the same millisecond may interleave at line granularity, and the
   reassembler has to be written so that it would notice. Needs a capture of overlapping calls.
2. **Which gaps are the rate limiter and which are the network.** A gap in the outer counter has
   two causes: the router dropping a message before transmitting it (rate limiting and overruns
   — this box has done both, § What syslog loses) and loss in transit. Whether a rate-limited
   message consumes a sequence number before it is dropped is not known, and it decides
   everything: if it does, a gap appears at the sender too and the two causes are separable by
   comparing a sender-side and a receiver-side capture; if it does not, a rate-limited message is
   invisible and no gap analysis can ever see it. The UDP capture had no drops, so it could not
   say. **Until this is settled the UI says "lost or rate-limited", not "lost"** — telling an
   engineer they have a network problem while their router throttles its own logging sends them
   looking in the wrong place.
3. **GUID uniqueness.** Is the 13-17-legs-per-GUID observation a truncation collision, or real
   CUBE behaviour (call forking, rollover to a second dial-peer)? A lab capture of two calls
   started in the same second would settle it, as would one capture of a known REFER transfer.
4. **Scenario coverage.** The terminal capture is whatever production was doing and the UDP
   capture is one call. Not represented, and all wanted per the plan's scenario list: a deliberate
   busy/404/503 failure, hold and resume, a REFER transfer, and a few genuinely idle minutes.
   There were only 8 REFERs and no `debug voip ccapi inout` at all, so call-control lines are
   undocumented here.
5. **`Peer-CallID` and `Correlator`** were `NA` in every Cover Buffer block. When are they
   populated, and does `Peer-CallID` give a leg-to-leg link better than the GUID?
6. **The second device on the live path.** The terminal capture held two CUBEs in disjoint
   sequence spaces; the UDP capture had one source address. That the live path separates devices
   by source address is inference from a one-device capture, not an observation of two.
7. **The third-party file formats are written from the specifications, not from files.** Nobody
   has yet pointed a CUBE at rsyslog, syslog-ng or Kiwi and kept what came out. The framings in
   § What a file adds in front of the line are what those servers document themselves as
   writing, and the fixtures under `testdata/files/` were written by hand to match. A real file
   from each would either confirm them or show a template option nobody thought of; the reader
   is built so that an unrecognised prefix costs a line, not a file.

### How the UDP capture was taken

Kept because the next one will be taken the same way. The collector cannot sit in the CUBE's
network, so it was an Embedded Packet Capture on the router, exported off the box. Three settings
have to be in place first or the capture is worthless: a routable
`logging host <collector> transport udp port 5514`, `logging trap debugging` (at the
`informational` level this box ships with, the capture contains no debug line at all, § What
syslog loses point 1), and `service sequence-numbers`. The collector needs nothing listening on
it — UDP is fire-and-forget — but it must be routable and ARP-resolvable, or the datagrams never
reach the wire.

```
ip access-list extended CAP-SYSLOG
 permit udp any host <collector> eq 5514
!
monitor capture CAP access-list CAP-SYSLOG interface <interface> out
```

One caution learned the hard way: the capture that answered these questions was taken without the
access list in force, so it also contains the call's RTP — real audio — along with unrelated TCP
and ICMP. Raw captures are gitignored, but the narrower the capture the less there is to be
careful with.
