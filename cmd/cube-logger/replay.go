package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// replayCmd sends a saved log to a listener the way a CUBE would: one datagram
// per line. That framing is the whole point. A tool that sent a whole SIP
// message in one datagram would exercise nothing the reassembler does, and the
// reassembler is where the hard parts of the live path live.
func replayCmd(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	to := fs.String("to", fmt.Sprintf("127.0.0.1:%d", defaultReplayPort),
		"UDP address to send to")
	rate := fs.Float64("rate", 200, "lines per second (0 means as fast as the socket takes them)")
	repeat := fs.Int("repeat", 1, "send the file this many times (0 means until interrupted)")
	frame := fs.Bool("frame", true,
		"add the wire framing a CUBE adds: <PRI> and the outer, per-line counter")
	facility := fs.Int("facility", 23, "syslog facility for the added <PRI> (23 is local7)")
	seq := fs.Uint64("seq", 1, "first value of the outer, per-line counter")
	drop := fs.Float64("drop", 0, "drop this fraction of datagrams, to exercise gap detection (0..1)")
	shuffle := fs.Int("shuffle", 0,
		"delay every nth datagram behind the next one, to exercise reordering (0 is off)")
	verbose := fs.Bool("v", false, "print a progress line while sending")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("replay needs exactly one file (or \"-\")")
	}
	if *drop < 0 || *drop >= 1 {
		return fmt.Errorf("-drop must be between 0 and 1")
	}

	// Reading the file into memory keeps -repeat honest and keeps the send loop
	// free of disk latency, which would otherwise show up as jitter in a load
	// test. Fixtures are small; this is not the 34 MB capture's tool.
	lines, err := readLines(fs.Arg(0))
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("%s is empty", fs.Arg(0))
	}

	conn, err := net.Dial("udp", *to)
	if err != nil {
		return err
	}
	defer conn.Close()

	r := &replayer{
		conn:     conn,
		frame:    *frame,
		facility: *facility,
		seq:      *seq,
		drop:     *drop,
		shuffle:  *shuffle,
	}
	// A rate of n lines per second is one line every 1/n seconds. Sleeping per
	// line is accurate enough below a few thousand lines a second and keeps the
	// pacing obvious; above that the socket is the limit anyway.
	var gap time.Duration
	if *rate > 0 {
		gap = time.Duration(float64(time.Second) / *rate)
	}

	start := time.Now()
	for n := 0; *repeat == 0 || n < *repeat; n++ {
		for _, line := range lines {
			if err := r.send(line); err != nil {
				return err
			}
			if gap > 0 {
				time.Sleep(gap)
			}
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "pass %d: %d datagram(s) sent, %d dropped\n",
				n+1, r.sent, r.dropped)
		}
	}
	// Give the receiver its idle timeout before the process exits, so the last
	// record is released rather than sitting half-assembled.
	time.Sleep(time.Second)

	fmt.Fprintf(os.Stderr, "replayed %d line(s) as %d datagram(s) to %s in %s",
		r.sent+r.dropped, r.sent, *to, time.Since(start).Round(time.Millisecond))
	if r.dropped > 0 {
		fmt.Fprintf(os.Stderr, ", %d dropped on purpose", r.dropped)
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

// defaultReplayPort mirrors listen.DefaultPort without importing it, so the
// two stay in one place: see routerConfig in live.go.
const defaultReplayPort = 5514

type replayer struct {
	conn     net.Conn
	frame    bool
	facility int
	seq      uint64
	drop     float64
	shuffle  int

	sent    uint64
	dropped uint64
	// held is the datagram -shuffle is keeping back, to be sent after the next
	// one. Real reordering is a later datagram overtaking an earlier one, which
	// is exactly this.
	held    string
	hasHeld bool
	count   uint64
	rnd     uint64
}

func (r *replayer) send(line string) error {
	payload := line
	if r.frame {
		payload = wrap(r.facility, severityOf(line), r.seq, line)
	}
	r.seq++
	r.count++

	if r.drop > 0 && r.next() < r.drop {
		r.dropped++
		return nil
	}
	if r.shuffle > 0 && r.count%uint64(r.shuffle) == 0 && !r.hasHeld {
		r.held, r.hasHeld = payload, true
		return nil
	}
	if err := r.write(payload); err != nil {
		return err
	}
	if r.hasHeld {
		r.hasHeld = false
		return r.write(r.held)
	}
	return nil
}

func (r *replayer) write(payload string) error {
	if _, err := r.conn.Write([]byte(payload)); err != nil {
		return err
	}
	r.sent++
	return nil
}

// next is a tiny deterministic generator: a replay that loses datagram 7 every
// run is reproducible, and reproducing a reassembly bug matters more here than
// statistical quality.
func (r *replayer) next() float64 {
	if r.rnd == 0 {
		r.rnd = 0x2545F4914F6CDD1D
	}
	r.rnd ^= r.rnd << 13
	r.rnd ^= r.rnd >> 7
	r.rnd ^= r.rnd << 17
	return float64(r.rnd%1_000_000) / 1_000_000
}

// wrap builds the datagram a CUBE puts on the wire: "<PRI>" then the outer,
// per-line counter, then the line as it appears in the log. A line that is
// already wire-shaped is passed through, so a saved datagram dump replays
// verbatim.
func wrap(facility, severity int, seq uint64, line string) string {
	if isWireShaped(line) {
		return line
	}
	pri := facility*8 + severity
	return "<" + strconv.Itoa(pri) + ">" + strconv.FormatUint(seq, 10) + ": " + line
}

func isWireShaped(line string) bool {
	if !strings.HasPrefix(line, "<") {
		return false
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 5 {
		return false
	}
	_, err := strconv.Atoi(line[1:end])
	return err == nil
}

// severityOf reads the severity out of an IOS message tag, "%FACILITY-n-MNEMONIC".
// Everything else is debug output, which is severity 7 — and getting that right
// matters, because severity 7 is precisely what "logging trap informational"
// keeps off the wire.
func severityOf(line string) int {
	i := strings.IndexByte(line, '%')
	if i < 0 {
		return 7
	}
	rest := line[i+1:]
	dash := strings.IndexByte(rest, '-')
	if dash < 0 || dash+2 >= len(rest) || rest[dash+2] != '-' {
		return 7
	}
	n, err := strconv.Atoi(rest[dash+1 : dash+2])
	if err != nil || n < 0 || n > 7 {
		return 7
	}
	return n
}

// readLines keeps empty lines. An empty datagram is not noise on this wire: it
// is what separates a SIP message's headers from its body, and dropping it
// would make every replayed INVITE arrive without a body.
func readLines(name string) ([]string, error) {
	f, err := open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		line = strings.TrimRight(line, "\r")
		if line != "" || err == nil {
			lines = append(lines, line)
		}
		if err != nil {
			if err == io.EOF {
				return lines, nil
			}
			return nil, err
		}
	}
}
