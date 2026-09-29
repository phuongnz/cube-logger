package listen

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxFrame is the largest syslog message accepted on a stream. RFC 5425 asks
// a receiver to take 2048 octets and suggests 8192; the longest line ever seen
// from a CUBE was 453. The limit is generous because a message cut short is a
// corrupted line, and it exists at all because a stream from the internet can
// announce any length it likes.
const maxFrame = 65536

// errFraming is a stream that is not syslog: a length that is not a number, a
// message that starts with neither a digit nor "<", or one longer than
// maxFrame. There is no way to find the next message boundary after one of
// these, so the connection is closed rather than guessed at.
var errFraming = errors.New("not syslog framing")

// frameReader cuts a byte stream into syslog messages, the way RFC 6587
// describes a receiver doing it:
//
//   - Octet counting, "LEN SP MSG", which is what RFC 5425 requires over TLS
//     and what IOS-XE sends. A message starts with a non-zero digit.
//   - Non-transparent framing, where a message ends at LF (or NUL, which some
//     senders use). A message starts with the "<" of its <PRI>.
//
// The choice is made per message, not per connection, which costs nothing and
// copes with a sender that changes its mind.
type frameReader struct {
	r   *bufio.Reader
	max int
}

func newFrameReader(r io.Reader, max int) *frameReader {
	return &frameReader{r: bufio.NewReader(r), max: max}
}

// next returns one message, shaped like a UDP payload: framing removed, a
// trailing NUL or LF removed, and anything else — including the bare CR IOS
// ends a line with — left for wire.Decode.
//
// It returns io.EOF when the stream ends cleanly between messages, and
// io.ErrUnexpectedEOF when it ends inside one; the partial message is dropped,
// because half a SIP header on screen is worse than a counted loss.
func (f *frameReader) next() (string, error) {
	// Separators between messages are skipped. IOS-XE counts the LF that ends
	// a message inside LEN, but a sender that puts it after the counted bytes
	// would otherwise make every second message look malformed.
	var b byte
	for {
		c, err := f.r.ReadByte()
		if err != nil {
			return "", err
		}
		if c != '\n' && c != '\r' && c != 0 {
			b = c
			break
		}
	}

	switch {
	case b >= '1' && b <= '9':
		n, err := f.length(int(b - '0'))
		if err != nil {
			return "", err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(f.r, buf); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		return trimFrame(string(buf)), nil
	case b == '<':
		var sb strings.Builder
		sb.WriteByte(b)
		for {
			c, err := f.r.ReadByte()
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return "", err
			}
			if c == '\n' || c == 0 {
				return sb.String(), nil
			}
			if sb.Len() >= f.max {
				return "", fmt.Errorf("%w: message longer than %d bytes", errFraming, f.max)
			}
			sb.WriteByte(c)
		}
	default:
		return "", fmt.Errorf("%w: a message cannot start with %q", errFraming, b)
	}
}

// length reads the rest of an octet count and the space after it.
func (f *frameReader) length(n int) (int, error) {
	for {
		c, err := f.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if c == ' ' {
			return n, nil
		}
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%w: %q in a message length", errFraming, c)
		}
		n = n*10 + int(c-'0')
		if n > f.max {
			return 0, fmt.Errorf("%w: message longer than %d bytes", errFraming, f.max)
		}
	}
}

// trimFrame removes what octet counting leaves at the end of a message: the
// NUL some senders pad with, and the LF that IOS-XE counts inside LEN. One LF
// only, so the payload looks exactly like the same line sent over UDP.
func trimFrame(s string) string {
	s = strings.TrimRight(s, "\x00")
	return strings.TrimSuffix(s, "\n")
}
