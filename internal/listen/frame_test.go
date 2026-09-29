package listen

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

// octet frames msg the way RFC 5425 does, counting a trailing LF inside LEN as
// IOS-XE was seen to.
func octet(msg string) string {
	msg += "\n"
	return strconv.Itoa(len(msg)) + " " + msg
}

func readAll(t *testing.T, r io.Reader, max int) ([]string, error) {
	t.Helper()
	fr := newFrameReader(r, max)
	var got []string
	for {
		m, err := fr.next()
		if err != nil {
			return got, err
		}
		got = append(got, m)
	}
}

func TestFrames(t *testing.T) {
	const a = "<191>400001: 400002: Sep 24 10:00:00.001 UTC: //1/ABC/SIP/Msg/ccsipDisplayMsg:\r"
	const b = "<191>400002: Sent: \r"
	tests := []struct {
		name   string
		stream string
		want   []string
	}{
		{"octet counted, LF inside LEN", octet(a) + octet(b), []string{a, b}},
		{"octet counted, no LF", "5 <1>x:" + "3 <2>", []string{"<1>x:", "<2>"}},
		{"octet counted, LF after LEN", "6 <1>x:\n\n6 <2>y:\n\n", []string{"<1>x:", "<2>y:"}},
		{"octet counted, NUL padding", "7 <1>x:\x00\x00", []string{"<1>x:"}},
		{"a counted LF in the middle is content", "9 <1>a\nb:\r\n", []string{"<1>a\nb:\r"}},
		{"newline delimited", a + "\n" + b + "\n", []string{a, b}},
		{"NUL delimited", "<1>x\x00<2>y\x00", []string{"<1>x", "<2>y"}},
		{"CRLF delimited leaves the CR for wire.Decode", "<1>x\r\n", []string{"<1>x\r"}},
		{"mixed on one stream", octet(a) + b + "\n" + octet(b), []string{a, b, b}},
		{"empty stream", "", nil},
		{"only separators", "\n\r\n\x00", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAll(t, strings.NewReader(tt.stream), maxFrame)
			if err != io.EOF {
				t.Fatalf("stream ended with %v, want io.EOF", err)
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") || len(got) != len(tt.want) {
				t.Errorf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

// A TLS record boundary lands anywhere, so a frame reader that assumed one
// Read per message would split lines in two.
func TestFramesSurviveOneByteReads(t *testing.T) {
	stream := octet("<191>1: first\r") + octet("<191>2: second\r") + "<191>3: third\r\n"
	got, err := readAll(t, iotest.OneByteReader(strings.NewReader(stream)), maxFrame)
	if err != io.EOF {
		t.Fatalf("stream ended with %v, want io.EOF", err)
	}
	want := []string{"<191>1: first\r", "<191>2: second\r", "<191>3: third\r"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFrameErrors(t *testing.T) {
	tests := []struct {
		name   string
		stream string
		// good is how many messages come out before the error.
		good int
		want error
	}{
		{"a letter where a message starts", "hello\n", 0, errFraming},
		{"a letter inside a length", "1x <1>\n", 0, errFraming},
		{"leading zero", "05 <1>x:", 0, errFraming},
		{"length over the limit", "70000 <1>", 0, errFraming},
		{"newline frame over the limit", "<1>" + strings.Repeat("x", 200) + "\n", 0, errFraming},
		{"stream ends inside a counted message", octet("<1>x") + "20 <1>short", 1, io.ErrUnexpectedEOF},
		{"stream ends inside a length", "12", 0, io.ErrUnexpectedEOF},
		{"stream ends inside a newline message", "<1>no end", 0, io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAll(t, strings.NewReader(tt.stream), 100)
			if !errors.Is(err, tt.want) {
				t.Errorf("error %v, want %v", err, tt.want)
			}
			if len(got) != tt.good {
				t.Errorf("%d message(s) before the error, want %d: %q", len(got), tt.good, got)
			}
		})
	}
}
