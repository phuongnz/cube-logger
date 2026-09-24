// Package ws is a WebSocket server just large enough for this tool.
//
// Go's standard library has no WebSocket, and the project's convention is to
// reach for a dependency only when the standard library will not do. What the
// live view needs is narrow enough that it will: one server pushing text
// frames to a browser on the loopback interface. So this implements the parts
// of RFC 6455 that path uses and refuses the rest, rather than pulling in a
// general-purpose library to ignore nine tenths of it.
//
// Implemented: the opening handshake, text and binary frames out, all frame
// types in, fragmentation on read, ping/pong, and close. Not implemented, and
// rejected rather than mishandled: permessage-deflate (never negotiated, so
// never used), and extensions generally.
//
// A client frame must be masked and a server frame must not be. Both rules are
// enforced, because a proxy that sees them broken may close the connection and
// the failure would look like a bug in this tool.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// magic is the GUID RFC 6455 fixes for the handshake accept value.
const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Close codes this package sends.
const (
	CloseNormal          = 1000
	CloseGoingAway       = 1001
	CloseProtocolError   = 1002
	CloseUnsupported     = 1003
	CloseTooLarge        = 1009
	CloseInternalError   = 1011
	closeNoStatusRcvd    = 1005
	closeAbnormalClosure = 1006
)

// maxFrame caps an incoming frame. The browser only ever sends small control
// messages to this server — a filter, a pause — so anything large is a bug or
// an attack, and refusing it keeps a stray length field from allocating the
// machine's memory.
const maxFrame = 1 << 20

// ErrClosed is returned once the connection has been closed.
var ErrClosed = errors.New("ws: connection closed")

// CloseError is returned by ReadMessage when the peer closed cleanly.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("ws: closed (%d)", e.Code)
	}
	return fmt.Sprintf("ws: closed (%d): %s", e.Code, e.Reason)
}

// IsClose reports whether err is a clean or an abrupt close, which is the
// normal way a browser tab ends a session and is not worth logging as a fault.
func IsClose(err error) bool {
	var ce *CloseError
	if errors.As(err, &ce) {
		return true
	}
	return errors.Is(err, ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF)
}

// Conn is an accepted WebSocket connection.
//
// Writes are serialised by a mutex, so a ping from a keepalive goroutine can
// safely interleave with records from the writer. Reads are expected to happen
// on one goroutine.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader

	wmu    sync.Mutex
	closed bool

	// WriteTimeout bounds a single write. A browser that has stopped reading
	// must not pin a goroutine and a socket buffer forever; the tab is gone and
	// TCP has not noticed yet.
	WriteTimeout time.Duration
}

// Accept performs the opening handshake and takes the connection over.
//
// It answers a bad handshake on the ResponseWriter itself, so a browser
// pointed at the wrong URL gets an HTTP error it can show rather than a
// silence it cannot explain.
func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !tokenHeaderContains(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "this endpoint speaks WebSocket", http.StatusUpgradeRequired)
		return nil, errors.New("ws: not an upgrade request")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported WebSocket version", http.StatusUpgradeRequired)
		return nil, errors.New("ws: unsupported version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("ws: missing key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection cannot be upgraded", http.StatusInternalServerError)
		return nil, errors.New("ws: ResponseWriter is not a Hijacker")
	}
	netConn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack: %w", err)
	}

	// The handshake response is written by hand: the ResponseWriter is gone.
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n")
	b.WriteString("\r\n")
	if _, err := brw.WriteString(b.String()); err != nil {
		netConn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		netConn.Close()
		return nil, err
	}
	// brw.Reader may already hold bytes the client pipelined after the
	// handshake, so it has to be kept rather than replaced.
	return &Conn{conn: netConn, br: brw.Reader, WriteTimeout: 10 * time.Second}, nil
}

// acceptKey is the RFC 6455 handshake answer.
func acceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, magic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// tokenHeaderContains reports whether a comma-separated header lists a token.
// "Connection: keep-alive, Upgrade" is legal and a plain string compare misses it.
func tokenHeaderContains(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Close sends a close frame and shuts the connection down. It is safe to call
// more than once and from any goroutine.
func (c *Conn) Close(code int, reason string) error {
	c.wmu.Lock()
	if c.closed {
		c.wmu.Unlock()
		return nil
	}
	c.closed = true
	payload := make([]byte, 0, 2+len(reason))
	payload = binary.BigEndian.AppendUint16(payload, uint16(code))
	payload = append(payload, reason...)
	// Best effort: the peer may already be gone, and that is not an error
	// worth reporting to a user watching a call.
	c.setWriteDeadline()
	_ = writeFrame(c.conn, opClose, payload)
	c.wmu.Unlock()
	return c.conn.Close()
}

func (c *Conn) setWriteDeadline() {
	if c.WriteTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}
}

// WriteText sends one text frame.
func (c *Conn) WriteText(p []byte) error { return c.write(opText, p) }

// WriteBinary sends one binary frame.
func (c *Conn) WriteBinary(p []byte) error { return c.write(opBinary, p) }

// Ping sends a ping. The browser answers automatically, which is how a dead
// connection is noticed before TCP gets round to it.
func (c *Conn) Ping() error { return c.write(opPing, nil) }

func (c *Conn) write(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return ErrClosed
	}
	c.setWriteDeadline()
	if err := writeFrame(c.conn, op, p); err != nil {
		// A failed write means the connection is unusable; do not leave it half
		// open for the next caller to discover.
		c.closed = true
		c.conn.Close()
		return err
	}
	return nil
}

// SetReadDeadline bounds how long a read may block, so a peer that stops
// answering pings is eventually noticed.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// RemoteAddr is the peer's address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// writeFrame writes one unmasked server frame. A server frame is never masked;
// a client's always is.
func writeFrame(w io.Writer, op byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | op // FIN set: this package never fragments what it sends
	n := len(payload)
	var hn int
	switch {
	case n < 126:
		hdr[1] = byte(n)
		hn = 2
	case n <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
		hn = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
		hn = 10
	}
	if _, err := w.Write(hdr[:hn]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// Message is one complete application message, with fragments joined.
type Message struct {
	// Binary is false for a text message.
	Binary bool
	Data   []byte
}

// ReadMessage reads the next text or binary message, answering pings and
// handling close along the way.
//
// The browser barely talks to this server, so this exists mostly to keep the
// protocol honest: without it, pings are never answered and a close frame is
// never acknowledged.
func (c *Conn) ReadMessage() (Message, error) {
	var (
		data       []byte
		op         byte
		assembling bool
	)
	for {
		f, err := readFrame(c.br)
		if err != nil {
			return Message{}, err
		}
		switch f.op {
		case opPing:
			if err := c.write(opPong, f.payload); err != nil {
				return Message{}, err
			}
		case opPong:
			// Nothing to do: a pong is proof of life, and the read deadline is
			// what consumes that proof.
		case opClose:
			code, reason := closeStatus(f.payload)
			_ = c.Close(CloseNormal, "")
			return Message{}, &CloseError{Code: code, Reason: reason}
		case opText, opBinary:
			if assembling {
				return Message{}, c.protocolError("a new message began before the previous one ended")
			}
			op, assembling = f.op, true
			data = append(data, f.payload...)
			if f.fin {
				return c.finishMessage(op, data)
			}
		case opContinuation:
			if !assembling {
				return Message{}, c.protocolError("continuation frame with nothing to continue")
			}
			data = append(data, f.payload...)
			if len(data) > maxFrame {
				_ = c.Close(CloseTooLarge, "message too large")
				return Message{}, errors.New("ws: message too large")
			}
			if f.fin {
				return c.finishMessage(op, data)
			}
		default:
			return Message{}, c.protocolError("unknown opcode")
		}
	}
}

func (c *Conn) finishMessage(op byte, data []byte) (Message, error) {
	if op == opText && !utf8.Valid(data) {
		// RFC 6455 requires a text message to be valid UTF-8, and requires the
		// receiver to fail the connection when it is not.
		_ = c.Close(CloseUnsupported, "text frame was not valid UTF-8")
		return Message{}, errors.New("ws: text frame was not valid UTF-8")
	}
	return Message{Binary: op == opBinary, Data: data}, nil
}

func (c *Conn) protocolError(reason string) error {
	_ = c.Close(CloseProtocolError, reason)
	return errors.New("ws: protocol error: " + reason)
}

// closeStatus reads the code and reason out of a close frame's payload. An
// empty payload is legal and means "no status".
func closeStatus(p []byte) (int, string) {
	if len(p) < 2 {
		return closeNoStatusRcvd, ""
	}
	return int(binary.BigEndian.Uint16(p)), string(p[2:])
}

type frame struct {
	fin     bool
	op      byte
	payload []byte
}

// readFrame reads one frame from a client. Every client frame must be masked.
func readFrame(br *bufio.Reader) (frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: hdr[0]&0x80 != 0, op: hdr[0] & 0x0F}
	if hdr[0]&0x70 != 0 {
		// Reserved bits set means an extension was negotiated. None ever is,
		// so this is a peer that did not read the handshake response.
		return frame{}, errors.New("ws: reserved bits set, but no extension was negotiated")
	}
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return frame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return frame{}, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	// A control frame carries at most 125 bytes and is never fragmented.
	if f.op >= opClose && (n > 125 || !f.fin) {
		return frame{}, errors.New("ws: malformed control frame")
	}
	if n > maxFrame {
		return frame{}, fmt.Errorf("ws: frame of %d bytes exceeds the %d byte limit", n, maxFrame)
	}
	if !masked {
		// Required by the RFC, and not pedantry: an unmasked client frame is
		// how a cache-poisoning proxy attack starts.
		return frame{}, errors.New("ws: client frame was not masked")
	}
	var mask [4]byte
	if _, err := io.ReadFull(br, mask[:]); err != nil {
		return frame{}, err
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(br, f.payload); err != nil {
		return frame{}, err
	}
	for i := range f.payload {
		f.payload[i] ^= mask[i%4]
	}
	return f, nil
}
