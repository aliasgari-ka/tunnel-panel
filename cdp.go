package main

// A minimal Chrome DevTools Protocol client: one websocket to the browser, calls one at a time
// (events are skipped). Its own tiny websocket client, since Chrome refuses a websocket that
// sends an Origin header (unless started with --remote-allow-origins) and x/net/websocket
// always sends one.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type cdpConn struct {
	c  net.Conn
	r  *bufio.Reader
	id int
}

// cdpDial connects to the browser endpoint of the DevTools port at addr ("127.0.0.1:9277").
func cdpDial(ctx context.Context, addr string) (*cdpConn, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/json/version", nil)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	var v struct {
		WS string `json:"webSocketDebuggerUrl"`
	}
	err = json.NewDecoder(resp.Body).Decode(&v)
	resp.Body.Close()
	if err != nil || v.WS == "" {
		return nil, fmt.Errorf("no browser endpoint at %s", addr)
	}
	u, err := url.Parse(v.WS)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr) // the advertised host may be the far side of a tunnel
	if err != nil {
		return nil, err
	}
	// the upgrade under a deadline: a port that accepts but never answers held this forever
	// (the context's, when it has one sooner; call sets its own deadline later)
	dl := time.Now().Add(15 * time.Second)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = c.SetDeadline(dl)
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		u.RequestURI(), addr, base64.StdEncoding.EncodeToString(key))
	r := bufio.NewReaderSize(c, 64<<10)
	hr, err := http.ReadResponse(r, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	hr.Body.Close()
	if hr.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, fmt.Errorf("browser refused the websocket: %s", hr.Status)
	}
	_ = c.SetDeadline(time.Time{})
	return &cdpConn{c: c, r: r}, nil
}

func (w *cdpConn) Close() { w.c.Close() }

func (w *cdpConn) writeFrame(op byte, p []byte) error {
	h := []byte{0x80 | op, 0x80}
	switch n := len(p); {
	case n < 126:
		h[1] |= byte(n)
	case n < 1<<16:
		h[1] |= 126
		h = binary.BigEndian.AppendUint16(h, uint16(n))
	default:
		h[1] |= 127
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	m := make([]byte, 4)
	_, _ = rand.Read(m)
	h = append(h, m...)
	b := make([]byte, len(p))
	for i := range p {
		b[i] = p[i] ^ m[i%4]
	}
	_, err := w.c.Write(append(h, b...))
	return err
}

// readMsg returns the next whole text message (answers pings, joins fragments).
func (w *cdpConn) readMsg() ([]byte, error) {
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.r, h[:]); err != nil {
			return nil, err
		}
		op, n := h[0]&0x0f, uint64(h[1]&0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > 64<<20 {
			return nil, errors.New("websocket message too big")
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.r, p); err != nil {
			return nil, err
		}
		switch op {
		case 8:
			return nil, errors.New("the browser closed the connection")
		case 9:
			_ = w.writeFrame(10, p)
			continue
		case 10:
			continue
		}
		msg = append(msg, p...)
		if h[0]&0x80 != 0 {
			return msg, nil
		}
	}
}

// call runs one CDP method (in session, "" = the browser) and decodes its result into out.
func (w *cdpConn) call(ctx context.Context, session, method string, params, out any) error {
	w.id++
	id := w.id
	m := map[string]any{"id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	if session != "" {
		m["sessionId"] = session
	}
	b, _ := json.Marshal(m)
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(30 * time.Second)
	}
	_ = w.c.SetDeadline(dl)
	if err := w.writeFrame(1, b); err != nil {
		return err
	}
	for {
		raw, err := w.readMsg()
		if err != nil {
			return err
		}
		var r struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &r) != nil || r.ID != id {
			continue // an event, or the answer to an earlier call that timed out
		}
		if r.Error != nil {
			return fmt.Errorf("%s: %s", method, r.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}
}
