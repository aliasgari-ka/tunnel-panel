// Package agentproto is the wire protocol between the panel and tp-agent.
//
// The agent dials the panel over TLS (the panel's certificate is pinned by its
// public-key hash), sends an HTTP upgrade request carrying its token, and the
// connection becomes a yamux session. The panel opens one stream per operation.
// Each stream starts with a JSON Request line; replies are frames:
//
//	[1 byte type][4 bytes big-endian length][payload]
//
// Types: 'o' output chunk, 'x' exit code (decimal text), 'e' error text.
// For "dial", after the 'x' frame the stream becomes a raw byte pipe.
package agentproto

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version     = 1
	ConnectPath = "/agent/connect"
	TokenHeader = "X-TP-Token"
)

type Request struct {
	Op     string `json:"op"`               // exec | write | dial | ping
	Script string `json:"script,omitempty"` // exec
	Path   string `json:"path,omitempty"`   // write
	Mode   uint32 `json:"mode,omitempty"`   // write
	Size   int64  `json:"size,omitempty"`   // write: bytes that follow the request line
	Addr   string `json:"addr,omitempty"`   // dial: host:port as seen from the agent
}

// Hello is sent by the agent right after the session is up.
type Hello struct {
	Version  int    `json:"version"`
	Hostname string `json:"hostname"`
	Arch     string `json:"arch"`
	OS       string `json:"os"`
}

func WriteRequest(w io.Writer, r Request) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func ReadRequest(br *bufio.Reader) (Request, error) {
	var r Request
	line, err := br.ReadBytes('\n')
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(line, &r)
	return r, err
}

func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

const maxFrame = 8 << 20

func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, errors.New("frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf, nil
}

// ReadResult consumes frames until an exit or error frame, passing output to out.
func ReadResult(r io.Reader, out func([]byte)) (int, error) {
	for {
		typ, p, err := ReadFrame(r)
		if err != nil {
			return -1, err
		}
		switch typ {
		case 'o':
			if out != nil {
				out(p)
			}
		case 'x':
			var code int
			fmt.Sscanf(string(p), "%d", &code)
			return code, nil
		case 'e':
			return -1, errors.New(string(p))
		}
	}
}

// FrameWriter turns writes into 'o' frames.
type FrameWriter struct{ W io.Writer }

func (f FrameWriter) Write(p []byte) (int, error) {
	// copy: callers may reuse p
	if err := WriteFrame(f.W, 'o', append([]byte(nil), p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}
