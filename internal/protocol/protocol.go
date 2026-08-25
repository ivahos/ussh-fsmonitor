// Package protocol defines the newline-delimited JSON the helper writes
// to stdout. Every line is one object; the first is the handshake.
//
//	{"v":1,"caps":["fsevents"],"root":"/home/ivar","version":"1.0.0"}
//	{"t":"mod","p":"src/main.go"}        path changed or appeared (file or dir)
//	{"t":"del","p":"build"}              path disappeared
//	{"t":"overflow"}                     events were lost — do a full resync
//	{"t":"ping"}                         liveness, every PingInterval
//
// Paths are relative to the root, slash-separated, never absolute, never
// containing "..". The consumer re-enumerates the parent container of each
// path, so the distinction between "created" and "modified" is deliberately
// not carried — it would only invite the client to trust it.
package protocol

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// PingInterval is how often a ping line is emitted when nothing else is.
const PingInterval = 30 * time.Second

// Version is the protocol generation. Mirrors version.Protocol.
const Version = 1

type Handshake struct {
	V       int      `json:"v"`
	Caps    []string `json:"caps"`
	Root    string   `json:"root"`
	Version string   `json:"version"`
}

type Event struct {
	T string `json:"t"`
	P string `json:"p,omitempty"`
}

const (
	Modified = "mod"
	Deleted  = "del"
	Overflow = "overflow"
	Ping     = "ping"
)

// Writer serialises lines to an io.Writer, one JSON object per line,
// safe for use from several goroutines.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, enc: json.NewEncoder(w)}
}

func (w *Writer) Write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(v) // Encode appends the newline
}
