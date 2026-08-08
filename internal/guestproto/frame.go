package guestproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Channels carried after an exec request. The host writes only Stdin; the guest writes only
// the rest. Keeping stdout and stderr apart on the wire is what lets --stream-json attribute
// them separately, the same way `container exec` already does.
const (
	ChanStdin  byte = 0
	ChanStdout byte = 1
	ChanStderr byte = 2
	ChanExit   byte = 3
)

// MaxFrame bounds one payload. A length prefix read from a socket is an instruction to
// allocate, so it needs a ceiling even on a trusted link -- a corrupted or truncated frame
// would otherwise ask for gigabytes.
const MaxFrame = 1 << 20

// ExitStatus is the payload of the final ChanExit frame, as JSON.
//
// The guest process's own exit code travels here, inside the document, and never becomes
// hcsctl's exit code. Those two things mean different things, and conflating them makes the
// contract unusable: a caller could not tell "the command ran and returned 1" from "the tool
// failed to run it".
type ExitStatus struct {
	ExitCode int    `json:"exitCode"`
	Error    string `json:"error,omitempty"`
}

// WriteFrame emits one frame: a channel byte, a big-endian uint32 length, then the payload.
func WriteFrame(w io.Writer, ch byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame of %d bytes exceeds the %d byte limit", len(payload), MaxFrame)
	}
	var hdr [5]byte
	hdr[0] = ch
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame. It returns io.EOF only when the stream ended cleanly between
// frames; a partial frame is an error, because silently treating a truncated stream as a
// clean end is how a caller comes to believe a command finished when it did not.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, fmt.Errorf("truncated frame header: %w", err)
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("frame claims %d bytes, over the %d byte limit", n, MaxFrame)
	}
	if n == 0 {
		return hdr[0], nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, fmt.Errorf("truncated frame payload: %w", err)
	}
	return hdr[0], buf, nil
}
