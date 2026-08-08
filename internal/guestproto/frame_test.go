package guestproto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		ch      byte
		payload []byte
	}{
		{"stdout", ChanStdout, []byte("hello")},
		{"stderr", ChanStderr, []byte("boom")},
		// A zero-length frame is EOF on stdin, so it has to survive the round trip as a
		// frame rather than being skipped.
		{"empty stdin means eof", ChanStdin, nil},
		{"binary", ChanStdout, []byte{0, 1, 2, 0xff, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, c.ch, c.payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			ch, got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if ch != c.ch {
				t.Errorf("channel = %d, want %d", ch, c.ch)
			}
			if !bytes.Equal(got, c.payload) {
				t.Errorf("payload = %q, want %q", got, c.payload)
			}
		})
	}
}

// A clean end between frames is io.EOF and nothing else, because the exec loop distinguishes
// "the stream ended" from "the stream broke".
func TestFrameCleanEOF(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

// A truncated frame must NOT read as a clean end. Treating one as EOF is how a caller comes
// to believe a command finished when the connection actually broke mid-stream.
func TestFrameTruncatedIsNotEOF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, ChanStdout, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()

	for _, n := range []int{1, 4, 6, len(full) - 1} {
		_, _, err := ReadFrame(bytes.NewReader(full[:n]))
		if err == nil {
			t.Errorf("%d bytes: no error", n)
			continue
		}
		if errors.Is(err, io.EOF) {
			t.Errorf("%d bytes: reported clean EOF for a truncated frame", n)
		}
	}
}

// The length prefix is an instruction to allocate, so it needs a ceiling. Without one, a
// corrupted header asks for gigabytes.
func TestFrameRejectsOversizeLength(t *testing.T) {
	hdr := []byte{ChanStdout, 0xff, 0xff, 0xff, 0xff}
	_, _, err := ReadFrame(bytes.NewReader(hdr))
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want a limit error", err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, ChanStdout, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("wrote a frame over the limit")
	}
}
