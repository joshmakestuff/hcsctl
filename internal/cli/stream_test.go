package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// The started record is the contract a consumer's pause gate latches on (hcsctl#98): stream
// "exec", event "started", and the pid as a JSON number. A shape change here breaks AspireHcs.
func TestExecStartedRecordShape(t *testing.T) {
	b, err := json.Marshal(execStartedRecord(4242))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"event":"started","pid":4242,"stream":"exec"}`
	if string(b) != want {
		t.Fatalf("record = %s, want %s", b, want)
	}
}

// The framer is exercised through Write/Close; emission goes to stderr, so these tests pin
// the *buffering* semantics -- what constitutes a line -- by inspecting internal state and
// counting emissions via the observable buffer transitions.
func TestStreamWriterFraming(t *testing.T) {
	e := Emit{JSON: true, StreamJSON: true}

	t.Run("partial line is buffered, not emitted", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		w.Write([]byte("no newline yet"))
		if string(w.buf) != "no newline yet" {
			t.Fatalf("partial line not held: %q", w.buf)
		}
	})
	t.Run("newline drains the buffer", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		w.Write([]byte("part"))
		w.Write([]byte("ial\nnext"))
		if string(w.buf) != "next" {
			t.Fatalf("buffer after emit: %q, want the trailing partial only", w.buf)
		}
	})
	t.Run("multiple lines in one write all drain", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		w.Write([]byte("a\nb\nc\n"))
		if len(w.buf) != 0 {
			t.Fatalf("buffer not drained: %q", w.buf)
		}
	})
	t.Run("close flushes the remainder", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		w.Write([]byte("tail without newline"))
		w.Close()
		if len(w.buf) != 0 {
			t.Fatalf("close left %q buffered", w.buf)
		}
	})
	t.Run("oversized line is force-flushed at the cap", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		w.Write([]byte(strings.Repeat("x", streamLineCap+1)))
		if len(w.buf) != 0 {
			t.Fatalf("cap did not flush: %d bytes held", len(w.buf))
		}
	})
	t.Run("multibyte rune split across writes survives", func(t *testing.T) {
		w := NewStreamWriter(e, "stdout")
		snowman := []byte("☃") // 3 bytes
		w.Write(snowman[:1])
		w.Write(snowman[1:])
		if string(w.buf) != "☃" {
			t.Fatalf("split rune mangled in buffer: %q", w.buf)
		}
	})
}
