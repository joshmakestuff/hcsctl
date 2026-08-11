//go:build windows

package guest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestWriteExecRequestClosesStdin(t *testing.T) {
	request := guestproto.Request{Protocol: guestproto.Protocol, Verb: "exec", Command: "read x"}
	var wire bytes.Buffer

	if err := writeExecRequest(&wire, request); err != nil {
		t.Fatalf("write exec request: %v", err)
	}

	reader := bufio.NewReader(&wire)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	var received guestproto.Request
	if err := json.Unmarshal(line, &received); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if received.Protocol != request.Protocol || received.Verb != request.Verb || received.Command != request.Command {
		t.Fatalf("request = %#v, want %#v", received, request)
	}

	channel, payload, err := guestproto.ReadFrame(reader)
	if err != nil {
		t.Fatalf("read stdin EOF frame: %v", err)
	}
	if channel != guestproto.ChanStdin || payload != nil {
		t.Fatalf("frame = (%d, %v), want stdin EOF", channel, payload)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("trailing data error = %v, want EOF", err)
	}
}
