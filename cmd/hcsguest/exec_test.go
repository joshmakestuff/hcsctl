//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestRunExecTerminatesStdinReaderOnEOF(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	go runExec(server, bufio.NewReader(server), guestproto.Request{Command: "more"})
	if err := guestproto.WriteFrame(client, guestproto.ChanStdin, nil); err != nil {
		t.Fatalf("send stdin EOF: %v", err)
	}

	reader := bufio.NewReader(client)
	for {
		channel, payload, err := guestproto.ReadFrame(reader)
		if err != nil {
			t.Fatalf("read guest frame: %v", err)
		}
		if channel != guestproto.ChanExit {
			continue
		}
		var status guestproto.ExitStatus
		if err := json.Unmarshal(payload, &status); err != nil {
			t.Fatalf("decode exit status: %v", err)
		}
		if status.ExitCode != 0 || status.Error != "" {
			t.Fatalf("exit status = %#v, want successful EOF completion", status)
		}
		return
	}
}
