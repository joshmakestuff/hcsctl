//go:build windows

package container

import (
	stdbytes "bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/cli"
)

func TestForwardStdinCopiesInputAndClosesGuest(t *testing.T) {
	var received stdbytes.Buffer
	closed := make(chan struct{})

	forwardStdin(stdbytes.NewBufferString("hello\n"), &received, func() { close(closed) }, false, nil)
	<-closed

	if got := received.String(); got != "hello\n" {
		t.Fatalf("stdin = %q, want %q", got, "hello\n")
	}
}

func TestCtrlCReaderCancelsWithoutForwardingControlByte(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &ctrlCReader{source: stdbytes.NewReader([]byte{'a', 3, 'b'}), cancel: cancel}
	buffer := make([]byte, 3)

	n, err := reader.Read(buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buffer[:n]); got != "a" {
		t.Fatalf("read = %q, want %q", got, "a")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Ctrl-C did not cancel")
	}

	n, err = reader.Read(buffer)
	if n != 0 || err != io.EOF {
		t.Fatalf("next read = (%d, %v), want (0, EOF)", n, err)
	}
}

// interruptibleProcess fakes the waitProc surface: WaitExit blocks until the
// process is terminated, then reports a clean exit.
type interruptibleProcess struct {
	killed chan struct{}
	once   sync.Once
}

func (p *interruptibleProcess) Terminate(time.Duration) error {
	p.once.Do(func() { close(p.killed) })
	return nil
}

func (p *interruptibleProcess) WaitExit(time.Duration) (string, error) {
	<-p.killed
	return `{"ProcessId":42,"Exited":true,"ExitCode":0}`, nil
}

func TestWaitInteractiveKillsOnlyTheExecProcessOnInterrupt(t *testing.T) {
	process := &interruptibleProcess{killed: make(chan struct{})}
	interrupt := make(chan struct{})
	close(interrupt)
	stdinClosed := false

	_, timedOut, interrupted, err := waitInteractive(process, cli.Emit{JSON: true}, 0, interrupt, func() {
		stdinClosed = true
	}, 42)
	if err != nil {
		t.Fatalf("wait interactive: %v", err)
	}
	if timedOut || !interrupted {
		t.Fatalf("result = (timedOut=%v, interrupted=%v), want (false, true)", timedOut, interrupted)
	}
	if !stdinClosed {
		t.Fatal("interrupt did not close guest stdin")
	}
	select {
	case <-process.killed:
	default:
		t.Fatal("interrupt did not kill the exec process")
	}
}
