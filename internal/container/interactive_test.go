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

type interruptibleProcess struct {
	killed chan struct{}
	once   sync.Once
}

func (p *interruptibleProcess) Pid() int                           { return 42 }
func (p *interruptibleProcess) Kill() error                        { p.once.Do(func() { close(p.killed) }); return nil }
func (p *interruptibleProcess) Wait() error                        { <-p.killed; return nil }
func (p *interruptibleProcess) WaitTimeout(time.Duration) error    { return nil }
func (p *interruptibleProcess) ExitCode() (int, error)             { return 0, nil }
func (p *interruptibleProcess) ResizeConsole(uint16, uint16) error { return nil }
func (p *interruptibleProcess) Stdio() (io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	return nil, nil, nil, nil
}
func (p *interruptibleProcess) CloseStdin() error { return nil }
func (p *interruptibleProcess) Close() error      { return nil }

func TestWaitInteractiveKillsOnlyTheExecProcessOnInterrupt(t *testing.T) {
	process := &interruptibleProcess{killed: make(chan struct{})}
	interrupt := make(chan struct{})
	close(interrupt)
	stdinClosed := false

	timedOut, interrupted, err := waitInteractive(process, cli.Emit{JSON: true}, 0, interrupt, func() {
		stdinClosed = true
	}, process.Pid())
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
