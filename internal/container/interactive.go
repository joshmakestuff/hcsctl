//go:build windows

package container

import (
	"context"
	"io"
	"os"
	"os/signal"

	"golang.org/x/term"
)

const (
	defaultConsoleWidth  = 80
	defaultConsoleHeight = 25
)

type execMode struct {
	interactive bool
	tty         bool
	consoleSize [2]uint
}

// prepareTerminal puts stdin in raw mode for an emulated guest console. Raw mode prevents the
// host terminal from locally echoing input the guest console will echo itself.
func prepareTerminal() (restore func(), consoleSize [2]uint, err error) {
	stdin := int(os.Stdin.Fd())
	stdout := int(os.Stdout.Fd())
	if !term.IsTerminal(stdin) || !term.IsTerminal(stdout) {
		return nil, consoleSize, os.ErrInvalid
	}

	width, height, sizeErr := term.GetSize(stdout)
	if sizeErr != nil || width < 1 || height < 1 {
		width, height = defaultConsoleWidth, defaultConsoleHeight
	}
	state, err := term.MakeRaw(stdin)
	if err != nil {
		return nil, consoleSize, err
	}
	return func() { _ = term.Restore(stdin, state) }, [2]uint{uint(width), uint(height)}, nil
}

// ctrlCReader turns Ctrl-C into cancellation when raw mode has disabled Windows' processed-input
// signal handling. The control byte is never forwarded to the guest.
type ctrlCReader struct {
	source   io.Reader
	cancel   context.CancelFunc
	finished bool
}

func (r *ctrlCReader) Read(p []byte) (int, error) {
	if r.finished {
		return 0, io.EOF
	}
	n, err := r.source.Read(p)
	for i, b := range p[:n] {
		if b == 3 {
			r.finished = true
			r.cancel()
			if i == 0 {
				return 0, io.EOF
			}
			return i, nil
		}
	}
	return n, err
}

// forwardStdin owns EOF propagation: the guest sees EOF whether it came from the terminal, a
// pipe, or Ctrl-C in raw mode. It does not wait for the source reader; a terminal
// read can remain blocked after the guest process exits.
func forwardStdin(source io.Reader, destination io.Writer, closeStdin func(), rawTTY bool, cancel context.CancelFunc) {
	if rawTTY {
		source = &ctrlCReader{source: source, cancel: cancel}
	}
	go func() {
		_, _ = io.Copy(destination, source)
		closeStdin()
	}()
}

func interruptContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}
