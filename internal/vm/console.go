//go:build windows

package vm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

// The serial console is the break-glass path. It needs no agent, no network adapter, no lease
// and no firewall rule -- it is a COM port on a named pipe, and the guest writes to it from
// the firmware onwards. When the agent is what is broken, this is what is left.
//
// It shows only what the guest writes while something is attached. HCS does not buffer, so a
// console attached after boot has missed the boot; that is the transport, not a bug here.

// consolePipe is the pipe a VM gets when the caller names none. One per VM, keyed by the id,
// which is already a GUID.
func consolePipe(id string) string { return `\\.\pipe\hcsctl-` + id }

type consoleResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	ID      string `json:"id"`
	Pipe    string `json:"pipe"`
	Bytes   int64  `json:"bytes"`
	Reason  string `json:"reason"`
}

func console(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--store", "--no-input", "--timeout"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}
	timeout := 15 * time.Second
	if s := a.Option("--timeout"); s != "" {
		d, perr := time.ParseDuration(s)
		if perr != nil || d <= 0 {
			return cli.Usage, cli.Usagef("--timeout must be a positive duration, e.g. 10s")
		}
		timeout = d
	}

	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Failed, fmt.Errorf("no vm %s in the store", id)
		}
		return cli.Failed, err
	}
	pipe := record.SerialPipe
	if pipe == "" {
		return cli.Failed, fmt.Errorf("vm %s has no COM port -- it was created before hcsctl "+
			"allocated one by default; recreate it to get a console", id)
	}

	e.Progress("connecting to %s", pipe)
	conn, err := dialConsole(pipe, timeout)
	if err != nil {
		return cli.Failed, err
	}
	defer conn.Close()

	e.Progress("connected; the guest writes here from the firmware onwards, and nothing that " +
		"was written before now was kept. Ctrl-C to detach.")

	// stdin -> guest, unless the caller only wants to watch. A console with no input cannot
	// log in, which is most of the point, so input is the default.
	if !a.Flag("--no-input") {
		go func() { _, _ = io.Copy(conn, os.Stdin) }()
	}

	// guest -> stdout. Under --stream-json the output is framed per line so a consumer can
	// tell console output from hcsctl's own voice; otherwise it is passed through untouched,
	// control characters and all, because that is what a console is.
	var sink io.Writer = os.Stdout
	if e.JSON && e.StreamJSON {
		w := cli.NewStreamWriter(e, "console")
		defer w.Close()
		sink = w
	}
	n, copyErr := io.Copy(sink, conn)

	reason := "the guest closed the console"
	if copyErr != nil {
		reason = copyErr.Error()
	}
	e.Result(consoleResult{OK: true, Command: "vm console", ID: id, Pipe: pipe,
		Bytes: n, Reason: reason}, func() {
		fmt.Fprintf(os.Stderr, "\ndetached from %s: %s\n", id, reason)
	})
	return cli.OK, nil
}

// dialConsole retries, because the pipe is created by the VM worker process and a console
// asked for immediately after vm create can arrive first.
func dialConsole(pipe string, timeout time.Duration) (io.ReadWriteCloser, error) {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := winio.DialPipe(pipe, nil)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s did not accept a connection within %s: %w -- a stopped VM "+
				"has no pipe, and a pipe accepts one client at a time", pipe, timeout, err)
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, winio.ErrTimeout) {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return nil, err
	}
}
