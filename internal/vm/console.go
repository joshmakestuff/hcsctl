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
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/spf13/cobra"
)

// The serial console needs no agent, no network adapter, no lease and no firewall rule: it is
// a COM port on a named pipe, and the guest writes to it from the firmware onwards.
//
// It shows only what the guest writes while something is attached. HCS does not buffer, so a
// console attached after boot has missed the boot.

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

func consoleCmd(e cli.Emit) *cobra.Command {
	var id, timeoutStr, storeDir string
	var noInput bool
	cmd := &cobra.Command{
		Use:   "console --id <guid> [--no-input] [--timeout 15s] [--store <dir>]",
		Short: "attach to the VM's serial console over its COM1 named pipe",
		Long: `Attach to the VM's serial console over its COM1 named pipe. This is the
break-glass path: no agent, no network adapter, no lease, no firewall rule --
it works when the agent is what is broken. Input is on by default, so a Linux
guest with a getty on ttyS0 gives a login prompt; --no-input only watches.
Nothing is buffered, so a console attached after boot has missed the boot.
Every VM gets a COM port; --serial-pipe at create time overrides the name.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			timeout := 15 * time.Second
			if timeoutStr != "" {
				d, perr := time.ParseDuration(timeoutStr)
				if perr != nil || d <= 0 {
					return cli.Usagef("--timeout must be a positive duration, e.g. 10s")
				}
				timeout = d
			}
			return console(vmID, noInput, timeout, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cmd.Flags().BoolVar(&noInput, "no-input", false, "watch only; do not forward stdin to the guest")
	cli.StringOnce(cmd.Flags(), &timeoutStr, "timeout", "how long to wait for the pipe to accept a connection (default 15s)")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func console(id string, noInput bool, timeout time.Duration, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no vm %s in the store", id)
		}
		return err
	}
	pipe := record.SerialPipe
	if pipe == "" {
		return fmt.Errorf("vm %s has no COM port -- it was created before hcsctl "+
			"allocated one by default; recreate it to get a console", id)
	}

	e.Progress("connecting to %s", pipe)
	conn, err := dialConsole(pipe, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	e.Progress("connected; the guest writes here from the firmware onwards, and nothing that " +
		"was written before now was kept. Ctrl-C to detach.")

	// stdin -> guest unless the caller only wants to watch. Input is the default.
	if !noInput {
		go func() { _, _ = io.Copy(conn, os.Stdin) }()
	}

	// The sink depends on the output mode; see consoleSink.
	sink, closeSink := consoleSink(e)
	defer closeSink()
	n, copyErr := io.Copy(sink, conn)

	reason := "the guest closed the console"
	if copyErr != nil {
		reason = copyErr.Error()
	}
	e.Result(consoleResult{OK: true, Command: "vm console", ID: id, Pipe: pipe,
		Bytes: n, Reason: reason}, func() {
		fmt.Fprintf(os.Stderr, "\ndetached from %s: %s\n", id, reason)
	})
	return nil
}

// consoleSink picks where the guest's serial bytes go, per output mode. Default: stdout,
// untouched, control characters and all. Under --json alone, stdout carries only the single
// final result document, so the bytes go to stderr -- the same rule guest exec applies to
// guest output. Under --json --stream-json they are framed per line as {"stream":"console"}.
// The closer flushes the stream writer, if there is one.
func consoleSink(e cli.Emit) (io.Writer, func()) {
	switch {
	case e.JSON && e.StreamJSON:
		w := cli.NewStreamWriter(e, "console")
		return w, func() { _ = w.Close() }
	case e.JSON:
		return os.Stderr, func() {}
	default:
		return os.Stdout, func() {}
	}
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
