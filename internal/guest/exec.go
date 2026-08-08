//go:build windows

package guest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

type execResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	VMID    string `json:"vmId"`
	Ran     string `json:"ran"`
	// ExitCode is the GUEST process's exit code. It is reported here and never as hcsctl's
	// own exit code: "the command ran and returned 1" and "the tool could not run it" are
	// different outcomes and a caller has to be able to tell them apart.
	ExitCode  int    `json:"exitCode"`
	TimedOut  bool   `json:"timedOut"`
	Detail    string `json:"detail,omitempty"`
	ElapsedMS int64  `json:"elapsedMs"`
}

func execVerb(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--vmid", "--cmd", "--cwd", "--env", "--timeout"); err != nil {
		return cli.Usage, err
	}
	raw, err := a.Require("--vmid")
	if err != nil {
		return cli.Usage, err
	}
	vmid, err := guid.FromString(raw)
	if err != nil {
		return cli.Usage, cli.Usagef("--vmid is not a GUID: %v", err)
	}
	cmdline, err := a.Require("--cmd")
	if err != nil {
		return cli.Usage, err
	}

	var timeout time.Duration
	if s := a.Option("--timeout"); s != "" {
		d, perr := time.ParseDuration(s)
		if perr != nil || d <= 0 {
			return cli.Usage, cli.Usagef("--timeout must be a positive duration, e.g. 30s")
		}
		timeout = d
	}

	req := guestproto.Request{
		Protocol:       guestproto.Protocol,
		Verb:           "exec",
		Command:        cmdline,
		Cwd:            a.Option("--cwd"),
		Env:            a.Options("--env"),
		TimeoutSeconds: int(timeout.Seconds()),
	}

	// The dial has its own budget. Reaching the guest and running a command are separate
	// waits, and a --timeout of 5s must not mean "give up dialling after 5s" when a dial
	// against a guest whose agent is absent takes 30s regardless (#37).
	svc, err := serviceFor(vmid, 35*time.Second)
	if err != nil {
		return cli.Failed, err
	}

	start := time.Now()
	res, err := runRemote(vmid, svc, req, e)
	res.VMID = vmid.String()
	res.Ran = cmdline
	res.Command = "guest exec"
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		return cli.Failed, err
	}

	e.Result(res, func() {
		// Output already went to stdout and stderr as it arrived; only the verdict is left.
		if res.TimedOut {
			fmt.Fprintf(os.Stderr, "timed out after %s\n", timeout)
		}
	})
	// Exit 0 means "the command ran". Whether it succeeded is exitCode in the document.
	return cli.OK, nil
}

func runRemote(vmid, svc guid.GUID, req guestproto.Request, e cli.Emit) (execResult, error) {
	res := execResult{ExitCode: -1}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	conn, err := winio.Dial(ctx, &winio.HvsockAddr{VMID: vmid, ServiceID: svc})
	if err != nil {
		return res, fmt.Errorf("dial guest: %w", err)
	}
	defer conn.Close()

	body, _ := json.Marshal(req)
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return res, err
	}

	// No deadline once the command is running: a long one would otherwise be cut off, and a
	// cut-off stream is indistinguishable from a command that finished.
	_ = conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// The agent answers a verb it cannot serve with a JSON failure document, not with frames
	// -- an older agent that has never heard of exec is the ordinary case. A frame header
	// begins with a channel byte of 0 to 3, so a leading '{' can only be a document, and
	// discriminating on it here turns "protocol desync, frame claims 577727266 bytes" into
	// the refusal the agent actually sent.
	if first, perr := br.Peek(1); perr == nil && first[0] == '{' {
		line, _ := br.ReadBytes('\n')
		var f guestproto.Failure
		if json.Unmarshal(line, &f) == nil && f.Error != "" {
			return res, fmt.Errorf("agent refused: %s", f.Error)
		}
		return res, fmt.Errorf("agent sent a document instead of frames: %s", bytes.TrimSpace(line))
	}

	outSink, errSink, closeSinks := sinks(e)
	defer closeSinks()

	for {
		ch, payload, ferr := guestproto.ReadFrame(br)
		if ferr != nil {
			if errors.Is(ferr, io.EOF) {
				// The agent closed without an exit frame. That is not a clean end: report it
				// rather than letting exitCode -1 pass for a result.
				return res, fmt.Errorf("agent closed before reporting an exit status")
			}
			// A failure document may arrive instead of frames, if the verb was refused.
			return res, ferr
		}
		switch ch {
		case guestproto.ChanStdout:
			_, _ = outSink.Write(payload)
		case guestproto.ChanStderr:
			_, _ = errSink.Write(payload)
		case guestproto.ChanExit:
			var st guestproto.ExitStatus
			if uerr := json.Unmarshal(payload, &st); uerr != nil {
				return res, fmt.Errorf("exit frame is not a status: %w", uerr)
			}
			res.OK = true
			res.ExitCode = st.ExitCode
			res.Detail = st.Error
			res.TimedOut = st.Error == "timed out"
			return res, nil
		}
	}
}

// sinks mirrors the container path: guest stdout and stderr go to the host's own stdout and
// stderr, and under --stream-json they are additionally framed and attributed individually.
func sinks(e cli.Emit) (io.Writer, io.Writer, func()) {
	if !e.JSON {
		return os.Stdout, os.Stderr, func() {}
	}
	if !e.StreamJSON {
		// With --json alone, stdout carries exactly one document. Guest output must not be
		// interleaved into it, so it goes to stderr where progress already lives.
		return os.Stderr, os.Stderr, func() {}
	}
	so := cli.NewStreamWriter(e, "stdout")
	se := cli.NewStreamWriter(e, "stderr")
	return so, se, func() {
		so.Close()
		se.Close()
	}
}
