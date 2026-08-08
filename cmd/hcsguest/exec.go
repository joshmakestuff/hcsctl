package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// runExec launches a command in the guest and streams it back as frames.
//
// Stdout and stderr stay on separate channels the whole way, so the host can attribute them
// individually. Merging them here would be irreversible.
func runExec(c net.Conn, buffered *bufio.Reader, req guestproto.Request) {
	if req.Command == "" {
		writeFailure(c, "exec needs a command")
		return
	}

	name, args := shellFor(req.Command)
	// exec.Command, NOT exec.CommandContext. CommandContext kills the one process it started,
	// which is the shell -- so `cmd /c ping ...` loses cmd.exe and leaves PING.EXE running,
	// holding the stdout handle open. Measured: a 5 s timeout took 29.5 s to report, because
	// the pipe did not close until the orphan finished on its own. The same trap is already
	// recorded for the container path. Kill the tree instead; see killTree.
	cmd := exec.Command(name, args...)
	setProcessGroup(cmd)
	cmd.Dir = req.Cwd
	if len(req.Env) > 0 {
		// Added to the guest's environment, not replacing it. A command that lost PATH would
		// fail for a reason nobody could guess from the host.
		cmd.Env = append(os.Environ(), req.Env...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		writeFailure(c, err.Error())
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeFailure(c, err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		writeFailure(c, err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		writeFailure(c, err.Error())
		return
	}

	timedOut := make(chan struct{})
	if req.TimeoutSeconds > 0 {
		// Enforced here as well as on the host. A host that gives up would otherwise leave
		// the command running in the guest with nothing left to stop it.
		t := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
			close(timedOut)
			killTree(cmd)
		})
		defer t.Stop()
	}

	// The connection has no deadline for the life of the command: a long-running one would
	// otherwise be cut off mid-flight by the request deadline set on accept.
	_ = c.SetDeadline(time.Time{})

	// One writer, one mutex. Two goroutines interleaving frames on one socket would corrupt
	// the stream, and the corruption would look like a protocol bug rather than a race.
	var mu sync.Mutex
	send := func(ch byte, p []byte) error {
		mu.Lock()
		defer mu.Unlock()
		return guestproto.WriteFrame(c, ch, p)
	}

	var wg sync.WaitGroup
	pump := func(r io.Reader, ch byte) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if serr := send(ch, buf[:n]); serr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	// Drained concurrently. Reading them in sequence deadlocks as soon as the command fills
	// the pipe this side is not reading -- the same trap the container path already carries.
	go pump(stdout, guestproto.ChanStdout)
	go pump(stderr, guestproto.ChanStderr)

	// Host stdin arrives as ChanStdin frames; a zero-length frame is EOF.
	go func() {
		defer stdin.Close()
		for {
			ch, payload, err := guestproto.ReadFrame(buffered)
			if err != nil {
				return
			}
			if ch != guestproto.ChanStdin {
				continue
			}
			if len(payload) == 0 {
				return
			}
			if _, werr := stdin.Write(payload); werr != nil {
				return
			}
		}
	}()

	wg.Wait()
	waitErr := cmd.Wait()

	status := guestproto.ExitStatus{ExitCode: cmd.ProcessState.ExitCode()}
	select {
	case <-timedOut:
		status.Error = "timed out"
	default:
	}
	if status.Error == "" && waitErr != nil && status.ExitCode == 0 {
		// A wait error with a zero code is not an ordinary non-zero exit; say so rather than
		// reporting success.
		status.Error = waitErr.Error()
	}
	b, _ := json.Marshal(status)
	_ = send(guestproto.ChanExit, b)
}
