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
// Stdout and stderr stay on separate channels so the host can attribute them individually.
func runExec(c net.Conn, buffered *bufio.Reader, req guestproto.Request) {
	if req.Command == "" {
		writeFailure(c, "exec needs a command")
		return
	}

	name, args := shellFor(req.Command)
	// exec.Command, not exec.CommandContext: CommandContext kills only the shell it started, and
	// an orphaned child (`cmd /c ping ...` leaves PING.EXE) holds the stdout pipe open until it
	// exits on its own. Timeouts kill the whole tree instead; see killTree.
	cmd := exec.Command(name, args...)
	setProcessGroup(cmd)
	cmd.Dir = req.Cwd
	if len(req.Env) > 0 {
		// Added to the guest's environment, not replacing it.
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
		// Enforced here as well as on the host, so a host that gives up does not leave the
		// command running in the guest.
		t := time.AfterFunc(time.Duration(req.TimeoutSeconds)*time.Second, func() {
			close(timedOut)
			killTree(cmd)
		})
		defer t.Stop()
	}

	// The connection has no deadline for the life of the command: a long-running one would
	// otherwise be cut off mid-flight by the request deadline set on accept.
	_ = c.SetDeadline(time.Time{})

	// One writer, one mutex: interleaved frames from two goroutines would corrupt the stream.
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
	// Drained concurrently: reading them in sequence deadlocks once the command fills the
	// pipe this side is not reading.
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
		// A wait error with a zero exit code is not an ordinary non-zero exit; report it.
		status.Error = waitErr.Error()
	}
	b, _ := json.Marshal(status)
	_ = send(guestproto.ChanExit, b)
}
