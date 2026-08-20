//go:build windows

package guest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

type forwardResult struct {
	OK        bool   `json:"ok"`
	Command   string `json:"command"`
	VMID      string `json:"vmId"`
	Listen    string `json:"listen"`
	GuestPort int    `json:"guestPort"`
}

func forward(vmid guid.GUID, port int, listenAddr string, dialTimeout time.Duration, e cli.Emit) error {
	// Loopback by default. A forward gives whoever reaches it the guest's service with no
	// credential of its own; a caller who wants another interface must write the address
	// out in full.
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	if !strings.Contains(listenAddr, ":") {
		listenAddr = "127.0.0.1:" + listenAddr
	}

	svc, err := serviceFor(vmid, dialTimeout)
	if err != nil {
		return err
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	defer l.Close()

	res := forwardResult{
		OK:        true,
		Command:   "guest forward",
		VMID:      vmid.String(),
		Listen:    l.Addr().String(),
		GuestPort: port,
	}
	// The document is emitted as soon as the listener exists: a caller has to learn the
	// chosen address before it can connect, and with `--listen 0` it cannot know the port
	// any other way.
	e.Result(res, func() {
		fmt.Printf("forwarding %s -> guest 127.0.0.1:%d\n", l.Addr(), port)
		fmt.Printf("press Ctrl-C to stop\n")
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			if err := pipe(c, vmid, svc, port, dialTimeout); err != nil {
				e.Progress("forward: %v", err)
			}
		}()
	}
}

// pipe joins one accepted TCP connection to a fresh hvsocket connection. One connection per
// session; the protocol has no multiplexing.
func pipe(local net.Conn, vmid, svc guid.GUID, port int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	remote, err := winio.Dial(ctx, &winio.HvsockAddr{VMID: vmid, ServiceID: svc})
	if err != nil {
		return fmt.Errorf("dial guest: %w", err)
	}
	defer remote.Close()

	req, _ := json.Marshal(guestproto.Request{
		Protocol: guestproto.Protocol,
		Verb:     "forward",
		Port:     port,
	})
	if _, err := remote.Write(append(req, '\n')); err != nil {
		return err
	}

	br := bufio.NewReader(remote)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("agent closed before replying: %w", err)
	}
	var ok guestproto.ForwardOK
	if err := json.Unmarshal(line, &ok); err != nil || !ok.OK {
		var f guestproto.Failure
		_ = json.Unmarshal(line, &f)
		if f.Error != "" {
			return fmt.Errorf("agent refused: %s", f.Error)
		}
		return fmt.Errorf("agent sent something that is not a reply")
	}

	// No deadline past this point: the forward lasts as long as the session it carries, and
	// an interactive one idles for minutes.
	_ = remote.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	// br, not remote: the reply line was read through a buffered reader that may already
	// hold payload bytes from the same segment.
	go func() { _, _ = io.Copy(local, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
	<-done
	return nil
}

// serviceFor decides once whether this guest answers on the Windows service GUID or the
// Linux VSOCK port, so every connection through the forward does not repeat the race.
func serviceFor(vmid guid.GUID, timeout time.Duration) (guid.GUID, error) {
	svc, err := guid.FromString(guestproto.ServiceID)
	if err != nil {
		return guid.GUID{}, err
	}
	type result struct {
		svc guid.GUID
		err error
	}
	candidates := []guid.GUID{svc, winio.VsockServiceID(guestproto.VsockPort)}
	ch := make(chan result, len(candidates))
	for _, c := range candidates {
		go func(c guid.GUID) {
			_, _, _, err := dial(vmid, c, timeout)
			ch <- result{c, err}
		}(c)
	}
	var last error
	for range candidates {
		r := <-ch
		if r.err == nil {
			return r.svc, nil
		}
		last = r.err
	}
	return guid.GUID{}, fmt.Errorf("no agent answered on %s: %w", vmid, last)
}
