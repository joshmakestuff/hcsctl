// Command hcsguest is the agent that runs inside a guest VM (#40).
//
// It listens on a Hyper-V socket and answers requests from the host. It never dials out: the
// host dials, the guest listens, and that direction doubles as the host's readiness probe.
//
//	hcsguest serve            listen and answer until killed
//	hcsguest info             print the same document locally, for debugging in the guest
//	hcsguest version
//
// It needs no network adapter, no DHCP lease, no firewall rule and no elevation on the host
// side. Measured in #37.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// Version is the agent build. The host reports it in `guest info`, so a guest running a stale
// agent is visible rather than mysterious.
const Version = "0.1.0"

// Commit is the hcsctl commit this agent was built from. Consumers pin a commit rather than a
// release (hcsctl#35), so the commit is the agent's identity -- and stamping it here is what
// makes that identity survive into the running guest instead of living only in whatever the
// build recorded. Set by the linker; falls back to the VCS stamp Go embeds by default.
var Commit = ""

func commit() string {
	if Commit != "" {
		return Commit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		// A dirty build is not the pinned commit, and saying so is the difference between
		// "this guest runs pin X" and "this guest runs something like pin X".
		return rev + "-dirty"
	}
	return rev
}

func main() {
	verb := ""
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	switch verb {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintf(os.Stderr, "hcsguest: %v\n", err)
			os.Exit(1)
		}
	case "info":
		doc, err := gatherInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "hcsguest: %v\n", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
	case "version":
		fmt.Printf("hcsguest %s commit %s protocol %d\n", Version, commit(), guestproto.Protocol)
	default:
		fmt.Fprintln(os.Stderr, "usage: hcsguest serve|info|version")
		os.Exit(64)
	}
}

// serve runs the accept loop, under the platform's service manager if there is one. On
// Windows that matters: a plain executable registered with sc.exe never answers the service
// control manager and fails to start with error 1053.
func serve() error {
	handled, err := runUnderServiceManager(acceptLoop)
	if handled {
		return err
	}
	return acceptLoop(nil)
}

// acceptLoop serves until stop is closed, or forever if stop is nil.
func acceptLoop(stop <-chan struct{}) error {
	l, err := listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer l.Close()
	fmt.Fprintf(os.Stderr, "hcsguest %s listening (protocol %d)\n", Version, guestproto.Protocol)

	if stop != nil {
		go func() {
			<-stop
			l.Close()
		}()
	}

	for {
		c, err := l.Accept()
		if err != nil {
			if stop != nil {
				select {
				case <-stop:
					return nil
				default:
				}
			}
			// A single failed accept must not end the agent: the host reads a refused or
			// timed-out connection as "not ready", and an agent that exited would look
			// identical forever.
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()

	// A request that never arrives must not hold a goroutine open for the life of the agent.
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(c)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req guestproto.Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeFailure(c, fmt.Sprintf("malformed request: %v", err))
		return
	}
	if req.Protocol != guestproto.Protocol {
		// Refused, never negotiated. See #40.
		writeFailure(c, fmt.Sprintf("protocol %d not supported; this agent speaks %d",
			req.Protocol, guestproto.Protocol))
		return
	}

	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	switch req.Verb {
	case "info":
		doc, err := gatherInfo()
		if err != nil {
			writeFailure(c, err.Error())
			return
		}
		writeJSON(c, doc)
	case "forward":
		forward(c, r, req.Port)
	case "exec":
		runExec(c, r, req)
	default:
		writeFailure(c, fmt.Sprintf("unknown verb %q", req.Verb))
	}
}

// forward joins the caller to a TCP port on the guest's own loopback.
//
// Loopback is the point. Windows does not filter loopback, so a forward reaches a service the
// guest firewall would otherwise drop -- which is the fault that left RDP unreachable while
// SSH worked on the same guest. It also means the guest needs no inbound rule, no NIC and no
// DHCP lease for the host to reach a service inside it.
func forward(c net.Conn, buffered *bufio.Reader, port int) {
	if port < 1 || port > 65535 {
		writeFailure(c, fmt.Sprintf("port %d out of range", port))
		return
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		writeFailure(c, fmt.Sprintf("dial %s: %v", target, err))
		return
	}
	defer up.Close()

	writeJSON(c, guestproto.ForwardOK{
		OK:       true,
		Protocol: guestproto.Protocol,
		Port:     port,
		Target:   target,
	})

	// A forward has no deadline: it lasts as long as the session it carries. An SSH session
	// idles for minutes at a time and must not be cut off by the request deadline set above.
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	// buffered, not c: the JSON request line was read through a bufio.Reader, which may hold
	// payload bytes that arrived in the same segment. Copying from c would silently drop them.
	go func() { _, _ = io.Copy(up, buffered); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func writeJSON(c net.Conn, doc any) {
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = c.Write(b)
}

func writeFailure(c net.Conn, msg string) {
	writeJSON(c, guestproto.Failure{OK: false, Protocol: guestproto.Protocol, Error: msg})
}

// addresses is portable: net.Interfaces works the same on both guests, so the field that
// removes the host's DHCP-lease poll needs no per-OS code.
func addresses() ([]guestproto.Address, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []guestproto.Address
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			family := "ipv6"
			if ipnet.IP.To4() != nil {
				family = "ipv4"
			}
			out = append(out, guestproto.Address{
				Interface: i.Name,
				Address:   ipnet.String(),
				Family:    family,
			})
		}
	}
	return out, nil
}
