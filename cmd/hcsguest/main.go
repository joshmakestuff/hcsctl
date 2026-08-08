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
	"net"
	"os"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// Version is the agent build. The host reports it in `guest info`, so a guest running a stale
// agent is visible rather than mysterious.
const Version = "0.1.0"

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
		fmt.Printf("hcsguest %s protocol %d\n", Version, guestproto.Protocol)
	default:
		fmt.Fprintln(os.Stderr, "usage: hcsguest serve|info|version")
		os.Exit(64)
	}
}

func serve() error {
	l, err := listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer l.Close()
	fmt.Fprintf(os.Stderr, "hcsguest %s listening (protocol %d)\n", Version, guestproto.Protocol)

	for {
		c, err := l.Accept()
		if err != nil {
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
	default:
		writeFailure(c, fmt.Sprintf("unknown verb %q", req.Verb))
	}
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
