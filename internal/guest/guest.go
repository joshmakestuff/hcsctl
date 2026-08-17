//go:build windows

// Package guest is the host half of the hcsguest protocol: it dials a guest VM's agent over
// a Hyper-V socket and reports what the guest says about itself.
//
// It needs no network adapter on the guest, no DHCP lease, no firewall rule and no elevation
// on the host: an unelevated member of Hyper-V Administrators reaches a guest listener with
// a service GUID registered nowhere.
package guest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "info":
		return info(a, e)
	case "forward":
		return forward(a, e)
	case "exec":
		return execVerb(a, e)
	case "":
		return cli.Usage, cli.Usagef("guest needs a subcommand: info, exec, forward")
	default:
		return cli.Usage, cli.Usagef("unknown guest subcommand %q (expected info, exec, forward)", a.Word(1))
	}
}

type infoResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	VMID    string `json:"vmId"`
	// Reachable separates "the guest answered" from "the guest is running": a stopped VM and
	// a booting one fail differently.
	Reachable bool `json:"reachable"`
	// State is the reading of that failure: absent, unreachable, or ready.
	State     string           `json:"state"`
	Detail    string           `json:"detail,omitempty"`
	ElapsedMS int64            `json:"elapsedMs"`
	Guest     *guestproto.Info `json:"guest,omitempty"`
}

func info(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--vmid", "--timeout"); err != nil {
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
	timeout := 35 * time.Second
	if s := a.Option("--timeout"); s != "" {
		d, perr := time.ParseDuration(s)
		if perr != nil || d <= 0 {
			return cli.Usage, cli.Usagef("--timeout must be a positive duration, e.g. 10s")
		}
		timeout = d
	}

	e.Progress("dialling %s", vmid)
	start := time.Now()
	doc, state, detail, derr := dialAny(vmid, timeout)
	elapsed := time.Since(start).Milliseconds()

	res := infoResult{
		OK:        derr == nil,
		Command:   "guest info",
		VMID:      vmid.String(),
		Reachable: derr == nil,
		State:     state,
		Detail:    detail,
		ElapsedMS: elapsed,
		Guest:     doc,
	}
	if derr != nil {
		// Not reachable is a result, not a crash: a caller polling for readiness gets the
		// document either way. The exit code still reports failure.
		e.Result(res, func() {
			fmt.Printf("guest %s: %s\n", vmid, state)
			if detail != "" {
				fmt.Printf("  %s\n", detail)
			}
		})
		return cli.Failed, nil
	}

	e.Result(res, func() {
		fmt.Printf("guest %s  %s\n", vmid, doc.Hostname)
		fmt.Printf("  os       %s %s\n", doc.OS, doc.OSVersion)
		fmt.Printf("  agent    %s commit %s (protocol %d)\n", doc.AgentVersion, doc.AgentCommit, doc.Protocol)
		fmt.Printf("  uptime   %ds\n", doc.UptimeSeconds)
		for _, ad := range doc.Addresses {
			fmt.Printf("  address  %s %s\n", ad.Interface, ad.Address)
		}
	})
	return cli.OK, nil
}

// ReadInfo waits for a guest agent response.
func ReadInfo(vmid guid.GUID, timeout time.Duration) (*guestproto.Info, error) {
	doc, _, _, err := dialAny(vmid, timeout)
	if err != nil {
		return nil, fmt.Errorf("guest agent unavailable: %w", err)
	}
	return doc, nil
}

// dialAny reaches the agent without being told which OS the guest runs. A Windows guest
// binds a service GUID; a Linux guest binds an AF_VSOCK port, which the host addresses
// through the VSOCK template GUID. They are two spellings of one rendezvous.
//
// Concurrently: a dial against a guest that is up without an agent takes 30 s, so dialling
// in sequence would cost a minute.
func dialAny(vmid guid.GUID, timeout time.Duration) (*guestproto.Info, string, string, error) {
	svc, err := guid.FromString(guestproto.ServiceID)
	if err != nil {
		return nil, "unreachable", err.Error(), err
	}
	candidates := []guid.GUID{svc, winio.VsockServiceID(guestproto.VsockPort)}

	type attempt struct {
		doc    *guestproto.Info
		state  string
		detail string
		err    error
	}
	results := make(chan attempt, len(candidates))
	for _, c := range candidates {
		go func(c guid.GUID) {
			d, s, det, e := dial(vmid, c, timeout)
			results <- attempt{d, s, det, e}
		}(c)
	}

	// First success wins. If none succeeds, report the last failure; both dials meet the
	// same guest and fail with the same errno.
	var last attempt
	for range candidates {
		a := <-results
		if a.err == nil {
			return a.doc, a.state, a.detail, nil
		}
		last = a
	}
	return nil, last.state, last.detail, last.err
}

// dial returns the guest document, or a state naming why not. The connect errno of a Hyper-V
// socket discriminates the failure modes; see classify.
func dial(vmid, svc guid.GUID, timeout time.Duration) (*guestproto.Info, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := winio.Dial(ctx, &winio.HvsockAddr{VMID: vmid, ServiceID: svc})
	if err != nil {
		return nil, classify(err), err.Error(), err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req, _ := json.Marshal(guestproto.Request{Protocol: guestproto.Protocol, Verb: "info"})
	if _, werr := conn.Write(append(req, '\n')); werr != nil {
		return nil, "unreachable", werr.Error(), werr
	}

	line, rerr := bufio.NewReader(conn).ReadBytes('\n')
	if rerr != nil && len(line) == 0 {
		return nil, "unreachable", rerr.Error(), rerr
	}

	var doc guestproto.Info
	if uerr := json.Unmarshal(line, &doc); uerr != nil {
		return nil, "unreachable", fmt.Sprintf("agent sent something that is not a document: %v", uerr), uerr
	}
	if !doc.OK {
		var f guestproto.Failure
		_ = json.Unmarshal(line, &f)
		e := fmt.Errorf("agent refused: %s", f.Error)
		return nil, "refused", f.Error, e
	}
	if doc.Protocol != guestproto.Protocol {
		e := fmt.Errorf("agent speaks protocol %d, this build speaks %d", doc.Protocol, guestproto.Protocol)
		return nil, "protocol-mismatch", e.Error(), e
	}
	return &doc, "ready", "", nil
}

// classify turns the connect errno into the distinction that matters to a caller waiting for
// a guest. Measured, host to guest:
//
//	10049 WSAEADDRNOTAVAIL  no such VM, or the VM is not running   (~1 ms)
//	10060 WSAETIMEDOUT      the guest is up, the agent is not      (~30 s)
//
// A caller polling for readiness should treat "absent" as "keep waiting" and "no-agent" as a
// problem with the image, not with the wait.
func classify(err error) string {
	var errno windows.Errno
	if errors.As(err, &errno) {
		switch errno {
		case windows.WSAEADDRNOTAVAIL:
			return "absent"
		case windows.WSAETIMEDOUT:
			return "no-agent"
		case windows.WSAECONNREFUSED:
			return "refused"
		}
	}
	return "unreachable"
}
