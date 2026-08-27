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
	"strconv"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

// Command is `hcsctl guest`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("guest", "reach a guest VM's agent over a Hyper-V socket",
		infoCmd(e), execCmd(e), forwardCmd(e))
}

func infoCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "info --vmid <guid> [--timeout 35s]",
		Short: "what a guest VM says about itself, over a Hyper-V socket",
		Long: `What a guest VM says about itself, over a Hyper-V socket. Needs no NIC,
no DHCP lease and no elevation; needs hcsguest in the image.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return info(vmid.Value(), timeout, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID -- also its hvsocket address")
	cli.Required(cmd, "vmid")
	cli.Duration(cmd.Flags(), &timeout, "timeout", 35*time.Second, 0, "dial budget, a positive duration, e.g. 10s")
	return cmd
}

func execCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var cmdline, cwd string
	var env []string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   `exec --vmid <guid> --cmd "..." [--cwd D] [--env NAME=value]... [--timeout 30s]`,
		Short: "run a command in the guest",
		Long: `Run a command in the guest. --timeout must be at least one second. The
guest's exit code is exitCode in the document, never hcsctl's.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return execVerb(vmid.Value(), cmdline, cwd, env, timeout, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID -- also its hvsocket address")
	cli.StringOnce(cmd.Flags(), &cmdline, "cmd", "command line to run in the guest")
	cli.Required(cmd, "vmid", "cmd")
	cli.StringOnce(cmd.Flags(), &cwd, "cwd", "working directory in the guest")
	cli.StringArray(cmd.Flags(), &env, "env", "NAME=value for the guest process, repeatable")
	// The one-second floor is the wire's: the request carries whole seconds, so anything
	// less truncates to unbounded.
	cli.Duration(cmd.Flags(), &timeout, "timeout", 0, time.Second, "bound on the command, at least one second, e.g. 30s; absent means unbounded")
	return cmd
}

func forwardCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var portRaw, listenAddr string
	var dialTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "forward --vmid <guid> --port <n> [--listen 127.0.0.1:2222] [--timeout <dur>]",
		Short: "publish a guest TCP port on the host",
		Long: `Publish a guest TCP port on the host. The agent dials it on the guest's
loopback, which the guest firewall does not filter.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			port, err := strconv.Atoi(portRaw)
			if err != nil || port < 1 || port > 65535 {
				return cli.Usagef("--port must be a TCP port between 1 and 65535")
			}
			return forward(vmid.Value(), port, listenAddr, dialTimeout, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID -- also its hvsocket address")
	cli.StringOnce(cmd.Flags(), &portRaw, "port", "guest TCP port, 1 to 65535")
	cli.Required(cmd, "vmid", "port")
	cli.StringOnce(cmd.Flags(), &listenAddr, "listen", "host listen address; a bare port means 127.0.0.1")
	cli.Duration(cmd.Flags(), &dialTimeout, "timeout", 35*time.Second, 0, "dial budget per connection, a positive duration, e.g. 10s")
	return cmd
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

func info(vmid guid.GUID, timeout time.Duration, e cli.Emit) error {
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
		// document either way. ErrReported makes the exit code report failure without a
		// second document.
		e.Result(res, func() {
			fmt.Printf("guest %s: %s\n", vmid, state)
			if detail != "" {
				fmt.Printf("  %s\n", detail)
			}
		})
		return cli.ErrReported
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
	return nil
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
// a guest. Host to guest:
//
//	10049 WSAEADDRNOTAVAIL  no such VM, or the VM is not running
//	10060 WSAETIMEDOUT      the guest is up, the agent is not
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
