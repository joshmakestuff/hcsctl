//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"github.com/mdlayher/vsock"
)

// listen binds AF_VSOCK. A Linux guest has no service GUID: the host maps a VSOCK port into
// a service ID through the template GUID, so the port here and the ServiceID on Windows are
// two spellings of the same rendezvous.
//
// mdlayher/vsock rather than a raw unix.Socket wrapped by net.FileListener. Measured
// 2026-08-08: the raw socket, bind and listen all succeed, and then net.FileListener fails
// with "getsockname: address family not supported by protocol". Go's net package only knows
// the address families it implements, and AF_VSOCK is not one of them.
func listen() (net.Listener, error) {
	l, err := vsock.Listen(guestproto.VsockPort, nil)
	if err != nil {
		return nil, fmt.Errorf("listen vsock port %d: %w", guestproto.VsockPort, err)
	}
	return l, nil
}

// runUnderServiceManager has nothing to do on Linux: systemd runs an ordinary process and
// signals it, so the accept loop runs directly.
func runUnderServiceManager(func(stop <-chan struct{}) error) (bool, error) { return false, nil }

// shellFor runs an exec command line through /bin/sh, the Windows counterpart being cmd.exe.
func shellFor(command string) (string, []string) {
	return "/bin/sh", []string{"-c", command}
}

// setProcessGroup puts the command in its own process group, so killTree can signal the whole
// group rather than only the shell.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree signals the negative pid, which is the process group -- the shell and everything
// it started. Killing the shell alone leaves children holding the stdout pipe open, so the
// command appears to run until they finish on their own.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}

// applyNetConfig programs the interface through NetworkManager. nmcli only, no raw-ip
// fallback: raw addresses are torn down at NM's DHCP failure (measured, natlab nmprobe
// 2026-08-11), and a guest without NM is unmeasured -- it gets an explicit error rather
// than a silently different mechanism.
func applyNetConfig(nc *guestproto.NetConfig) (guestproto.NetConfigResult, error) {
	if err := validateNetConfig(nc); err != nil {
		return guestproto.NetConfigResult{}, err
	}
	nmcli, err := exec.LookPath("nmcli")
	if err != nil {
		return guestproto.NetConfigResult{}, fmt.Errorf("nmcli not found: this agent configures through NetworkManager only")
	}
	if out, err := exec.Command(nmcli, nmcliModArgs(nc)...).CombinedOutput(); err != nil {
		return guestproto.NetConfigResult{}, fmt.Errorf("nmcli con mod %s: %v: %s", nc.Interface, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(nmcli, "con", "up", nc.Interface).CombinedOutput(); err != nil {
		return guestproto.NetConfigResult{}, fmt.Errorf("nmcli con up %s: %v: %s", nc.Interface, err, strings.TrimSpace(string(out)))
	}
	return guestproto.NetConfigResult{
		OK:        true,
		Protocol:  guestproto.Protocol,
		Applied:   "nmcli",
		Addresses: observedAddresses(nc.Interface),
	}, nil
}

func gatherInfo() (guestproto.Info, error) {
	host, err := os.Hostname()
	if err != nil {
		return guestproto.Info{}, err
	}
	addrs, err := addresses()
	if err != nil {
		return guestproto.Info{}, err
	}

	uptime, err := readUptime()
	if err != nil {
		return guestproto.Info{}, err
	}

	return guestproto.Info{
		OK:            true,
		Protocol:      guestproto.Protocol,
		AgentVersion:  Version,
		AgentCommit:   commit(),
		OS:            "linux",
		OSVersion:     readOSVersion(),
		Hostname:      host,
		BootTimeUTC:   time.Now().UTC().Add(-uptime),
		UptimeSeconds: int64(uptime.Seconds()),
		Addresses:     addrs,
	}, nil
}

// readUptime uses /proc/uptime rather than the wall clock, for the same reason Windows uses
// GetTickCount64: a freshly booted guest may not have synchronised its clock yet.
func readUptime() (time.Duration, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, fmt.Errorf("/proc/uptime is empty")
	}
	secs, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/uptime: %w", err)
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// readOSVersion prefers PRETTY_NAME, which is the one field every distribution sets and the
// one a human reading a dashboard wants. A guest with no /etc/os-release still answers.
func readOSVersion() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "linux"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "linux"
}
