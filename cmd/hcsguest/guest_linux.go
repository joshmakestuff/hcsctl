//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

// listen binds AF_VSOCK. A Linux guest has no service GUID: the host maps a VSOCK port into
// a service ID through the template GUID, so the port here and the ServiceID on Windows are
// two spellings of the same rendezvous.
//
// UNMEASURED as of 2026-08-08. #37 proved the Windows path host-to-guest; the Linux path has
// never been exercised. Treat a failure here as a finding, not as a bug in this file.
func listen() (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket AF_VSOCK: %w", err)
	}
	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: guestproto.VsockPort}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", guestproto.VsockPort, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen vsock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vsock")
	l, err := net.FileListener(f)
	// FileListener dups the descriptor, so the original is closed either way.
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("file listener: %w", err)
	}
	return l, nil
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
