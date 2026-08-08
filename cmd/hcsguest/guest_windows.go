//go:build windows

package main

import (
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
)

// listen binds the agent's service on the wildcard VM ID. Wildcard rather than parent so the
// same binary works if the agent is ever reached from somewhere other than the immediate
// parent partition; the host arrives as HV_GUID_PARENT either way (#37).
func listen() (net.Listener, error) {
	svc, err := guid.FromString(guestproto.ServiceID)
	if err != nil {
		return nil, err
	}
	return winio.ListenHvsock(&winio.HvsockAddr{
		VMID:      winio.HvsockGUIDWildcard(),
		ServiceID: svc,
	})
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

	v := windows.RtlGetVersion()
	// GetTickCount64 is milliseconds since boot. It is the cheapest source that does not
	// depend on the guest's clock being correct, which matters because a freshly booted
	// guest may not have synchronised time yet. x/sys/windows does not wrap it.
	uptime := time.Duration(tickCount64()) * time.Millisecond

	return guestproto.Info{
		OK:            true,
		Protocol:      guestproto.Protocol,
		AgentVersion:  Version,
		OS:            "windows",
		OSVersion:     formatVersion(v.MajorVersion, v.MinorVersion, v.BuildNumber),
		Hostname:      host,
		BootTimeUTC:   time.Now().UTC().Add(-uptime),
		UptimeSeconds: int64(uptime.Seconds()),
		Addresses:     addrs,
	}, nil
}

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func tickCount64() uint64 {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r)
}

func formatVersion(major, minor, build uint32) string {
	return itoa(major) + "." + itoa(minor) + "." + itoa(build)
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
