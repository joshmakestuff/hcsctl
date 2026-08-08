//go:build windows

package main

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
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

// ServiceName is what the image build registers with the service control manager.
const ServiceName = "hcsguest"

// shellFor runs an exec command line through cmd.exe, matching `hcsctl container exec --cmd`.
// A caller who needs an exact argv would need a different request shape; nothing does yet.
func shellFor(command string) (string, []string) {
	return "cmd.exe", []string{"/c", command}
}

// setProcessGroup has nothing to do on Windows. The tree is killed by pid instead; see
// killTree.
func setProcessGroup(*exec.Cmd) {}

// killTree ends the command AND its children.
//
// Killing only the process kills the shell and orphans what it started. Measured: a 5 s
// timeout on `cmd /c ping -n 30 127.0.0.1` took 29.5 s to report, because the orphaned
// PING.EXE inherited the stdout handle and the pipe did not close until it finished on its
// own. The same behaviour is already recorded for the container path.
//
// taskkill /T rather than a job object: assigning a job after Start races the shell spawning
// its child, and os/exec gives no hook between create and resume to close that race.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	// Belt and braces: if taskkill is unavailable the process itself still dies, and a
	// half-killed tree is better than a command that never returns.
	_ = cmd.Process.Kill()
}

// runUnderServiceManager runs the accept loop as a Windows service when Windows started us as
// one, and reports handled=false when it did not, so the same binary still runs in a console.
//
// This is not optional plumbing. A plain executable registered with sc.exe never answers the
// service control manager and fails to start with error 1053, "did not respond to the start
// request in a timely fashion".
func runUnderServiceManager(loop func(stop <-chan struct{}) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	h := &handler{loop: loop}
	return true, svc.Run(ServiceName, h)
}

type handler struct {
	loop func(stop <-chan struct{}) error
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- h.loop(stop) }()
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The loop only returns on a listen failure. Exiting non-zero lets the service
			// recovery actions restart us, which is what keeps a guest reachable.
			s <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		}
	}
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
