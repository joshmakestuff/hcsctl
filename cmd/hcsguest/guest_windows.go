//go:build windows

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

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

// defaultInterface is what an empty NetConfig.Interface means on Windows: nothing named --
// applyNetConfig selects the single connected adapter instead. Windows has no stable eth0
// analogue; the synthetic NIC's name ("Ethernet 2" on the current image) is an enumeration
// accident, not a contract.
func defaultInterface() string { return "" }

// applyNetConfig programs the adapter through netsh, the measured Windows mechanism
// (winnetprobe arm b, 2026-08-11): a static address set this way holds address and dataplane
// through the whole observation window, because manual assignment itself moves the interface
// off DHCP -- there is no NetworkManager-analogue teardown to defend against.
//
// The same measurement caught the dataplane failing right after apply and recovering within
// the next minute: the address exists but is still in duplicate address detection. So this
// waits for the applied addresses to reach Preferred before attesting -- the host must never
// be handed an allocation the guest cannot yet use.
func applyNetConfig(nc *guestproto.NetConfig) (guestproto.NetConfigResult, error) {
	if err := validateNetConfig(nc); err != nil {
		return guestproto.NetConfigResult{}, err
	}
	iface, err := resolveAdapter(nc.Interface)
	if err != nil {
		return guestproto.NetConfigResult{}, err
	}
	for _, args := range netshCmds(nc, iface.Index) {
		if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
			return guestproto.NetConfigResult{}, fmt.Errorf("netsh %s: %v: %s",
				strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	if err := waitPreferred(uint32(iface.Index), nc.Addresses, 30*time.Second); err != nil {
		return guestproto.NetConfigResult{}, err
	}
	return guestproto.NetConfigResult{
		OK:        true,
		Protocol:  guestproto.Protocol,
		Applied:   "netsh",
		Addresses: observedAddresses(iface.Name),
	}, nil
}

// resolveAdapter picks the adapter to program. A name selects it directly. An empty name
// selects the single up, non-loopback adapter -- the hcs-images guests have exactly one
// synthetic NIC -- and anything else is refused rather than guessed at.
func resolveAdapter(name string) (net.Interface, error) {
	if name != "" {
		i, err := net.InterfaceByName(name)
		if err != nil {
			return net.Interface{}, fmt.Errorf("interface %q: %w", name, err)
		}
		return *i, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	var up []net.Interface
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			up = append(up, i)
		}
	}
	if len(up) != 1 {
		names := make([]string, len(up))
		for j, i := range up {
			names[j] = i.Name
		}
		return net.Interface{}, fmt.Errorf(
			"cannot choose among %d connected adapters (%s) -- name one in the request",
			len(up), strings.Join(names, ", "))
	}
	return up[0], nil
}

// waitPreferred blocks until every applied address passes duplicate address detection, polls
// every 500ms until the timeout. A Duplicate verdict fails immediately: another host holds
// the address, and reporting success would attest a dataplane that cannot work.
func waitPreferred(ifIndex uint32, cidrs []string, timeout time.Duration) error {
	want := []netip.Addr{}
	for _, c := range cidrs {
		want = append(want, netip.MustParsePrefix(c).Addr()) // validated
	}
	deadline := time.Now().Add(timeout)
	for {
		states, err := dadStates(ifIndex)
		if err != nil {
			return err
		}
		pending := []string{}
		for _, a := range want {
			switch states[a] {
			case windows.IpDadStateDuplicate:
				return fmt.Errorf("address %s is already held by another host on the network", a)
			case windows.IpDadStatePreferred:
			default:
				pending = append(pending, a.String())
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("addresses %s still in duplicate address detection after %s",
				strings.Join(pending, ","), timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// dadStates reads each IPv4 unicast address's duplicate-address-detection state on one
// adapter. net.Interface cannot see DAD, so this is the one place the agent asks iphlpapi
// directly.
func dadStates(ifIndex uint32) (map[netip.Addr]int32, error) {
	size := uint32(16 * 1024)
	for {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue // size now holds the needed length; the next make uses it
		}
		if err != nil {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		out := map[netip.Addr]int32{}
		for ; aa != nil; aa = aa.Next {
			if aa.IfIndex != ifIndex {
				continue
			}
			for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
				if ip := ua.Address.IP().To4(); ip != nil {
					if a, ok := netip.AddrFromSlice(ip); ok {
						out[a] = ua.DadState
					}
				}
			}
		}
		return out, nil
	}
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
		AgentCommit:   commit(),
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
	// Also kill the process directly. If taskkill is absent, the command still stops, and a
	// partly killed tree is better than a command that never returns.
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
