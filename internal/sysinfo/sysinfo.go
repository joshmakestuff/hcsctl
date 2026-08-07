//go:build windows

// Package sysinfo answers "why did that fail" without a support round-trip: what build this
// is, what the token actually holds, and which HCS features the host reports.
package sysinfo

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"golang.org/x/sys/windows"
)

type imageCompat struct {
	Ref       string `json:"ref"`
	OSVersion string `json:"osVersion"`
	// ProcessIsolation is osversion.CheckHostAndContainerCompat -- whether this image build
	// can run process-isolated on this host. Hyper-V isolation boots the image's own kernel
	// and does not depend on it.
	ProcessIsolation bool `json:"processIsolationCompatible"`
}

type storeInfo struct {
	Root   string `json:"root"`
	Exists bool   `json:"exists"`
}

type info struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	// ToolVersion and ContractVersion are hcsctl's own (#29); Version below is the host OS.
	// The contract version is what a consumer's preflight checks; the tool version is for
	// humans in a bug report.
	ToolVersion     string   `json:"toolVersion"`
	ContractVersion string   `json:"contractVersion"`
	Build           uint16   `json:"build"`
	BuildRevision   uint32   `json:"buildRevision"`
	Version         string   `json:"version"`
	Elevated        bool     `json:"elevated"`
	HyperVAdmin     bool     `json:"hyperVAdministrators"`
	Privileges      []string `json:"privilegesHeld"`
	CimFSSupported  bool     `json:"cimfsSupported"`
	BlockCimSupport bool     `json:"blockCimSupported"`
	// Services are reported as states, not distilled into a verdict: which one is absent or
	// stopped is the answer to "why did that fail", and a boolean would hide it.
	Services map[string]string `json:"services"`
	Store    storeInfo         `json:"store"`
	Images   []imageCompat     `json:"images"`
}

// servicesOfInterest: vmcompute is HCS itself -- nothing in this tool works without it.
// vmms and hvhost are the Hyper-V role; absent means Hyper-V isolation cannot boot a
// utility VM.
var servicesOfInterest = []string{"vmcompute", "vmms", "hvhost"}

// privilegesOfInterest are the ones that decide whether a verb can work at all. Reported as
// held or not; enabled-vs-disabled does not matter, because a held privilege can be enabled
// and an absent one cannot.
var privilegesOfInterest = []string{
	"SeBackupPrivilege",
	"SeRestorePrivilege",
	"SeManageVolumePrivilege",
	"SeSecurityPrivilege",
}

func Run(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--store"); err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}

	rev, err := osversion.BuildRevision()
	if err != nil {
		rev = 0
	}
	v := osversion.Get()

	i := info{
		OK: true, Command: "info",
		ToolVersion: cli.ToolVersion, ContractVersion: cli.ContractVersion,
		Build: osversion.Build(), BuildRevision: rev,
		Version:         fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, v.Build, rev),
		Elevated:        isElevated(),
		HyperVAdmin:     inHyperVAdministrators(),
		Privileges:      heldPrivileges(),
		CimFSSupported:  cimfs.IsCimFSSupported(),
		BlockCimSupport: cimfs.IsBlockCimSupported(),
		Services:        serviceStates(),
		Store:           storeState(st),
		Images:          imageCompats(st, v),
	}

	e.Result(i, func() {
		fmt.Printf("hcsctl       %s (contract %s)\n", i.ToolVersion, i.ContractVersion)
		fmt.Printf("windows      %s\n", i.Version)
		fmt.Printf("elevated     %v\n", i.Elevated)
		fmt.Printf("hypervAdmin  %v\n", i.HyperVAdmin)
		fmt.Printf("cimfs        supported=%v blockCim=%v\n", i.CimFSSupported, i.BlockCimSupport)
		fmt.Printf("services     ")
		for n, name := range servicesOfInterest {
			if n > 0 {
				fmt.Print(" ")
			}
			fmt.Printf("%s=%s", name, i.Services[name])
		}
		fmt.Println()
		fmt.Printf("privileges   held: ")
		if len(i.Privileges) == 0 {
			fmt.Print("(none of interest)")
		}
		for n, p := range i.Privileges {
			if n > 0 {
				fmt.Print(", ")
			}
			fmt.Print(p)
		}
		fmt.Println()
		fmt.Printf("store        %s (exists=%v)\n", i.Store.Root, i.Store.Exists)
		for _, img := range i.Images {
			fmt.Printf("image        %-52s %s processIsolation=%v\n", img.Ref, img.OSVersion, img.ProcessIsolation)
		}
	})
	return cli.OK, nil
}

func storeState(st *store.Store) storeInfo {
	_, err := os.Stat(st.Root)
	return storeInfo{Root: st.Root, Exists: err == nil}
}

// imageCompats runs the process-isolation compatibility check for every record in the store.
// An unparseable record version is reported as incompatible rather than skipped -- a blank
// row would look like an empty store.
func imageCompats(st *store.Store, host osversion.OSVersion) []imageCompat {
	recs, err := st.Records()
	if err != nil {
		return nil
	}
	out := make([]imageCompat, 0, len(recs))
	for _, r := range recs {
		c := imageCompat{Ref: r.Ref, OSVersion: r.OSVersion}
		if ctr, ok := parseOSVersion(r.OSVersion); ok {
			c.ProcessIsolation = osversion.CheckHostAndContainerCompat(host, ctr)
		}
		out = append(out, c)
	}
	return out
}

// parseOSVersion turns a record's "10.0.20348.5386" into the three fields the compat check
// reads. The revision does not participate.
func parseOSVersion(s string) (osversion.OSVersion, bool) {
	var v osversion.OSVersion
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return v, false
	}
	major, err1 := strconv.ParseUint(parts[0], 10, 8)
	minor, err2 := strconv.ParseUint(parts[1], 10, 8)
	build, err3 := strconv.ParseUint(parts[2], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil {
		return v, false
	}
	v.MajorVersion = uint8(major)
	v.MinorVersion = uint8(minor)
	v.Build = uint16(build)
	return v, true
}

// serviceStates queries the SCM with the minimum access that works unelevated. "absent" and
// "stopped" are different answers: absent means the role is not installed.
func serviceStates() map[string]string {
	out := map[string]string{}
	for _, name := range servicesOfInterest {
		out[name] = "unknown"
	}
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return out
	}
	defer windows.CloseServiceHandle(m)
	for _, name := range servicesOfInterest {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			out[name] = "absent"
			continue
		}
		var status windows.SERVICE_STATUS
		if err := windows.QueryServiceStatus(s, &status); err == nil {
			switch status.CurrentState {
			case windows.SERVICE_RUNNING:
				out[name] = "running"
			case windows.SERVICE_STOPPED:
				out[name] = "stopped"
			default:
				out[name] = fmt.Sprintf("state-%d", status.CurrentState)
			}
		}
		windows.CloseServiceHandle(s)
	}
	return out
}

func isElevated() bool {
	return inBuiltinGroup(windows.DOMAIN_ALIAS_RID_ADMINS)
}

// inHyperVAdministrators answers for this process's token. Like Administrators, the group is
// UAC-filtered, so unelevated membership can read false for a user who is in the group --
// which is the truthful answer about what this process can do.
func inHyperVAdministrators() bool {
	// DOMAIN_ALIAS_RID_HYPER_V_ADMINS, 0x242 -- not defined in x/sys/windows.
	return inBuiltinGroup(0x242)
}

func inBuiltinGroup(rid uint32) bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, rid,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// heldPrivileges reports which of the interesting privileges the process token carries.
func heldPrivileges() []string {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil
	}
	defer token.Close()

	var held []string
	for _, name := range privilegesOfInterest {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
			continue
		}
		// PrivilegeCheck answers "does this token have it", which is what matters; the
		// enabled/disabled state is adjustable and therefore not interesting here.
		if hasPrivilege(token, luid) {
			held = append(held, name)
		}
	}
	return held
}

func hasPrivilege(token windows.Token, luid windows.LUID) bool {
	privs, err := tokenPrivileges(token)
	if err != nil {
		return false
	}
	for _, p := range privs {
		if p == luid {
			return true
		}
	}
	return false
}

func tokenPrivileges(token windows.Token) ([]windows.LUID, error) {
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if size == 0 {
		return nil, fmt.Errorf("token privileges unavailable")
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], size, &size); err != nil {
		return nil, err
	}
	tp := (*windows.Tokenprivileges)(unsafePointer(&buf[0]))
	all := tp.AllPrivileges()
	out := make([]windows.LUID, 0, len(all))
	for _, p := range all {
		out = append(out, p.Luid)
	}
	return out, nil
}
