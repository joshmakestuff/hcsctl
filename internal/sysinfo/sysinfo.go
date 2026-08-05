//go:build windows

// Package sysinfo answers "why did that fail" without a support round-trip: what build this
// is, what the token actually holds, and which HCS features the host reports.
package sysinfo

import (
	"fmt"

	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"golang.org/x/sys/windows"
)

type info struct {
	OK              bool     `json:"ok"`
	Command         string   `json:"command"`
	Build           uint16   `json:"build"`
	BuildRevision   uint32   `json:"buildRevision"`
	Version         string   `json:"version"`
	Elevated        bool     `json:"elevated"`
	Privileges      []string `json:"privilegesHeld"`
	CimFSSupported  bool     `json:"cimfsSupported"`
	BlockCimSupport bool     `json:"blockCimSupported"`
}

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
	if err := a.RejectUnknown(); err != nil {
		return cli.Usage, err
	}

	rev, err := osversion.BuildRevision()
	if err != nil {
		rev = 0
	}
	v := osversion.Get()

	i := info{
		OK: true, Command: "info",
		Build: osversion.Build(), BuildRevision: rev,
		Version:         fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, v.Build, rev),
		Elevated:        isElevated(),
		Privileges:      heldPrivileges(),
		CimFSSupported:  cimfs.IsCimFSSupported(),
		BlockCimSupport: cimfs.IsBlockCimSupported(),
	}

	e.Result(i, func() {
		fmt.Printf("windows      %s\n", i.Version)
		fmt.Printf("elevated     %v\n", i.Elevated)
		fmt.Printf("cimfs        supported=%v blockCim=%v\n", i.CimFSSupported, i.BlockCimSupport)
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
	})
	return cli.OK, nil
}

func isElevated() bool {
	var sid *windows.SID
	// BUILTIN\Administrators.
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
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
