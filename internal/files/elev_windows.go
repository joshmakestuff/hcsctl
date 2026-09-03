//go:build windows

package files

import "golang.org/x/sys/windows"

// isElevated reports whether this process runs with an elevated token. prepare and remove
// touch the SMB server, a local account and a firewall rule, all of which a UAC-filtered token
// cannot; inspect and the exposure verbs do not and never call this.
func isElevated() bool {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}
