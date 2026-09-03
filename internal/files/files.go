// Package files is the host side of VM file sharing: the one-time elevated preparation of a
// host SMB share (prepare/remove) and the unelevated per-VM exposures under it
// (expose/unexpose/ls, added separately). A guest reaches the share with `hcsctl guest mount`.
//
// The share root holds one subdirectory per VM, each holding NTFS junctions to the developer's
// directories. Two shares cover the same root: a read-write share and a read-only one, so a
// guest mount's read-only choice is enforced by the host, not trusted from the guest.
//
// prepare and remove need elevation (NetShareAdd, a firewall rule, a local user); inspect and
// the exposure verbs run unelevated. The password to the share user is kept in Windows
// Credential Manager, shared across the same user's elevated and unelevated tokens, and is
// never passed on a command line.
package files

import (
	"os"
	"path/filepath"
)

const (
	// ShareRW and ShareRO are two shares over one root: full and read-only.
	ShareRW = "hcsctl-files"
	ShareRO = "hcsctl-files-ro"

	// UserName is the local account the SMB server impersonates for a guest; CredentialTarget
	// is where its password lives in Credential Manager. Same string, different namespaces.
	UserName         = "hcsctl-files"
	CredentialTarget = "hcsctl-files"

	// RuleName is the inbound TCP 445 firewall rule, scoped to the hcsctl vNICs.
	RuleName = "hcsctl-files SMB-In"

	// StateFile records what prepare made, so the unelevated verbs need no privileged query.
	StateFile = "hcsctl-files.json"

	// stateVersion is the on-disk schema version of StateFile.
	stateVersion = 1
)

// DefaultRoot is the share root: %ProgramData%\hcsctl\files. Machine-wide, because the share
// itself is machine-wide; a per-user location would not match.
func DefaultRoot() string {
	return filepath.Join(os.Getenv("ProgramData"), "hcsctl", "files")
}
