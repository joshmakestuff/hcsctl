//go:build windows

package files

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// NTFS access masks for the source-directory grant, inherited to files and subdirectories:
//
//	0x1301BF  modify   (read/write/execute/delete, no take-ownership or change-permissions)
//	0x1200A9  read+execute
const (
	maskModify     = 0x1301BF
	maskReadExecNT = 0x1200A9
)

// grantSource gives the share user access to a source directory so the SMB server, which
// impersonates that user, can read (or write) the developer's files through the junction.
// GRANT merges with any existing grant for the user, so it is idempotent.
func grantSource(dir string, sid *windows.SID, full bool) error {
	mask := windows.ACCESS_MASK(maskReadExecNT)
	if full {
		mask = windows.ACCESS_MASK(maskModify)
	}
	return setSourceEntry(dir, windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	})
}

// revokeSource removes every ACE granting the share user on the source. Safe because the user
// is hcsctl's own account and nothing else grants it, so nothing a developer set is touched.
func revokeSource(dir string, sid *windows.SID) error {
	return setSourceEntry(dir, windows.EXPLICIT_ACCESS{
		AccessMode: windows.REVOKE_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	})
}

// setSourceEntry applies one EXPLICIT_ACCESS to a directory's existing DACL and writes it back.
func setSourceEntry(dir string, ea windows.EXPLICIT_ACCESS) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", dir, err)
	}
	oldACL, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL of %s: %w", dir, err)
	}
	newACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, oldACL)
	if err != nil {
		return fmt.Errorf("merge ACE for %s: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, newACL, nil); err != nil {
		return fmt.Errorf("write DACL of %s: %w", dir, err)
	}
	return nil
}
