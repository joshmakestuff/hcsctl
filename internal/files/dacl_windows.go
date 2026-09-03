//go:build windows

package files

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// ensureRootDir creates the share root and applies the given SDDL as a protected DACL, so the
// root's permissions are exactly what rootDirectorySDDL declares regardless of what ProgramData
// would inherit.
func ensureRootDir(root, sddl string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", root, err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("root SDDL %q: %w", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL from SDDL: %w", err)
	}
	// PROTECTED_DACL_SECURITY_INFORMATION drops inheritance from ProgramData; the SDDL's own
	// ACEs (SYSTEM, Administrators, CREATOR OWNER, Authenticated Users, the share user) stand
	// alone.
	if err := windows.SetNamedSecurityInfo(
		root,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set root DACL: %w", err)
	}
	return nil
}
