// mount: the pure half of the mount/unmount verbs. Portable so the tests run on any OS; the
// cifs mount(2) is in mount_linux.go, the WNet connect + symlink in mount_windows.go.

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// validateMount rejects malformed input. The agent is a wire endpoint and trusts nothing; the
// host validates too. OS-specific path rules (an absolute guest path) are left to the platform
// applyMount, so this stays testable on any OS.
func validateMount(m *guestproto.Mount) error {
	if m == nil {
		return fmt.Errorf("mount needs a payload")
	}
	if err := validateUNC(m.UNC); err != nil {
		return err
	}
	if m.Path == "" {
		return fmt.Errorf("mount needs a guest path")
	}
	if m.User == "" {
		return fmt.Errorf("mount needs a user")
	}
	// The cifs options string is comma-separated with no escaping, so a comma in the password
	// would split it into a bogus option. Reject it rather than mangle the mount.
	if strings.ContainsAny(m.Password, ",") {
		return fmt.Errorf("password contains a comma, which the cifs options string cannot carry")
	}
	return nil
}

// validateUNC accepts \\host\share and \\host\share\any\sub. It rejects a bare host, a
// forward-slash spelling, and an empty host or share segment.
func validateUNC(unc string) error {
	if !strings.HasPrefix(unc, `\\`) {
		return fmt.Errorf("unc %q must start with \\\\", unc)
	}
	parts := strings.Split(strings.TrimPrefix(unc, `\\`), `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("unc %q must name a host and a share (\\\\host\\share)", unc)
	}
	return nil
}

func validateUnmount(u *guestproto.Unmount) error {
	if u == nil || u.Path == "" {
		return fmt.Errorf("unmount needs a guest path")
	}
	return nil
}

// cifsSource turns the UNC into the source cifs takes: \\host\share\sub -> //host/share/sub.
func cifsSource(unc string) string {
	return strings.ReplaceAll(unc, `\`, "/")
}

// cifsOptions builds the mount(2) data string for a validated mount. ReadOnly is a mount flag
// (MS_RDONLY), not an option, so it is not here. uid/gid are emitted only when non-zero; zero
// leaves the cifs default (root).
func cifsOptions(m *guestproto.Mount) string {
	opts := []string{"vers=3.1.1", "username=" + m.User, "password=" + m.Password}
	if m.UID != 0 {
		opts = append(opts, "uid="+strconv.Itoa(m.UID))
	}
	if m.GID != 0 {
		opts = append(opts, "gid="+strconv.Itoa(m.GID))
	}
	opts = append(opts, "file_mode=0644", "dir_mode=0755")
	return strings.Join(opts, ",")
}

// shareRoot reduces a UNC to its \\host\share prefix, the connection the Windows agent makes;
// the symlink carries the rest of the path.
func shareRoot(unc string) string {
	parts := strings.Split(strings.TrimPrefix(unc, `\\`), `\`)
	return `\\` + parts[0] + `\` + parts[1]
}
