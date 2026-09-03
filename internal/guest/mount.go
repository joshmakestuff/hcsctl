//go:build windows

package guest

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"github.com/joshmakestuff/hcsctl/internal/wincred"
	"github.com/spf13/cobra"
)

// Mount asks a VM's agent to attach an SMB share at a guest path and returns what it did.
func Mount(vmid guid.GUID, m guestproto.Mount, timeout time.Duration) (*guestproto.MountResult, error) {
	return call[guestproto.MountResult](vmid, guestproto.Request{
		Protocol: guestproto.Protocol,
		Verb:     "mount",
		Mount:    &m,
	}, timeout)
}

// Unmount asks a VM's agent to detach the mount at a guest path.
func Unmount(vmid guid.GUID, path string, timeout time.Duration) (*guestproto.UnmountResult, error) {
	return call[guestproto.UnmountResult](vmid, guestproto.Request{
		Protocol: guestproto.Protocol,
		Verb:     "unmount",
		Unmount:  &guestproto.Unmount{Path: path},
	}, timeout)
}

func mountCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var unc, path, credential, user string
	var passwordStdin, readOnly bool
	var uid, gid int
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "mount --vmid <guid> --unc <\\\\host\\share\\sub> --path <guest path> (--credential <target> | --user <u> --password-stdin) [--ro] [--uid N] [--gid N] [--timeout 60s]",
		Short: "mount a host SMB share inside the guest",
		Long: `Mount a host SMB share inside the guest over SMB. The agent chooses the
mechanism by its own OS: cifs on Linux, a share connection plus a directory symlink on
Windows. The credential authenticates to the host's SMB server; it is read from Windows
Credential Manager (--credential) or one line of stdin (--user --password-stdin) and never
appears on a command line.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			u, pw, err := resolveCredential(credential, user, passwordStdin)
			if err != nil {
				return err
			}
			return mountVerb(vmid.Value(), guestproto.Mount{
				UNC: unc, Path: path, User: u, Password: pw,
				ReadOnly: readOnly, UID: uid, GID: gid,
			}, timeout, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID -- also its hvsocket address")
	cli.StringOnce(cmd.Flags(), &unc, "unc", `share path, \\host\share or \\host\share\sub`)
	cli.StringOnce(cmd.Flags(), &path, "path", "mount point inside the guest, an absolute path")
	cli.Required(cmd, "vmid", "unc", "path")
	cli.StringOnce(cmd.Flags(), &credential, "credential", "Windows Credential Manager target holding the share user and password")
	cli.StringOnce(cmd.Flags(), &user, "user", "share user; requires --password-stdin")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the share password as one line from stdin; requires --user")
	cmd.Flags().BoolVar(&readOnly, "ro", false, "mount read-only")
	cmd.Flags().IntVar(&uid, "uid", 0, "Linux: owner uid for the mounted files; 0 leaves the cifs default")
	cmd.Flags().IntVar(&gid, "gid", 0, "Linux: owner gid for the mounted files; 0 leaves the cifs default")
	cli.Duration(cmd.Flags(), &timeout, "timeout", 60*time.Second, 0, "budget for the mount, a positive duration, e.g. 60s")
	return cmd
}

func unmountCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var path string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "unmount --vmid <guid> --path <guest path> [--timeout 30s]",
		Short: "unmount a host SMB share inside the guest",
		Long:  `Unmount a host SMB share the agent mounted at the given guest path.`,
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return unmountVerb(vmid.Value(), path, timeout, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID -- also its hvsocket address")
	cli.StringOnce(cmd.Flags(), &path, "path", "mount point inside the guest")
	cli.Required(cmd, "vmid", "path")
	cli.Duration(cmd.Flags(), &timeout, "timeout", 30*time.Second, 0, "budget for the unmount, a positive duration, e.g. 30s")
	return cmd
}

// resolveCredential turns the credential flags into a user and password. Exactly one of
// --credential or --user must be given; --user requires --password-stdin.
func resolveCredential(credential, user string, passwordStdin bool) (string, string, error) {
	switch {
	case credential != "" && user != "":
		return "", "", cli.Usagef("give either --credential or --user, not both")
	case credential != "":
		if passwordStdin {
			return "", "", cli.Usagef("--password-stdin is for --user, not --credential")
		}
		u, pw, err := wincred.Read(credential)
		if err != nil {
			return "", "", fmt.Errorf("read credential %q: %w", credential, err)
		}
		return u, pw, nil
	case user != "":
		if !passwordStdin {
			return "", "", cli.Usagef("--user requires --password-stdin")
		}
		pw, err := readPasswordLine()
		if err != nil {
			return "", "", err
		}
		return user, pw, nil
	default:
		return "", "", cli.Usagef("give --credential <target> or --user <u> --password-stdin")
	}
}

// readPasswordLine reads one line from stdin, stripping the trailing newline.
func readPasswordLine() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type mountResult struct {
	OK        bool   `json:"ok"`
	Command   string `json:"command"`
	VMID      string `json:"vmId"`
	UNC       string `json:"unc"`
	Path      string `json:"path"`
	ReadOnly  bool   `json:"readOnly"`
	Applied   string `json:"applied"`
	ElapsedMS int64  `json:"elapsedMs"`
}

func mountVerb(vmid guid.GUID, m guestproto.Mount, timeout time.Duration, e cli.Emit) error {
	e.Progress("mounting %s at %s", m.UNC, m.Path)
	start := time.Now()
	res, err := Mount(vmid, m, timeout)
	if err != nil {
		return err
	}
	doc := mountResult{
		OK:        true,
		Command:   "guest mount",
		VMID:      vmid.String(),
		UNC:       res.UNC,
		Path:      res.Path,
		ReadOnly:  res.ReadOnly,
		Applied:   res.Applied,
		ElapsedMS: time.Since(start).Milliseconds(),
	}
	e.Result(doc, func() {
		fmt.Printf("mounted %s at %s (%s)\n", doc.UNC, doc.Path, doc.Applied)
	})
	return nil
}

type unmountResult struct {
	OK        bool   `json:"ok"`
	Command   string `json:"command"`
	VMID      string `json:"vmId"`
	Path      string `json:"path"`
	Applied   string `json:"applied"`
	ElapsedMS int64  `json:"elapsedMs"`
}

func unmountVerb(vmid guid.GUID, path string, timeout time.Duration, e cli.Emit) error {
	e.Progress("unmounting %s", path)
	start := time.Now()
	res, err := Unmount(vmid, path, timeout)
	if err != nil {
		return err
	}
	doc := unmountResult{
		OK:        true,
		Command:   "guest unmount",
		VMID:      vmid.String(),
		Path:      res.Path,
		Applied:   res.Applied,
		ElapsedMS: time.Since(start).Milliseconds(),
	}
	e.Result(doc, func() {
		fmt.Printf("unmounted %s (%s)\n", doc.Path, doc.Applied)
	})
	return nil
}
