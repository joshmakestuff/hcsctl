//go:build windows

package files

import (
	"fmt"
	"os"

	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/wincred"
)

type removeResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	Root    string   `json:"root"`
	Removed []string `json:"removed"`
	Kept    []string `json:"kept"`
}

// remove undoes prepare. Elevated. It refuses while any VM exposure remains under the root
// unless --force, so a running AppHost's mounts are not pulled out from under it by accident.
func remove(root string, force bool, e cli.Emit) error {
	if !isElevated() {
		return fmt.Errorf("files remove needs elevation: deleting a share, a local user and a firewall rule all require an elevated token -- rerun elevated")
	}
	if st, err := readState(root); err == nil && st.Root != "" {
		root = st.Root
	}

	dirs, err := vmDirs(root)
	if err != nil {
		return err
	}
	if len(dirs) > 0 && !force {
		return fmt.Errorf("%d VM exposure(s) remain under %s; unexpose them or pass --force", len(dirs), root)
	}

	// Each step is gated on the thing existing, so remove is idempotent and removed[] reports
	// only what it actually undid.
	var removed, kept []string
	if rule, _ := readRule(RuleName); rule.Present {
		if err := removeRule(RuleName); err != nil {
			return err
		}
		removed = append(removed, "firewall rule")
	}

	for _, s := range []string{ShareRW, ShareRO} {
		exists, err := shareExists(s)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := shareDel(s); err != nil {
			return err
		}
		removed = append(removed, "share "+s)
	}

	if _, _, err := wincred.Read(CredentialTarget); err == nil {
		if err := wincred.Delete(CredentialTarget); err != nil {
			e.Progress("warning: delete credential %s: %v", CredentialTarget, err)
		} else {
			removed = append(removed, "credential")
		}
	}

	// unhideUser is best effort and not reported: it only tidies a registry value.
	if err := unhideUser(UserName); err != nil {
		e.Progress("warning: unhide %s: %v", UserName, err)
	}
	if userExists(UserName) {
		if err := userDel(UserName); err != nil {
			return err
		}
		removed = append(removed, "user")
	}

	if _, err := os.Stat(stateFilePath(root)); err == nil {
		if err := os.Remove(stateFilePath(root)); err != nil {
			e.Progress("warning: remove state file: %v", err)
		} else {
			removed = append(removed, "state file")
		}
	}

	// Remove the root only when it exists and is empty; os.Remove fails on a non-empty
	// directory, which is exactly the guard we want (a stray exposure keeps it).
	if dirExists(root) {
		if err := os.Remove(root); err != nil {
			kept = append(kept, "root: "+root+" (not empty)")
		} else {
			removed = append(removed, "root")
		}
	}

	e.Result(removeResult{
		OK:      true,
		Command: "files remove",
		Root:    root,
		Removed: removed,
		Kept:    kept,
	}, func() {
		fmt.Printf("removed %v\n", removed)
		if len(kept) > 0 {
			fmt.Printf("kept %v\n", kept)
		}
	})
	return nil
}
