//go:build windows

package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"golang.org/x/sys/windows"
)

type exposeResult struct {
	OK           bool   `json:"ok"`
	Command      string `json:"command"`
	VMID         string `json:"vmId"`
	Name         string `json:"name"`
	Source       string `json:"source"`
	Junction     string `json:"junction"`
	RelativePath string `json:"relativePath"`
	Share        string `json:"share"`
	ReadOnly     bool   `json:"readOnly"`
	ACEAdded     bool   `json:"aceAdded"`
}

// loadPrepared reads the state under root and resolves the share user's SID. It fails clearly
// when the host is not prepared, so a caller sees the prepare command to run.
func loadPrepared(root string) (State, *windows.SID, error) {
	st, err := readState(root)
	if err != nil {
		return State{}, nil, fmt.Errorf("host not prepared for VM file sharing under %s; run (elevated): hcsctl files prepare --network <name>", root)
	}
	sid, _, _, err := windows.LookupSID("", st.User)
	if err != nil {
		return State{}, nil, fmt.Errorf("share user %q not found; re-run: hcsctl files prepare --network <name>", st.User)
	}
	return st, sid, nil
}

func expose(vmid guid.GUID, name, source string, readOnly bool, labelVals []string, root string, e cli.Emit) error {
	if err := cli.ValidateID(name); err != nil {
		return err
	}
	source, err := validateSource(source)
	if err != nil {
		return err
	}
	labels, err := cli.ParseLabels(labelVals, reservedLabelKeys)
	if err != nil {
		return err
	}
	st, sid, err := loadPrepared(root)
	if err != nil {
		return err
	}
	vmID := vmid.String()

	rec, recErr := readRecord(root, vmID)
	if recErr == nil {
		for _, ex := range rec.Exposures {
			if strings.EqualFold(ex.Name, name) {
				return cli.Usagef("VM %s already exposes a mount named %q", vmID, name)
			}
		}
	} else {
		rec = VMRecord{VMID: vmID}
	}
	// Labels are set once, on the first exposure, and carried; a later expose keeps them.
	if len(rec.Labels) == 0 && len(labels) > 0 {
		rec.Labels = labels
	}

	share := st.Shares.ReadWrite
	if readOnly {
		share = st.Shares.ReadOnly
	}
	vmDir := filepath.Join(root, vmID)
	junction := filepath.Join(vmDir, name)
	relativePath := filepath.Join(vmID, name)

	// Acquire in order, unwinding in reverse on any failure.
	var undo []func()
	fail := func(err error) error {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return err
	}

	vmDirExisted := dirExists(vmDir)
	if !vmDirExisted {
		if err := os.MkdirAll(vmDir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", vmDir, err)
		}
		undo = append(undo, func() { os.Remove(vmDir) })
	}

	if err := grantSource(source, sid, !readOnly); err != nil {
		return fail(err)
	}
	aceAdded := true
	undo = append(undo, func() {
		if !sourceReferencedElsewhere(root, vmID, source) {
			revokeSource(source, sid)
		}
	})

	if err := createJunction(junction, source); err != nil {
		return fail(err)
	}
	undo = append(undo, func() { removeJunction(junction) })

	rec.Exposures = append(rec.Exposures, Exposure{
		Name: name, Source: source, Share: share, ReadOnly: readOnly, ACEAdded: aceAdded,
	})
	if err := writeRecord(root, rec); err != nil {
		return fail(err)
	}

	e.Result(exposeResult{
		OK:           true,
		Command:      "files expose",
		VMID:         vmID,
		Name:         name,
		Source:       source,
		Junction:     junction,
		RelativePath: relativePath,
		Share:        share,
		ReadOnly:     readOnly,
		ACEAdded:     aceAdded,
	}, func() {
		fmt.Printf("exposed %s as %s\\%s (%s)\n", source, vmID, name, share)
	})
	return nil
}

// validateSource applies the same rules as a container mount host path: a drive-letter
// absolute path that exists and is a directory.
func validateSource(source string) (string, error) {
	if len(source) < 3 || source[1] != ':' || (source[2] != '\\' && source[2] != '/') {
		return "", cli.Usagef("--source %q must be a drive-letter absolute path, e.g. C:\\data", source)
	}
	clean := filepath.Clean(source)
	fi, err := os.Stat(clean)
	if err != nil {
		return "", cli.Usagef("--source %q: %v", source, err)
	}
	if !fi.IsDir() {
		return "", cli.Usagef("--source %q is not a directory", source)
	}
	return clean, nil
}

type unexposeResult struct {
	OK         bool     `json:"ok"`
	Command    string   `json:"command"`
	VMID       string   `json:"vmId"`
	Removed    []string `json:"removed"`
	ACERevoked []string `json:"aceRevoked"`
}

func unexpose(vmid guid.GUID, name, root string, e cli.Emit) error {
	vmID := vmid.String()
	st, sid, err := loadPrepared(root)
	if err != nil {
		return err
	}
	_ = st
	rec, err := readRecord(root, vmID)
	if err != nil {
		// Nothing recorded for this VM is a no-op success, so teardown is idempotent.
		e.Result(unexposeResult{OK: true, Command: "files unexpose", VMID: vmID, Removed: []string{}, ACERevoked: []string{}}, func() {
			fmt.Printf("no exposures for %s\n", vmID)
		})
		return nil
	}

	var removed, revoked []string
	var keep []Exposure
	for _, ex := range rec.Exposures {
		if name != "" && !strings.EqualFold(ex.Name, name) {
			keep = append(keep, ex)
			continue
		}
		junction := filepath.Join(root, vmID, ex.Name)
		if err := removeJunction(junction); err != nil {
			// Report and keep the record entry rather than losing track of it.
			e.Progress("warning: remove junction %s: %v", junction, err)
			keep = append(keep, ex)
			continue
		}
		removed = append(removed, ex.Name)
		if ex.ACEAdded && !sourceReferencedElsewhere(root, vmID, ex.Source) {
			if err := revokeSource(ex.Source, sid); err != nil {
				e.Progress("warning: revoke ACE on %s: %v", ex.Source, err)
			} else {
				revoked = append(revoked, ex.Source)
			}
		}
	}

	rec.Exposures = keep
	if len(keep) == 0 {
		// No exposures left: drop the record and the VM directory.
		os.Remove(recordPath(root, vmID))
		os.Remove(filepath.Join(root, vmID))
	} else if err := writeRecord(root, rec); err != nil {
		return err
	}

	e.Result(unexposeResult{
		OK: true, Command: "files unexpose", VMID: vmID,
		Removed: nonNil(removed), ACERevoked: nonNil(revoked),
	}, func() {
		fmt.Printf("unexposed %v from %s\n", removed, vmID)
	})
	return nil
}

type lsExposure struct {
	VMID     string            `json:"vmId"`
	Name     string            `json:"name"`
	Source   string            `json:"source"`
	Share    string            `json:"share"`
	ReadOnly bool              `json:"readOnly"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type lsResult struct {
	OK        bool         `json:"ok"`
	Command   string       `json:"command"`
	Root      string       `json:"root"`
	Exposures []lsExposure `json:"exposures"`
}

func lsExposures(root string, e cli.Emit) error {
	records, err := allRecords(root)
	if err != nil {
		return err
	}
	rows := []lsExposure{}
	for _, r := range records {
		for _, ex := range r.Exposures {
			rows = append(rows, lsExposure{
				VMID: r.VMID, Name: ex.Name, Source: ex.Source,
				Share: ex.Share, ReadOnly: ex.ReadOnly, Labels: r.Labels,
			})
		}
	}
	e.Result(lsResult{OK: true, Command: "files ls", Root: root, Exposures: rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no exposures")
			return
		}
		for _, r := range rows {
			fmt.Printf("%s  %s -> %s (%s)\n", r.VMID, r.Name, r.Source, r.Share)
		}
	})
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
