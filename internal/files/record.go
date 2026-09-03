package files

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// recordFile is the per-VM exposure record, a dotfile inside <root>\<vmid> beside the
// junctions. It records enough to unexpose (junction names, sources, whether an ACE was added)
// and the owner labels the scavenger reads.
const recordFile = ".hcsctl-files.json"

// reservedLabelKeys are label keys a caller may not use, because they would shadow a field of
// the exposure documents.
var reservedLabelKeys = map[string]bool{
	"vmId": true, "name": true, "source": true, "share": true,
	"readOnly": true, "labels": true, "exposures": true, "root": true,
	"ok": true, "command": true,
}

// Exposure is one junction under a VM's directory.
type Exposure struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Share    string `json:"share"`
	ReadOnly bool   `json:"readOnly"`
	ACEAdded bool   `json:"aceAdded"`
}

// VMRecord is every exposure for one VM, plus the owner labels.
type VMRecord struct {
	VMID      string            `json:"vmId"`
	Labels    map[string]string `json:"labels,omitempty"`
	Exposures []Exposure        `json:"exposures"`
}

func recordPath(root, vmID string) string {
	return filepath.Join(root, vmID, recordFile)
}

// readRecord loads a VM's record. A missing file is os.ErrNotExist.
func readRecord(root, vmID string) (VMRecord, error) {
	b, err := os.ReadFile(recordPath(root, vmID))
	if err != nil {
		return VMRecord{}, err
	}
	var r VMRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return VMRecord{}, err
	}
	return r, nil
}

// writeRecord writes a VM's record.
func writeRecord(root string, r VMRecord) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recordPath(root, r.VMID), b, 0o644)
}

// allRecords reads every VM record under the root, sorted by VM id for a stable listing.
func allRecords(root string) ([]VMRecord, error) {
	dirs, err := vmDirs(root)
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	var out []VMRecord
	for _, d := range dirs {
		r, err := readRecord(root, d)
		if err != nil {
			// A VM directory without a record is skipped, not fatal: it may be mid-expose.
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// sourceReferencedElsewhere reports whether any exposure other than the excluded VM still
// targets the same source (case-insensitive), so unexpose knows whether it may revoke the ACE.
func sourceReferencedElsewhere(root, excludeVMID, source string) bool {
	records, err := allRecords(root)
	if err != nil {
		return false
	}
	for _, r := range records {
		if r.VMID == excludeVMID {
			continue
		}
		for _, e := range r.Exposures {
			if strings.EqualFold(e.Source, source) {
				return true
			}
		}
	}
	return false
}
