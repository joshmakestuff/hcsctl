package files

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// State records what prepare made. The unelevated verbs (inspect, expose) read it instead of
// a privileged query: NetShareGetInfo level 2 (the level that returns the path) is
// admin-only, and inspect must work unelevated.
type State struct {
	Version          int      `json:"version"`
	Root             string   `json:"root"`
	Shares           Shares   `json:"shares"`
	User             string   `json:"user"`
	CredentialTarget string   `json:"credentialTarget"`
	RuleName         string   `json:"ruleName"`
	Networks         []string `json:"networks"`
}

// Shares names the read-write and read-only shares over the root.
type Shares struct {
	ReadWrite string `json:"readWrite"`
	ReadOnly  string `json:"readOnly"`
}

// aliasFor is the host vNIC an hcsctl network presents: Hyper-V names it "vEthernet (<name>)".
// The firewall rule binds to this so 445 opens on the guest-facing NIC and nothing else.
func aliasFor(network string) string {
	return "vEthernet (" + network + ")"
}

// networkFromAlias is the inverse of aliasFor: "vEthernet (X)" -> "X". A string that is not a
// vEthernet alias is returned unchanged.
func networkFromAlias(alias string) string {
	s, ok := strings.CutPrefix(alias, "vEthernet (")
	if !ok {
		return alias
	}
	return strings.TrimSuffix(s, ")")
}

// vmDirs lists the per-VM exposure subdirectories under the share root (everything that is a
// directory; the state file is a file). Used to count exposures and to refuse a remove that
// would strand them.
func vmDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs, nil
}

func stateFilePath(root string) string {
	return filepath.Join(root, StateFile)
}

// readState loads the state file under root. A missing file is reported as os.ErrNotExist so a
// caller can treat "not prepared" as a normal answer.
func readState(root string) (State, error) {
	b, err := os.ReadFile(stateFilePath(root))
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("parse %s: %w", stateFilePath(root), err)
	}
	return s, nil
}

// writeState writes the state file under root, pretty-printed.
func writeState(root string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFilePath(root), b, 0o644)
}
