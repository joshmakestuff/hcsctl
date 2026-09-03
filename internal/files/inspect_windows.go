//go:build windows

package files

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/wincred"
)

type presentName struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
}

type shareStatuses struct {
	ReadWrite presentName `json:"readWrite"`
	ReadOnly  presentName `json:"readOnly"`
}

type credentialStatus struct {
	Target  string `json:"target"`
	Present bool   `json:"present"`
}

type firewallStatus struct {
	Rule       string   `json:"rule"`
	Present    bool     `json:"present"`
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
}

type inspectResult struct {
	OK         bool             `json:"ok"`
	Command    string           `json:"command"`
	Prepared   bool             `json:"prepared"`
	Root       string           `json:"root"`
	Shares     shareStatuses    `json:"shares"`
	User       presentName      `json:"user"`
	Credential credentialStatus `json:"credential"`
	Firewall   firewallStatus   `json:"firewall"`
	Networks   []string         `json:"networks"`
	Exposures  int              `json:"exposures"`
	Missing    []string         `json:"missing"`
}

// inspect reports the host's preparedness. Unelevated, and "not prepared" is a normal answer,
// so it always exits 0.
func inspect(root string, e cli.Emit) error {
	// A state file, if present, is the authority for the root; without one, the passed root
	// (default or --root) is inspected and every element reads absent.
	if st, err := readState(root); err == nil && st.Root != "" {
		root = st.Root
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		e.Progress("warning: could not read state file: %v", err)
	}

	rwPresent, _ := shareExists(ShareRW)
	roPresent, _ := shareExists(ShareRO)
	userPresent := userExists(UserName)
	_, _, credErr := wincred.Read(CredentialTarget)
	credPresent := credErr == nil
	rule, ruleErr := readRule(RuleName)
	if ruleErr != nil {
		e.Progress("warning: could not read firewall rule: %v", ruleErr)
	}

	networks := make([]string, 0, len(rule.Interfaces))
	for _, a := range rule.Interfaces {
		networks = append(networks, networkFromAlias(a))
	}
	sort.Strings(networks)

	dirs, _ := vmDirs(root)

	var missing []string
	if !rwPresent {
		missing = append(missing, "share "+ShareRW)
	}
	if !roPresent {
		missing = append(missing, "share "+ShareRO)
	}
	if !userPresent {
		missing = append(missing, "user")
	}
	if !credPresent {
		missing = append(missing, "credential")
	}
	if !rule.Present {
		missing = append(missing, "firewall rule")
	}

	res := inspectResult{
		OK:         true,
		Command:    "files inspect",
		Prepared:   len(missing) == 0,
		Root:       root,
		Shares:     shareStatuses{presentName{ShareRW, rwPresent}, presentName{ShareRO, roPresent}},
		User:       presentName{UserName, userPresent},
		Credential: credentialStatus{CredentialTarget, credPresent},
		Firewall:   firewallStatus{RuleName, rule.Present, rule.Enabled, rule.Interfaces},
		Networks:   networks,
		Exposures:  len(dirs),
		Missing:    missing,
	}
	e.Result(res, func() {
		if res.Prepared {
			fmt.Printf("prepared: %s\n", root)
		} else {
			fmt.Printf("not prepared: %s (missing %v)\n", root, missing)
		}
		fmt.Printf("  shares      %s=%v %s=%v\n", ShareRW, rwPresent, ShareRO, roPresent)
		fmt.Printf("  user        %s=%v  credential %s=%v\n", UserName, userPresent, CredentialTarget, credPresent)
		fmt.Printf("  firewall    %s present=%v enabled=%v on %v\n", RuleName, rule.Present, rule.Enabled, rule.Interfaces)
		fmt.Printf("  networks    %v\n", networks)
		fmt.Printf("  exposures   %d\n", len(dirs))
	})
	return nil
}
