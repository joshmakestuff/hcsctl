//go:build windows

package files

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/wincred"
)

type firewallDoc struct {
	Rule       string   `json:"rule"`
	Interfaces []string `json:"interfaces"`
}

type prepareResult struct {
	OK         bool        `json:"ok"`
	Command    string      `json:"command"`
	Root       string      `json:"root"`
	Shares     Shares      `json:"shares"`
	User       string      `json:"user"`
	Credential string      `json:"credential"`
	Firewall   firewallDoc `json:"firewall"`
	Networks   []string    `json:"networks"`
	Created    []string    `json:"created"`
	Updated    []string    `json:"updated"`
}

func prepare(networks []string, root string, e cli.Emit) error {
	// Bad arguments before privilege: an empty network name is a usage error, not a runtime one.
	for _, n := range networks {
		if strings.TrimSpace(n) == "" {
			return cli.Usagef("--network must name a network, not an empty string")
		}
	}
	if !isElevated() {
		return fmt.Errorf("files prepare needs elevation: creating a share, a local user and a firewall rule all require an elevated token -- rerun elevated")
	}

	// Validate every network exists and presents a host vNIC before changing anything.
	aliases := make([]string, 0, len(networks))
	for _, n := range networks {
		if _, err := hcn.GetNetworkByName(n); err != nil {
			return fmt.Errorf("network %q not found: %w", n, err)
		}
		alias := aliasFor(n)
		if _, err := net.InterfaceByName(alias); err != nil {
			return fmt.Errorf("network %q has no host vNIC %q (create the network first): %w", n, alias, err)
		}
		aliases = append(aliases, alias)
	}

	var created, updated []string

	// The local user first: the root DACL and the share ACLs all reference its SID.
	pw, err := newPassword()
	if err != nil {
		return err
	}
	if userExists(UserName) {
		if err := userSetPassword(UserName, pw); err != nil {
			return err
		}
		updated = append(updated, "password")
	} else {
		if err := userAdd(UserName, pw); err != nil {
			return err
		}
		created = append(created, "user")
	}
	if err := hideUser(UserName); err != nil {
		e.Progress("warning: could not hide %s from the sign-in screen: %v", UserName, err)
	}
	sid, err := userSID(UserName)
	if err != nil {
		return err
	}

	// Credential, so the unelevated guest mount can read it.
	credExisted := false
	if _, _, e := wincred.Read(CredentialTarget); e == nil {
		credExisted = true
	}
	if err := wincred.Write(CredentialTarget, UserName, pw); err != nil {
		return err
	}
	if credExisted {
		updated = append(updated, "credential")
	} else {
		created = append(created, "credential")
	}

	// Root directory with its protected DACL.
	rootExisted := dirExists(root)
	if err := ensureRootDir(root, rootDirectorySDDL(sid)); err != nil {
		return err
	}
	if !rootExisted {
		created = append(created, "root")
	}

	// Shares: full and read-only over the same root.
	for _, s := range []struct {
		name string
		full bool
	}{{ShareRW, true}, {ShareRO, false}} {
		exists, err := shareExists(s.name)
		if err != nil {
			return err
		}
		if exists {
			updated = append(updated, "share "+s.name)
			continue
		}
		if err := shareAdd(s.name, root, sharePermissionSDDL(sid, s.full), "hcsctl VM file sharing"); err != nil {
			return err
		}
		created = append(created, "share "+s.name)
	}

	// Firewall rule bound to the union of the requested networks' vNICs.
	ruleCreated, err := ensureRule(RuleName, aliases)
	if err != nil {
		return err
	}
	if ruleCreated {
		created = append(created, "firewall rule")
	} else {
		updated = append(updated, "firewall rule")
	}

	// State records the union of all networks ever prepared, so a later prepare with a new
	// --network keeps the old ones on the rule.
	prior, _ := readState(root)
	allNetworks := unionStrings(prior.Networks, networks)
	if err := writeState(root, State{
		Version:          stateVersion,
		Root:             root,
		Shares:           Shares{ReadWrite: ShareRW, ReadOnly: ShareRO},
		User:             UserName,
		CredentialTarget: CredentialTarget,
		RuleName:         RuleName,
		Networks:         allNetworks,
	}); err != nil {
		return err
	}

	// Report the rule's actual interfaces, unioned over any prior prepare.
	rule, _ := readRule(RuleName)
	e.Result(prepareResult{
		OK:         true,
		Command:    "files prepare",
		Root:       root,
		Shares:     Shares{ReadWrite: ShareRW, ReadOnly: ShareRO},
		User:       UserName,
		Credential: CredentialTarget,
		Firewall:   firewallDoc{Rule: RuleName, Interfaces: rule.Interfaces},
		Networks:   allNetworks,
		Created:    created,
		Updated:    updated,
	}, func() {
		fmt.Printf("prepared %s\n", root)
		fmt.Printf("  shares    %s (rw), %s (ro)\n", ShareRW, ShareRO)
		fmt.Printf("  user      %s (credential %s)\n", UserName, CredentialTarget)
		fmt.Printf("  firewall  %s on %v\n", RuleName, rule.Interfaces)
		if len(created) > 0 {
			fmt.Printf("  created   %v\n", created)
		}
		if len(updated) > 0 {
			fmt.Printf("  updated   %v\n", updated)
		}
	})
	return nil
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
