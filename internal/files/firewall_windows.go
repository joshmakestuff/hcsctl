//go:build windows

package files

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// The firewall rule is created through the modern Windows Firewall cmdlets, not netsh (which
// cannot bind a rule to a named interface) and not the legacy INetFwRule COM object (go-ole
// cannot set its Interfaces property -- measured, findings.md "SMB bind mounts", G2). prepare
// and remove are elevated and one-time, so a PowerShell invocation there is acceptable; this
// is the only place hcsctl's host side shells out.

// runPS runs a self-contained PowerShell script and returns its stdout.
func runPS(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// psQuote renders a string as a single-quoted PowerShell literal, doubling any embedded quote.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// psStringArray renders a slice as a PowerShell array literal, e.g. @('a','b').
func psStringArray(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = psQuote(s)
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}

// ruleInfo is the shape readRule parses from PowerShell.
type ruleInfo struct {
	Present    bool     `json:"present"`
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
}

// readRule reports whether the rule exists, whether it is enabled, and the interface aliases
// it is bound to. It reads unelevated.
func readRule(name string) (ruleInfo, error) {
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$r = Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue
if (-not $r) { '{"present":false}'; exit 0 }
$aliases = @($r | Get-NetFirewallInterfaceFilter | ForEach-Object { $_.InterfaceAlias } | Where-Object { $_ -and $_ -ne 'Any' })
[pscustomobject]@{ present=$true; enabled=[bool]$r.Enabled; interfaces=$aliases } | ConvertTo-Json -Compress
`, psQuote(name))
	out, err := runPS(script)
	if err != nil {
		return ruleInfo{}, err
	}
	var info ruleInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return ruleInfo{}, fmt.Errorf("parse rule info %q: %w", out, err)
	}
	// ConvertTo-Json renders a single-element array as a scalar; normalize nil to empty.
	if info.Interfaces == nil {
		info.Interfaces = []string{}
	}
	return info, nil
}

// ensureRule creates or updates the inbound TCP 445 rule bound to the given interface aliases,
// unioned with any it already carries, and enables it. Returns whether it was created.
func ensureRule(name string, interfaces []string) (bool, error) {
	existing, err := readRule(name)
	if err != nil {
		return false, err
	}
	aliases := unionStrings(existing.Interfaces, interfaces)
	if existing.Present {
		script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
Set-NetFirewallRule -DisplayName %s -Enabled True -Direction Inbound -Action Allow -Profile Any
Set-NetFirewallRule -DisplayName %s -InterfaceAlias %s
`, psQuote(name), psQuote(name), psStringArray(aliases))
		if _, err := runPS(script); err != nil {
			return false, err
		}
		return false, nil
	}
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
New-NetFirewallRule -DisplayName %s -Description 'hcsctl VM file sharing: SMB 445 inbound on hcsctl vNICs only' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -InterfaceAlias %s -Profile Any -Enabled True | Out-Null
`, psQuote(name), psStringArray(aliases))
	if _, err := runPS(script); err != nil {
		return false, err
	}
	return true, nil
}

// removeRule deletes the rule; a missing rule is not an error. Piping from Get avoids
// Remove-NetFirewallRule's "no rule found" failure, so remove is idempotent.
func removeRule(name string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
exit 0
`, psQuote(name))
	_, err := runPS(script)
	return err
}

// unionStrings returns the case-insensitive union of two slices, preserving first-seen order.
func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		k := strings.ToLower(s)
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}
