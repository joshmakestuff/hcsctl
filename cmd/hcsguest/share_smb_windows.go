//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// Fixed script: all data, including credentials, arrives only through stdin.
const globalSMBScript = `$ErrorActionPreference = 'Stop'
try {
 $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
 if ($p.op -eq 'add') {
  $existing = @(Get-SmbGlobalMapping | Where-Object { $_.RemotePath -ieq $p.remote })
  if ($existing.Count -ne 0) { throw 'mapping already exists' }
  $secure = ConvertTo-SecureString -String $p.password -AsPlainText -Force
  try {
   $cred = [System.Management.Automation.PSCredential]::new($p.user, $secure)
   $args = @{ RemotePath=$p.remote; Credential=$cred; Persistent=$false; ErrorAction='Stop' }
   if ($p.port -ne 0) { $args.TcpPort = [uint16]$p.port }
   New-SmbGlobalMapping @args | Out-Null
  } finally { if ($secure) { $secure.Dispose() }; $cred=$null; $p.password=$null }
 } elseif ($p.op -eq 'remove') {
  Remove-SmbGlobalMapping -RemotePath $p.remote -Confirm:$false -ErrorAction Stop
 } else { throw 'invalid operation' }
} catch { [Console]::Error.WriteLine('global mapping operation failed'); exit 1 }`

type globalRequest struct {
	Op       string `json:"op"`
	Remote   string `json:"remote"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	Port     uint32 `json:"port,omitempty"`
}
type globalOps struct {
	command    func(globalRequest) error
	link       func(string, string) error
	removeLink func(string, string) error
}
type globalEntry struct {
	refs        int
	fingerprint [32]byte
	pending     bool
}
type globalManager struct {
	mu      sync.Mutex
	entries map[string]*globalEntry
	ops     globalOps
}

var globalSMB = globalManager{ops: globalOps{command: runGlobalSMB, link: os.Symlink, removeLink: removeOwnedLink}}

func runGlobalSMB(req globalRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return errors.New("global mapping input failed")
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", globalSMBScript)
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil || stderr.Len() != 0 {
		return errors.New("global mapping command failed")
	}
	return nil
}
func removeOwnedLink(path, target string) error {
	got, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, target) {
		return errors.New("mapping link changed")
	}
	return os.Remove(path)
}
func mountGlobalSMB(s *guestproto.Share) (func() error, error) { return globalSMB.mount(s) }
func (m *globalManager) mount(s *guestproto.Share) (func() error, error) {
	// Do not retain the request or its credentials in cleanup closures.
	source, path := s.Source, s.Path
	parts := strings.Split(strings.TrimPrefix(s.Source, `\\`), `\`)
	if !strings.HasPrefix(s.Source, `\\`) || len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(s.Source, "/\x00") || s.User == "" || s.Port > 65535 {
		return nil, errors.New("invalid SMB mapping")
	}
	key := strings.ToLower(s.Source)
	// Fingerprints avoid keeping credentials in the ownership registry.
	encoded, _ := json.Marshal([]any{s.User, s.Password, s.Port})
	fingerprint := sha256.Sum256(encoded)
	clear(encoded)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*globalEntry)
	}
	e := m.entries[key]
	if e != nil && e.pending {
		if err := m.ops.command(globalRequest{Op: "remove", Remote: s.Source}); err != nil {
			return nil, errors.New("pending global mapping cleanup failed")
		}
		delete(m.entries, key)
		e = nil
	}
	if e != nil && e.fingerprint != fingerprint {
		return nil, errors.New("global mapping credentials conflict")
	}
	if e == nil {
		if err := m.ops.command(globalRequest{Op: "add", Remote: s.Source, User: s.User, Password: s.Password, Port: s.Port}); err != nil {
			return nil, errors.New("global mapping creation failed")
		}
		e = &globalEntry{fingerprint: fingerprint}
		m.entries[key] = e
	}
	if err := m.ops.link(s.Source, s.Path); err != nil {
		if e.refs == 0 {
			if m.ops.command(globalRequest{Op: "remove", Remote: s.Source}) != nil {
				e.pending = true
			} else {
				delete(m.entries, key)
			}
		}
		return nil, errors.New("global mapping link creation failed")
	}
	e.refs++
	linked := true
	released := false
	return func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if linked {
			if err := m.ops.removeLink(path, source); err != nil {
				return errors.New("global mapping link removal failed")
			}
			linked = false
		}
		if released {
			return nil
		}
		if e.refs == 1 {
			if err := m.ops.command(globalRequest{Op: "remove", Remote: source}); err != nil {
				return errShareBusy
			}
			delete(m.entries, key)
		}
		e.refs--
		released = true
		return nil
	}, nil
}
