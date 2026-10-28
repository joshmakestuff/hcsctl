//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// Fixed script: all data, including credentials, arrives only through stdin.
const globalSMBScript = `$ErrorActionPreference = 'Stop'
$mutex = $null; $locked = $false; $base = $null; $intent = $null
try {
 $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
 $mutex = [Threading.Mutex]::new($false, 'Global\hcsctl-guest-smb-mapping-v1')
 try { $locked = $mutex.WaitOne(35000) } catch [Threading.AbandonedMutexException] { $locked = $true }
 if (!$locked) { throw 'mutex timeout' }
 $base = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\hcsctl\GuestSMB')
 $intent = $base.OpenSubKey($p.key, $true)
 $matches = @(Get-SmbGlobalMapping | Where-Object { $_.RemotePath -ieq $p.remote })
 if ($p.op -eq 'add') {
  if ($intent -or $matches.Count -ne 0) { throw 'existing mapping or intent' }
  $intent = $base.CreateSubKey($p.key, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
  $intent.SetValue('Token', [string]$p.token)
  $intent.SetValue('Remote', [string]$p.remote)
  $intent.SetValue('User', [string]$p.user)
  $intent.SetValue('Port', [int]$p.port, [Microsoft.Win32.RegistryValueKind]::DWord)
  $intent.Flush()
  $secure = ConvertTo-SecureString -String $p.password -AsPlainText -Force
  try {
   $cred = [System.Management.Automation.PSCredential]::new($p.user, $secure)
   $args = @{ RemotePath=$p.remote; Credential=$cred; Persistent=$false; ErrorAction='Stop' }
   if ($p.port -ne 0) { $args.TcpPort = [uint16]$p.port }
   New-SmbGlobalMapping @args | Out-Null
   $created = @(Get-SmbGlobalMapping | Where-Object { $_.RemotePath -ieq $p.remote })
   if ($created.Count -ne 1 -or $created[0].LocalPath -or ($p.port -ne 0 -and [int]$created[0].TcpPort -ne [int]$p.port)) { throw 'created mapping mismatch' }
  } finally { if ($secure) { $secure.Dispose() }; $cred=$null; $p.password=$null }
 } elseif ($p.op -eq 'remove') {
  if (!$intent) { if ($matches.Count -ne 0) { throw 'unowned mapping' }; exit 0 }
  if ($intent.GetValue('Token') -cne $p.token -or $intent.GetValue('Remote') -ine $p.remote -or $intent.GetValue('User') -cne $p.user -or [int]$intent.GetValue('Port') -ne [int]$p.port) { throw 'intent mismatch' }
  if ($matches.Count -gt 1) { throw 'multiple mappings' }
  if ($matches.Count -eq 1) {
   $mapping = $matches[0]
   if ($mapping.LocalPath -or ($p.port -ne 0 -and [int]$mapping.TcpPort -ne [int]$p.port)) { throw 'mapping mismatch' }
   Remove-SmbGlobalMapping -InputObject $mapping -Confirm:$false -ErrorAction Stop
  }
  $intent.Close(); $intent = $null
  $base.DeleteSubKey($p.key, $false)
 } else { throw 'invalid operation' }
} catch { [Console]::Error.WriteLine('global mapping operation failed'); exit 1 }
finally { if ($intent) { $intent.Close() }; if ($base) { $base.Close() }; if ($locked) { $mutex.ReleaseMutex() }; if ($mutex) { $mutex.Dispose() } }`

type globalRequest struct {
	Op       string `json:"op"`
	Key      string `json:"key"`
	Token    string `json:"token"`
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
	owner       globalRequest
}
type globalManager struct {
	mu      sync.Mutex
	entries map[string]*globalEntry
	ops     globalOps
}

var globalSMB = globalManager{ops: globalOps{command: runGlobalSMB, link: os.Symlink, removeLink: removeOwnedLink}}

func runGlobalSMB(req globalRequest) error {
	digest := sha256.Sum256([]byte(strings.ToLower(req.Remote)))
	if req.Key != hex.EncodeToString(digest[:]) || len(req.Token) != 32 {
		return errors.New("invalid global mapping ownership")
	}
	if _, err := hex.DecodeString(req.Token); err != nil {
		return errors.New("invalid global mapping ownership")
	}
	data, err := json.Marshal(req)
	if err != nil {
		return errors.New("global mapping input failed")
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("system directory unavailable")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", globalSMBScript)
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
		if err := m.ops.command(e.owner); err != nil {
			return nil, errors.New("pending global mapping cleanup failed")
		}
		delete(m.entries, key)
		e = nil
	}
	if e != nil && e.fingerprint != fingerprint {
		return nil, errors.New("global mapping credentials conflict")
	}
	if e == nil {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, errors.New("global mapping ownership unavailable")
		}
		digest := sha256.Sum256([]byte(key))
		owner := globalRequest{Op: "remove", Key: hex.EncodeToString(digest[:]), Token: hex.EncodeToString(token[:]), Remote: source, User: s.User, Port: s.Port}
		e = &globalEntry{fingerprint: fingerprint, owner: owner, pending: true}
		m.entries[key] = e
		add := owner
		add.Op = "add"
		add.Password = s.Password
		if err := m.ops.command(add); err != nil {
			return nil, errors.New("global mapping creation failed; cleanup pending")
		}
		e.pending = false
	}
	if err := m.ops.link(s.Source, s.Path); err != nil {
		if e.refs == 0 {
			if m.ops.command(e.owner) != nil {
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
			if err := m.ops.command(e.owner); err != nil {
				return errShareBusy
			}
			delete(m.entries, key)
		}
		e.refs--
		released = true
		return nil
	}, nil
}

// recoverGlobalSMBOwnership is the coordinator seam for an ownership record
// recovered from the volatile registry; it never removes by UNC alone.
func recoverGlobalSMBOwnership(owner globalRequest) error {
	if owner.Key == "" || owner.Token == "" || owner.Remote == "" || owner.User == "" {
		return errors.New("incomplete global mapping ownership")
	}
	owner.Op = "remove"
	owner.Password = ""
	return runGlobalSMB(owner)
}
