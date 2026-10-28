//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	wnetDLL       = windows.NewLazySystemDLL("mpr.dll")
	wnetAdd       = wnetDLL.NewProc("WNetAddConnection2W")
	wnetCancel    = wnetDLL.NewProc("WNetCancelConnection2W")
	wnetUser      = wnetDLL.NewProc("WNetGetUserW")
	flushRegistry = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey")
)

type wnetResource struct {
	scope, kind, display, usage      uint32
	local, remote, comment, provider *uint16
}

type wnetRecord struct {
	Owner                             globalRequest
	Boot, Logon, Phase, ConnectedUser string
}
type wnetStore interface {
	get(string) (wnetRecord, bool, error)
	put(wnetRecord) error
	delete(string) error
}
type wnetAPI interface {
	user(string) (string, bool, error)
	add(string, string, string) error
	cancel(string) error
}
type wnetBackend struct {
	store    wnetStore
	api      wnetAPI
	identity func() (string, string, error)
}

// The caller serializes operations. A record is evidence of intent, not proof
// that an interrupted add or a pre-existing connection belongs to this agent.
func (b wnetBackend) run(r globalRequest) error {
	digest := sha256.Sum256([]byte(strings.ToLower(r.Remote)))
	if r.Key != hex.EncodeToString(digest[:]) || len(r.Token) != 32 || r.User == "" || (r.Port != 0 && r.Port != 445) {
		return errors.New("invalid connection ownership")
	}
	if _, err := hex.DecodeString(r.Token); err != nil {
		return errors.New("invalid connection ownership")
	}
	boot, logon, err := b.identity()
	if err != nil {
		return err
	}
	rec, exists, err := b.store.get(r.Key)
	if err != nil {
		return err
	}
	if r.Op == "add" {
		if exists {
			return errors.New("connection ownership already recorded")
		}
		_, connected, err := b.api.user(r.Remote)
		if err != nil {
			return err
		}
		if connected {
			return errors.New("pre-existing connection is unowned")
		}
		rec = wnetRecord{Owner: r, Boot: boot, Logon: logon, Phase: "intent"}
		rec.Owner.Password = ""
		rec.Owner.Op = "remove"
		if err = b.store.put(rec); err != nil {
			return err
		}
		if err = b.api.add(r.Remote, r.User, r.Password); err != nil {
			return err
		}
		user, connected, err := b.api.user(r.Remote)
		if err != nil {
			return err
		}
		if !connected || !expectedWNetUser(r.User, user) {
			return errors.New("created connection identity uncertain")
		}
		rec.ConnectedUser = user
		rec.Phase = "connected"
		// Failure here leaves intent, never authorizes removal.
		return b.store.put(rec)
	}
	if !exists || rec.Owner.Key != r.Key || rec.Owner.Token != r.Token || !strings.EqualFold(rec.Owner.Remote, r.Remote) || rec.Owner.User != r.User || rec.Owner.Port != r.Port {
		return errors.New("connection ownership uncertain")
	}
	if r.Op == "remove" && rec.Boot != boot && rec.Boot != "" {
		return b.store.delete(r.Key)
	}
	if rec.Boot != boot || rec.Logon != logon {
		return errors.New("connection ownership uncertain")
	}
	if rec.Phase != "connected" && rec.Phase != "intent" && rec.Phase != "releasing" {
		return errors.New("connection ownership uncertain")
	}
	user, connected, err := b.api.user(r.Remote)
	if err != nil {
		return err
	}
	if r.Op == "remove" && !connected {
		return b.store.delete(r.Key)
	}
	if rec.Phase != "connected" || rec.ConnectedUser == "" {
		return errors.New("connection ownership uncertain")
	}
	if connected && !strings.EqualFold(user, rec.ConnectedUser) {
		return errors.New("connection identity changed")
	}
	switch r.Op {
	case "check":
		if !connected {
			return errors.New("connection absent")
		}
		return nil
	case "remove":
		// A crash after cancel cannot make a later replacement look owned.
		rec.Phase = "releasing"
		if err = b.store.put(rec); err != nil {
			return err
		}
		if err = b.api.cancel(r.Remote); err != nil {
			if errors.Is(err, windows.ERROR_OPEN_FILES) || errors.Is(err, windows.ERROR_DEVICE_IN_USE) {
				rec.Phase = "connected"
				if persistErr := b.store.put(rec); persistErr != nil {
					return errors.Join(err, persistErr)
				}
			}
			return err
		}
		return b.store.delete(r.Key)
	default:
		return errors.New("invalid connection operation")
	}
}

// A leaf comparison is used only after this call's successful add. It never
// establishes ownership of a pre-existing connection.
func expectedWNetUser(expected, observed string) bool {
	if expected == "" || observed == "" {
		return false
	}
	if strings.ContainsAny(expected, `\@`) {
		return strings.EqualFold(expected, observed)
	}
	if i := strings.LastIndexByte(observed, '\\'); i >= 0 {
		observed = observed[i+1:]
	}
	return strings.EqualFold(expected, observed)
}

func runGlobalSMB(r globalRequest) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, err := windows.UTF16PtrFromString(`Global\hcsctl-guest-wnet-v1`)
	if err != nil {
		return err
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(mutex)
	result, err := windows.WaitForSingleObject(mutex, 35000)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED {
		return errors.New("connection lock unavailable")
	}
	defer windows.ReleaseMutex(mutex)
	return (wnetBackend{registryWNetStore{}, nativeWNet{}, wnetIdentity}).run(r)
}

func wnetIdentity() (string, string, error) {
	boot, err := readBootID()
	if err != nil {
		return "", "", err
	}
	var token windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", "", err
	}
	defer token.Close()
	// TOKEN_STATISTICS starts with TokenId and AuthenticationId, both LUIDs.
	var stats [64]byte
	var n uint32
	if err = windows.GetTokenInformation(token, windows.TokenStatistics, &stats[0], uint32(len(stats)), &n); err != nil {
		return "", "", err
	}
	if n < 16 {
		return "", "", errors.New("logon identity unavailable")
	}
	return boot, hex.EncodeToString(stats[8:16]), nil
}
func (nativeWNet) user(remote string) (string, bool, error) {
	p, err := windows.UTF16PtrFromString(remote)
	if err != nil {
		return "", false, err
	}
	buf := make([]uint16, 512)
	n := uint32(len(buf))
	code, _, _ := wnetUser.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if code == 2250 {
		return "", false, nil
	}
	if code != 0 {
		return "", false, windows.Errno(code)
	}
	return windows.UTF16ToString(buf), true, nil
}

type nativeWNet struct{}

func (nativeWNet) add(remote, user, password string) error {
	rp, err := windows.UTF16PtrFromString(remote)
	if err != nil {
		return err
	}
	up, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16FromString(password)
	if err != nil {
		return err
	}
	defer clear(pw)
	nr := wnetResource{kind: 1, remote: rp}
	code, _, _ := wnetAdd.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(&pw[0])), uintptr(unsafe.Pointer(up)), 0)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}
func (nativeWNet) cancel(remote string) error {
	p, err := windows.UTF16PtrFromString(remote)
	if err != nil {
		return err
	}
	code, _, _ := wnetCancel.Call(uintptr(unsafe.Pointer(p)), 0, 0)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}

type registryWNetStore struct{}

// Only direct, agent-reserved SMB endpoints are supported. Other software in
// this logon session must not create or replace connections to those endpoints:
// WNet does not expose an identity for an individual connection instance.
const wnetRegistry = `SOFTWARE\hcsctl\GuestWNet`

const wnetRecordValue = "Record"

func encodeWNetRecord(r wnetRecord) ([]byte, error) {
	r.Owner.Password = ""
	r.Owner.Op = "remove"
	if err := validateWNetRecord(r.Owner.Key, r); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// A missing value in this new namespace means initialization stopped before
// authorization; add is never called until the value has been flushed.
func decodeWNetRecord(key string, data []byte, readErr error) (wnetRecord, bool, error) {
	if errors.Is(readErr, windows.ERROR_FILE_NOT_FOUND) {
		return wnetRecord{}, false, nil
	}
	if readErr != nil {
		return wnetRecord{}, false, readErr
	}
	var r wnetRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return wnetRecord{}, false, errors.New("corrupt connection record")
	}
	if err := validateWNetRecord(key, r); err != nil {
		return wnetRecord{}, false, err
	}
	return r, true, nil
}

func validateWNetRecord(key string, r wnetRecord) error {
	digest := sha256.Sum256([]byte(strings.ToLower(r.Owner.Remote)))
	_, tokenErr := hex.DecodeString(r.Owner.Token)
	if key != r.Owner.Key || key != hex.EncodeToString(digest[:]) || len(r.Owner.Token) != 32 || tokenErr != nil || r.Owner.Remote == "" || r.Owner.User == "" || r.Owner.Password != "" || r.Owner.Op != "remove" || (r.Owner.Port != 0 && r.Owner.Port != 445) || r.Boot == "" || r.Logon == "" {
		return errors.New("invalid connection record")
	}
	switch r.Phase {
	case "intent":
	case "connected", "releasing":
		if r.ConnectedUser == "" {
			return errors.New("invalid connection record")
		}
	default:
		return errors.New("invalid connection record")
	}
	return nil
}

func (registryWNetStore) root() (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, wnetRegistry, registry.ALL_ACCESS)
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)")
	if err != nil {
		k.Close()
		return 0, err
	}
	acl, _, err := sd.DACL()
	if err == nil {
		err = windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	if err != nil {
		k.Close()
		return 0, err
	}
	return k, nil
}
func (s registryWNetStore) get(key string) (wnetRecord, bool, error) {
	root, err := s.root()
	if err != nil {
		return wnetRecord{}, false, err
	}
	defer root.Close()
	k, err := registry.OpenKey(root, key, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return wnetRecord{}, false, nil
	}
	if err != nil {
		return wnetRecord{}, false, err
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue(wnetRecordValue)
	return decodeWNetRecord(key, data, err)
}
func (s registryWNetStore) put(r wnetRecord) error {
	data, err := encodeWNetRecord(r)
	if err != nil {
		return err
	}
	root, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	k, _, err := registry.CreateKey(root, r.Owner.Key, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	if err = k.SetBinaryValue(wnetRecordValue, data); err != nil {
		return err
	}
	code, _, _ := flushRegistry.Call(uintptr(k))
	if code != 0 {
		return fmt.Errorf("flush connection record: %w", windows.Errno(code))
	}
	return nil
}
func (s registryWNetStore) delete(key string) error {
	root, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	if err = registry.DeleteKey(root, key); err != nil {
		return err
	}
	code, _, _ := flushRegistry.Call(uintptr(root))
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}
