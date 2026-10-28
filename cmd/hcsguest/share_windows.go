//go:build windows

// VSMB initialization buffer layouts are adapted from Microsoft hcsshim
// internal/gcs-sidecar/vsmb.go (MIT), copyright (c) 2015 Microsoft.
// See LICENSE.hcsshim.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const vsmbDevice = `\\?\GLOBALROOT\Device\vmsmb`
const vsmbTransport = `\Device\VMBus\{4d12e519-17a0-4ae4-8eaa-5270fc6abdb7}-{dcc079ae-60ba-4d07-847c-3493609c0870}-0000`
const vsmbRoot = `\\?\GLOBALROOT\Device\vmsmb\VSMB-{dcc079ae-60ba-4d07-847c-3493609c0870}\`

var vsmbState struct {
	sync.Mutex
	device windows.Handle
	refs   int
}

func mountManagedShare(s *guestproto.Share) (func() error, error) {
	if s == nil {
		return nil, errors.New("nil share")
	}
	if s.Transport == "smb-tcp" {
		return mountGlobalSMB(s)
	}
	if s.Transport != "vsmb" {
		return nil, errShareNotImplemented
	}
	if s.Source == "" || strings.ContainsAny(s.Source, `\/:`+"\x00") || s.Source == "." || s.Source == ".." {
		return nil, errors.New("invalid VSMB share name")
	}
	if err := checkBindVSMB(); err != nil {
		return nil, err
	}
	vsmbState.Lock()
	defer vsmbState.Unlock()
	defer func() {
		if vsmbState.refs == 0 && vsmbState.device != 0 {
			_ = windows.CloseHandle(vsmbState.device)
			vsmbState.device = 0
		}
	}()
	if vsmbState.device == 0 {
		h, err := initVSMB()
		if err != nil {
			return nil, err
		}
		// Keep the device open while any mapping is active.
		vsmbState.device = h
	}
	target := vsmbRoot + s.Source
	keep, err := openVSMB(target, windows.FILE_READ_ATTRIBUTES, windows.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return nil, err
	}
	// Never delete a caller's directory: only create a single missing leaf, and
	// remove it only when we created it and after unmapping.
	created := false
	if err = os.Mkdir(s.Path, 0755); err == nil {
		created = true
	} else if !os.IsExist(err) {
		windows.CloseHandle(keep)
		return nil, err
	}
	if !created {
		info, statErr := os.Lstat(s.Path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			windows.CloseHandle(keep)
			return nil, errors.New("mount target must be a directory")
		}
		entries, readErr := os.ReadDir(s.Path)
		if readErr != nil || len(entries) != 0 {
			windows.CloseHandle(keep)
			return nil, errors.New("mount target must be empty")
		}
	}
	if err = bindVSMB(s.Path, target, true); err != nil {
		windows.CloseHandle(keep)
		if created {
			_ = os.Remove(s.Path)
		}
		return nil, err
	}
	vsmbState.refs++
	var mu sync.Mutex
	mapped := true
	opened := true
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if mapped {
			if err := bindVSMB(s.Path, "", false); err != nil {
				return err
			}
			mapped = false
		}
		if opened {
			if err := windows.CloseHandle(keep); err != nil {
				return err
			}
			opened = false
			vsmbState.Lock()
			vsmbState.refs--
			if vsmbState.refs == 0 {
				_ = windows.CloseHandle(vsmbState.device)
				vsmbState.device = 0
			}
			vsmbState.Unlock()
		}
		if created {
			if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			created = false
		}
		return nil
	}, nil
}

func checkBindVSMB() error {
	dll := windows.NewLazySystemDLL("bindfltapi.dll")
	for _, name := range []string{"BfSetupFilter", "BfRemoveMapping"} {
		if err := dll.NewProc(name).Find(); err != nil {
			return classifyBindAvailability(err)
		}
	}
	return nil
}

func classifyBindAvailability(err error) error {
	if errors.Is(err, windows.ERROR_MOD_NOT_FOUND) || errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return fmt.Errorf("%w: bindflt API: %w", errShareTransportUnavailable, err)
	}
	return fmt.Errorf("bindflt API: %w", err)
}

func bindVSMB(path, target string, add bool) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	dll := windows.NewLazySystemDLL("bindfltapi.dll")
	if add {
		t, err := windows.UTF16PtrFromString(target)
		if err != nil {
			return err
		}
		proc := dll.NewProc("BfSetupFilter")
		if err := proc.Find(); err != nil {
			return err
		}
		// 0x20 is experimental, not a documented bindflt support contract.
		hr, _, _ := proc.Call(0, 0x20, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(t)), 0, 0)
		if int32(hr) < 0 {
			return fmt.Errorf("BfSetupFilter: HRESULT %#x", uint32(hr))
		}
		return nil
	}
	proc := dll.NewProc("BfRemoveMapping")
	if err := proc.Find(); err != nil {
		return err
	}
	hr, _, _ := proc.Call(0, uintptr(unsafe.Pointer(p)))
	if int32(hr) < 0 {
		return fmt.Errorf("BfRemoveMapping: HRESULT %#x", uint32(hr))
	}
	return nil
}

func openVSMB(path string, access, flags uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
}
func vsmbBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}
func vsmbFSCTL(h windows.Handle, code uint32, input []byte) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	var iosb struct{ Status, Information uintptr }
	proc := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtFsControlFile")
	status, _, _ := proc.Call(uintptr(h), uintptr(event), 0, 0, uintptr(unsafe.Pointer(&iosb)), uintptr(code), uintptr(unsafe.Pointer(&input[0])), uintptr(len(input)), 0, 0)
	if uint32(status) == 0x103 {
		wait, e := windows.WaitForSingleObject(event, windows.INFINITE)
		if e != nil {
			return e
		}
		if wait != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("unexpected wait %d", wait)
		}
		status = iosb.Status
	}
	runtime.KeepAlive(input)
	if uint32(status) != 0 && uint32(status) != 0xc0000035 {
		return fmt.Errorf("FSCTL %#x: NTSTATUS %#x", code, uint32(status))
	}
	return nil
}
func initVSMB() (windows.Handle, error) {
	if err := startWorkstation(); err != nil {
		return 0, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return 0, err
	}
	defer token.Close()
	name, _ := windows.UTF16PtrFromString("SeLoadDriverPrivilege")
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return 0, err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return 0, err
	}
	rdr, err := openVSMB(`\\?\GLOBALROOT\Device\LanmanRedirector`, windows.SYNCHRONIZE|windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(rdr)
	n := vsmbBytes(`\Device\vmsmb`)
	b := make([]byte, 120+len(n))
	binary.LittleEndian.PutUint32(b, 120)
	binary.LittleEndian.PutUint32(b[4:], 30)
	binary.LittleEndian.PutUint32(b[8:], 3)
	binary.LittleEndian.PutUint16(b[12:], 0x1e)
	b[80] = 0x1f
	binary.LittleEndian.PutUint32(b[84:], 55)
	binary.LittleEndian.PutUint32(b[88:], 10)
	binary.LittleEndian.PutUint32(b[92:], 30)
	binary.LittleEndian.PutUint32(b[96:], 30)
	b[116] = 1
	binary.LittleEndian.PutUint16(b[118:], uint16(len(n)))
	copy(b[120:], n)
	if err := vsmbFSCTL(rdr, 0x001403a0, b); err != nil {
		return 0, err
	}
	h, err := openVSMB(vsmbDevice, windows.SYNCHRONIZE|windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE, 0)
	if err != nil {
		return 0, err
	}
	n = vsmbBytes(vsmbTransport)
	b = make([]byte, 12+len(n))
	binary.LittleEndian.PutUint16(b, 16)
	binary.LittleEndian.PutUint32(b[4:], 2)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(n)))
	copy(b[12:], n)
	if err := vsmbFSCTL(h, 0x001401b0, b); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}
func startWorkstation() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("LanmanWorkstation")
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err = s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("workstation start timed out")
}
