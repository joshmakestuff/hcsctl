//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var regCreateKeyEx = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegCreateKeyExW")

// HKLM\HARDWARE is a volatile hive, so an existing key here cannot be durable.
func readBootID() (string, error) {
	return registryBootID(registry.LOCAL_MACHINE, `HARDWARE\hcsctl\hcsguest\BootIdentity`, `Global\hcsctl-hcsguest-BootIdentity`)
}

func registryBootID(root registry.Key, path, mutexName string) (string, error) {
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return "", fmt.Errorf("create boot identity mutex: %w", err)
	}
	defer windows.CloseHandle(h)
	// Windows mutex ownership is thread-affine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	state, err := windows.WaitForSingleObject(h, 10000)
	if err != nil {
		return "", fmt.Errorf("wait for boot identity mutex: %w", err)
	}
	if state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED {
		return "", fmt.Errorf("boot identity mutex wait: %d", state)
	}
	defer windows.ReleaseMutex(h)

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var key windows.Handle
	var disposition uint32
	r, _, _ := regCreateKeyEx.Call(uintptr(root), uintptr(unsafe.Pointer(p)), 0, 0, 1, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|registry.CREATE_SUB_KEY), 0, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		return "", fmt.Errorf("create volatile boot identity key: %w", windows.Errno(r))
	}
	k := registry.Key(key)
	defer k.Close()
	if disposition == 1 {
		id, err := newBootID()
		if err != nil {
			return "", err
		}
		if err := k.SetStringValue("BootID", id); err != nil {
			return "", fmt.Errorf("write boot identity: %w", err)
		}
		return id, nil
	}
	if disposition != 2 {
		return "", fmt.Errorf("unexpected boot identity key disposition: %d", disposition)
	}
	id, kind, err := k.GetStringValue("BootID")
	if err != nil {
		return "", fmt.Errorf("read boot identity: %w", err)
	}
	if kind != registry.SZ {
		return "", fmt.Errorf("invalid boot identity type")
	}
	return parseBootID(id)
}
