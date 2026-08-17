//go:build windows

package vm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createDifferencing makes a copy-on-write VHDX child of base at path. Unelevated.
func createDifferencing(base, path string) error {
	// VIRTUAL_STORAGE_TYPE { DeviceId, VendorId GUID }
	var storageType struct {
		DeviceID uint32
		VendorID windows.GUID
	}
	storageType.DeviceID = 3 // VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
	// VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
	storageType.VendorID = windows.GUID{
		Data1: 0xec984aec, Data2: 0xa0f9, Data3: 0x47e9,
		Data4: [8]byte{0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b},
	}

	basePtr, err := windows.UTF16PtrFromString(base)
	if err != nil {
		return err
	}

	// CREATE_VIRTUAL_DISK_PARAMETERS, Version 2. Only ParentPath is set: a differencing disk
	// takes its size and block size from the parent, and setting them here is how you get
	// ERROR_INVALID_PARAMETER instead.
	var params struct {
		Version                  uint32
		_                        uint32 // padding to the 8-byte union
		UniqueID                 windows.GUID
		MaximumSize              uint64
		BlockSizeInBytes         uint32
		SectorSizeInBytes        uint32
		PhysicalSectorSize       uint32
		_                        uint32
		ParentPath               *uint16
		SourcePath               *uint16
		OpenFlags                uint32
		_                        uint32
		ParentVirtualStorageType struct {
			DeviceID uint32
			VendorID windows.GUID
		}
		SourceVirtualStorageType struct {
			DeviceID uint32
			VendorID windows.GUID
		}
		ResiliencyGUID windows.GUID
	}
	params.Version = 2
	params.ParentPath = basePtr

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	var handle windows.Handle
	rc, _, _ := procCreateVirtualDisk.Call(
		uintptr(unsafe.Pointer(&storageType)),
		uintptr(unsafe.Pointer(pathPtr)),
		0, // VIRTUAL_DISK_ACCESS_NONE -- required for version 2 parameters
		0, // default security descriptor
		0, // CREATE_VIRTUAL_DISK_FLAG_NONE
		0, // provider-specific flags
		uintptr(unsafe.Pointer(&params)),
		0, // synchronous
		uintptr(unsafe.Pointer(&handle)),
	)
	if rc != 0 {
		return fmt.Errorf("CreateVirtualDisk %s from %s: %w", path, base, windows.Errno(rc))
	}
	_ = windows.CloseHandle(handle)
	return nil
}

var procCreateVirtualDisk = windows.NewLazySystemDLL("virtdisk.dll").NewProc("CreateVirtualDisk")
