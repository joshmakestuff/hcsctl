//go:build windows

package storage

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// VM group access for a scratch VHD.
//
// A hyperv-isolated (xenon) container hands the scratch sandbox.vhdx to
// VMMS/vmwp at create, and that principal opens it under the Virtual Machines
// group (S-1-5-83-0). The computestorage scratch product (blank.vhdx copy +
// InitializeWritableLayer) carries only SYSTEM/Administrators/user ACEs, so a
// xenon create fails with "Access is denied" before the doc is even accepted.
// CreateScratchLayer's product carries the group ACE; the computestorage path
// never adds it. Measured isolation (hcsctl#86 xenon shape): granting
// S-1-5-83-0 read+write on the sandbox.vhdx flips the xenon create from
// Access denied to a full boot. This is a re-implementation of vmcompute's
// unexported GrantVmGroupAccess (go-winio/pkg/security ships one, but it
// grants GENERIC_READ only; the measured grant includes write).

const sidVMGroup = "S-1-5-83-0" // NT VIRTUAL MACHINE\Virtual Machines

// grantVMGroupAccess adds a Grant ACE for the Virtual Machines group
// (GENERIC_READ | GENERIC_WRITE, no inheritance) to the file's DACL,
// preserving every existing entry. Idempotent: re-granting merges to one ACE.
func grantVMGroupAccess(path string) error {
	const (
		accessMaskReadWrite = 1<<31 | 1<<30 // GENERIC_READ | GENERIC_WRITE
		accessModeGrant     = 1
		inheritNoInherit    = 0x0
		objFileObject       = 0x1
		secInfoDACL         = 0x4
		shareRead           = 0x1
		shareWrite          = 0x2
		trusteeIsSID        = 0
		trusteeWellKnown    = 5
	)

	type explicitAccess struct {
		accessPermissions uint32
		accessMode        uint32
		inheritance       uint32
		trustee           struct {
			multipleTrustee          *struct{}
			multipleTrusteeOperation int32
			trusteeForm              uint32
			trusteeType              uint32
			name                     uintptr
		}
	}

	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("grantVMGroupAccess stat %s: %w", path, err)
	}
	da := uint32(0x20000 | 0x40000) // READ_CONTROL | WRITE_DAC
	sm := uint32(shareRead | shareWrite)
	fa := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if s.IsDir() {
		fa |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	namep, err := windows.UTF16FromString(path)
	if err != nil {
		return fmt.Errorf("grantVMGroupAccess utf16 %s: %w", path, err)
	}
	fd, err := windows.CreateFile(&namep[0], da, sm, nil, windows.OPEN_EXISTING, fa, 0)
	if err != nil {
		return fmt.Errorf("grantVMGroupAccess open %s: %w", path, err)
	}
	defer windows.CloseHandle(fd)

	// Current DACL + full security descriptor from the handle.
	var sd, origDACL uintptr
	if err := getSecurityInfo(fd, objFileObject, secInfoDACL, 0, 0, uintptr(unsafe.Pointer(&origDACL)), 0, uintptr(unsafe.Pointer(&sd))); err != nil {
		return fmt.Errorf("grantVMGroupAccess GetSecurityInfo %s: %w", path, err)
	}
	defer windows.LocalFree(windows.Handle(sd))

	sid, err := windows.StringToSid(sidVMGroup)
	if err != nil {
		return fmt.Errorf("grantVMGroupAccess sid %s: %w", sidVMGroup, err)
	}

	inheritance := uint32(inheritNoInherit)
	if s.IsDir() {
		inheritance = 0x3 // SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	ea := explicitAccess{
		accessPermissions: accessMaskReadWrite,
		accessMode:        accessModeGrant,
		inheritance:       inheritance,
	}
	ea.trustee.trusteeForm = trusteeIsSID
	ea.trustee.trusteeType = trusteeWellKnown
	ea.trustee.name = uintptr(unsafe.Pointer(sid))

	var newDACL uintptr
	if err := setEntriesInAcl(1, uintptr(unsafe.Pointer(&ea)), origDACL, uintptr(unsafe.Pointer(&newDACL))); err != nil {
		return fmt.Errorf("grantVMGroupAccess SetEntriesInAcl %s: %w", path, err)
	}
	defer windows.LocalFree(windows.Handle(newDACL))

	if err := setSecurityInfo(fd, objFileObject, secInfoDACL, 0, 0, newDACL, 0); err != nil {
		return fmt.Errorf("grantVMGroupAccess SetSecurityInfo %s: %w", path, err)
	}
	return nil
}

var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityInfo = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo = advapi32.NewProc("SetSecurityInfo")
	procSetEntriesInAcl = advapi32.NewProc("SetEntriesInAclW")
)

func getSecurityInfo(handle windows.Handle, objectType, secInfo uint32, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSd uintptr) error {
	r0, _, e1 := procGetSecurityInfo.Call(
		uintptr(handle), uintptr(objectType), uintptr(secInfo),
		ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSd,
	)
	if int32(r0) != 0 {
		return e1
	}
	return nil
}

func setSecurityInfo(handle windows.Handle, objectType, secInfo uintptr, psidOwner, psidGroup, pDacl, pSacl uintptr) error {
	r0, _, e1 := procSetSecurityInfo.Call(
		uintptr(handle), objectType, secInfo,
		psidOwner, psidGroup, pDacl, pSacl,
	)
	if int32(r0) != 0 {
		return e1
	}
	return nil
}

func setEntriesInAcl(count uintptr, entries, oldACL, newACL uintptr) error {
	r0, _, e1 := procSetEntriesInAcl.Call(count, entries, oldACL, newACL)
	if int32(r0) != 0 {
		return e1
	}
	return nil
}
