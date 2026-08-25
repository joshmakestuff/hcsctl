//go:build windows

package scratch

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ExpandScratch grows a scratch layer's sandbox.vhdx to at least size bytes: the virtual
// disk, then its GPT data partition, then the NTFS volume. It replaces vmcompute's
// ExpandSandboxSize (hcsshim.ExpandScratchSize), which fails 0x5 for any unelevated caller
// -- the service-side check is unreachable from a filtered token no matter what it holds.
// This sequence needs no elevation; its one requirement is SeManageVolumePrivilege, spent
// at AttachVirtualDisk (1314 ERROR_PRIVILEGE_NOT_HELD without it). Measured on hcsctl#36.
//
// Call it between CreateScratchLayer and Activate/Prepare, while nothing holds the vhd.
// The disk detaches when the handle closes, so no attach state survives this function.
//
// Everything here goes through the volume device, not the disk device: an attached VHD's
// disk object is ACLed to Administrators only (and AttachVirtualDisk's security-descriptor
// parameter measurably does not override that), while its volume object grants Authenticated
// Users read/write. IOCTL_DISK_GROW_PARTITION is forwarded down the storage stack from the
// volume handle.
func ExpandScratch(scratchDir string, size uint64) error {
	vhd, err := openVhd(filepath.Join(scratchDir, "sandbox.vhdx"))
	if err != nil {
		return err
	}
	defer syscall.Close(vhd)

	// A request at or below the current virtual size resizes nothing, matching the "at
	// least" contract of the call this replaces; the partition and volume steps still run
	// and no-op against an already-full disk.
	current, err := vhdVirtualSize(vhd)
	if err != nil {
		return err
	}
	if size > current {
		if err := resizeVhd(vhd, size); err != nil {
			return err
		}
	}

	if err := attachVhd(vhd); err != nil {
		return fmt.Errorf("%w (--scratch-size needs the SeManageVolumePrivilege grant)", err)
	}
	vol, err := volumeOnVhd(vhd)
	if err != nil {
		return err
	}
	vh, err := openVolume(vol)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(vh)

	if err := growPartition(vh, int64(size)); err != nil {
		return err
	}
	return extendVolume(vh, vol)
}

var (
	virtdisk           = windows.NewLazySystemDLL("virtdisk.dll")
	procOpenVDisk      = virtdisk.NewProc("OpenVirtualDisk")
	procResizeVDisk    = virtdisk.NewProc("ResizeVirtualDisk")
	procAttachVDisk    = virtdisk.NewProc("AttachVirtualDisk")
	procGetVDiskInfo   = virtdisk.NewProc("GetVirtualDiskInformation")
	procGetVDiskPath   = virtdisk.NewProc("GetVirtualDiskPhysicalPath")
)

// openVhd opens with VERSION_2 parameters, which require VIRTUAL_DISK_ACCESS_NONE and give
// a handle valid for every operation below, subject only to the file's ACL.
func openVhd(path string) (syscall.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var (
		vst struct {
			DeviceID uint32
			VendorID [16]byte
		}
		params struct {
			Version        uint32
			GetInfoOnly    int32
			ReadOnly       int32
			ResiliencyGUID [16]byte
		}
		handle syscall.Handle
	)
	params.Version = 2
	if r, _, _ := procOpenVDisk.Call(
		uintptr(unsafe.Pointer(&vst)), uintptr(unsafe.Pointer(p)),
		0, 0, uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&handle))); r != 0 {
		return 0, fmt.Errorf("OpenVirtualDisk %s: %w", path, syscall.Errno(r))
	}
	return handle, nil
}

func vhdVirtualSize(vhd syscall.Handle) (uint64, error) {
	// GET_VIRTUAL_DISK_INFO, Version = GET_VIRTUAL_DISK_INFO_SIZE.
	var info struct {
		Version      uint32
		_            uint32
		VirtualSize  uint64
		PhysicalSize uint64
		BlockSize    uint32
		SectorSize   uint32
	}
	info.Version = 1
	n := uint32(unsafe.Sizeof(info))
	if r, _, _ := procGetVDiskInfo.Call(uintptr(vhd),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&info)), 0); r != 0 {
		return 0, fmt.Errorf("GetVirtualDiskInformation: %w", syscall.Errno(r))
	}
	return info.VirtualSize, nil
}

func resizeVhd(vhd syscall.Handle, size uint64) error {
	params := struct {
		Version uint32
		_       uint32
		NewSize uint64
	}{Version: 1, NewSize: size}
	if r, _, _ := procResizeVDisk.Call(uintptr(vhd), 0, uintptr(unsafe.Pointer(&params)), 0); r != 0 {
		return fmt.Errorf("ResizeVirtualDisk: %w", syscall.Errno(r))
	}
	return nil
}

func attachVhd(vhd syscall.Handle) error {
	// No PERMANENT_LIFETIME: closing the handle detaches.
	if r, _, _ := procAttachVDisk.Call(uintptr(vhd), 0, 0, 0, 0, 0); r != 0 {
		return fmt.Errorf("AttachVirtualDisk: %w", syscall.Errno(r))
	}
	return nil
}

// volumeOnVhd finds the \\?\Volume{guid} whose single extent lives on the attached vhd's
// disk, by walking the volume namespace -- the disk device itself cannot be opened.
func volumeOnVhd(vhd syscall.Handle) (string, error) {
	pathBuf := make([]uint16, 260)
	n := uint32(len(pathBuf) * 2)
	if r, _, _ := procGetVDiskPath.Call(uintptr(vhd),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&pathBuf[0]))); r != 0 {
		return "", fmt.Errorf("GetVirtualDiskPhysicalPath: %w", syscall.Errno(r))
	}
	phys := windows.UTF16ToString(pathBuf) // \\.\PhysicalDriveN
	i := strings.LastIndexFunc(phys, func(r rune) bool { return r < '0' || r > '9' })
	disk64, err := strconv.ParseUint(phys[i+1:], 10, 32)
	if err != nil {
		return "", fmt.Errorf("unparseable physical path %q", phys)
	}
	disk := uint32(disk64)

	const ioctlVolumeGetDiskExtents = 0x00560000
	buf := make([]uint16, 260)
	h, err := windows.FindFirstVolume(&buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	defer windows.FindVolumeClose(h)
	for {
		vol := strings.TrimSuffix(windows.UTF16ToString(buf), `\`)
		// FILE_EXECUTE is the widest grant World holds on volume devices, and the extents
		// IOCTL is FILE_ANY_ACCESS.
		if vh, err := openVolumeAccess(vol, windows.FILE_EXECUTE); err == nil {
			// VOLUME_DISK_EXTENTS: count, pad, then {DiskNumber, pad, offset, length}.
			ext := make([]byte, 8+24)
			var bytes uint32
			ioErr := windows.DeviceIoControl(vh, ioctlVolumeGetDiskExtents, nil, 0,
				&ext[0], uint32(len(ext)), &bytes, nil)
			windows.CloseHandle(vh)
			if ioErr == nil &&
				*(*uint32)(unsafe.Pointer(&ext[0])) == 1 &&
				*(*uint32)(unsafe.Pointer(&ext[8])) == disk {
				return vol, nil
			}
		}
		if err := windows.FindNextVolume(h, &buf[0], uint32(len(buf))); err != nil {
			return "", fmt.Errorf("no volume found on %s", phys)
		}
	}
}

func openVolume(vol string) (windows.Handle, error) {
	// Volume devices grant Authenticated Users read/write, which GROW_PARTITION's access
	// bits require. FSCTL_EXTEND_VOLUME is FILE_ANY_ACCESS but gated on
	// SeManageVolumePrivilege inside the filesystem.
	vh, err := openVolumeAccess(vol, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", vol, err)
	}
	return vh, nil
}

func openVolumeAccess(vol string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(vol)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

type partitionInfoEx struct { // PARTITION_INFORMATION_EX
	PartitionStyle     uint32
	_                  uint32
	StartingOffset     int64
	PartitionLength    int64
	PartitionNumber    uint32
	RewritePartition   byte
	IsServicePartition byte
	_                  [2]byte
	_                  [112]byte // style-specific union, unread
}

func partitionInfo(vh windows.Handle) (*partitionInfoEx, error) {
	const ioctlDiskGetPartitionInfoEx = 0x00070048
	var part partitionInfoEx
	var bytes uint32
	if err := windows.DeviceIoControl(vh, ioctlDiskGetPartitionInfoEx, nil, 0,
		(*byte)(unsafe.Pointer(&part)), uint32(unsafe.Sizeof(part)), &bytes, nil); err != nil {
		return nil, fmt.Errorf("IOCTL_DISK_GET_PARTITION_INFO_EX: %w", err)
	}
	return &part, nil
}

// growPartition grows the volume's partition toward diskSize. The driver does not clamp an
// oversized ask (ERROR_INVALID_PARAMETER), so the growth is computed exactly, keeping 1 MiB
// clear for the GPT backup table at the end of the disk.
func growPartition(vh windows.Handle, diskSize int64) error {
	part, err := partitionInfo(vh)
	if err != nil {
		return err
	}
	grow := diskSize - part.StartingOffset - part.PartitionLength - (1 << 20)
	if grow <= 0 {
		return nil
	}
	const ioctlDiskGrowPartition = 0x0007C0D0
	in := struct {
		PartitionNumber uint32
		_               uint32
		BytesToGrow     int64
	}{PartitionNumber: part.PartitionNumber, BytesToGrow: grow}
	var bytes uint32
	if err := windows.DeviceIoControl(vh, ioctlDiskGrowPartition,
		(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)), nil, 0, &bytes, nil); err != nil {
		return fmt.Errorf("IOCTL_DISK_GROW_PARTITION: %w", err)
	}
	return nil
}

// extendVolume brings the NTFS volume up to its partition -- hcsshim expandSandboxVolume's
// own arithmetic, kept call-compatible so the two agree on when there is nothing to do.
func extendVolume(vh windows.Handle, vol string) error {
	part, err := partitionInfo(vh)
	if err != nil {
		return err
	}
	const clusterSize, sectorSize = 4096, 512
	targetClusters := part.PartitionLength / clusterSize
	var volSize uint64
	if err := windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(vol+`\`), nil, &volSize, nil); err != nil {
		return fmt.Errorf("GetDiskFreeSpaceEx %s: %w", vol, err)
	}
	if int64(volSize)/clusterSize+1 >= targetClusters {
		return nil
	}
	const fsctlExtendVolume = 0x000900F0
	targetSectors := targetClusters * (clusterSize / sectorSize)
	var bytes uint32
	if err := windows.DeviceIoControl(vh, fsctlExtendVolume,
		(*byte)(unsafe.Pointer(&targetSectors)), 8, nil, 0, &bytes, nil); err != nil {
		return fmt.Errorf("FSCTL_EXTEND_VOLUME: %w", err)
	}
	return nil
}
