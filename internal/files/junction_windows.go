//go:build windows

package files

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

// createJunction makes path a junction to target. path must not exist; target must.
func createJunction(path, target string) error {
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(path), nil); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		// Roll back the directory we just made so a failure leaves nothing behind.
		windows.RemoveDirectory(windows.StringToUTF16Ptr(path))
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	data := mountPointReparseData(target)
	var ret uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &ret, nil); err != nil {
		windows.CloseHandle(h)
		windows.RemoveDirectory(windows.StringToUTF16Ptr(path))
		return fmt.Errorf("set reparse point on %s: %w", path, err)
	}
	return nil
}

// isJunction reports whether path is a mount-point reparse point (a junction). A plain
// directory, a file, or a symlink reparse point all read false.
func isJunction(path string) (bool, error) {
	p := windows.StringToUTF16Ptr(path)
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false, nil
	}
	h, err := windows.CreateFile(p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 16*1024)
	var ret uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return false, err
	}
	if ret < 4 {
		return false, nil
	}
	return binary.LittleEndian.Uint32(buf[:4]) == ioReparseTagMountPoint, nil
}

// removeJunction deletes a junction. It refuses anything that is not a junction, so it can
// never recurse into (or delete the contents of) the target directory: RemoveDirectory on a
// reparse point removes the link, not the target.
func removeJunction(path string) error {
	ok, err := isJunction(path)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not a junction; refusing to remove it", path)
	}
	if err := windows.RemoveDirectory(windows.StringToUTF16Ptr(path)); err != nil {
		return fmt.Errorf("remove junction %s: %w", path, err)
	}
	return nil
}
