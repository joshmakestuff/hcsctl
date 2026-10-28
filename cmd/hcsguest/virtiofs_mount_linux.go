//go:build linux

package main

import (
	"errors"
	"fmt"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

var fsOpen = unix.Fsopen
var fsSetString = unix.FsconfigSetString
var fsCreate = unix.FsconfigCreate
var fsMount = unix.Fsmount
var fsMoveMount = unix.MoveMount
var uniqueMountID = statxUniqueMountID

func mountAPIError(stage string, err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("%w: %s: %w", errSharePrerequisiteMissing, stage, err)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

func statxUniqueMountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || st.Mnt_id == 0 {
		return 0, errors.New("unique mount identity unavailable")
	}
	return st.Mnt_id, nil
}

func mountVirtioFSDetached(s *guestproto.Share, r *shareIntent, persist func() error, target int, original unix.Stat_t, oldID uint64) (func() error, error) {
	contextFD, err := fsOpen("virtiofs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, fmt.Errorf("%w: fsopen virtiofs: %w", errSharePrerequisiteMissing, err)
		}
		return nil, err
	}
	defer unix.Close(contextFD)
	if err = fsSetString(contextFD, "source", s.Source); err != nil {
		return nil, mountAPIError("fsconfig source", err)
	}
	if err = fsCreate(contextFD); err != nil {
		return nil, mountAPIError("fsconfig create", err)
	}
	attrs := 0
	if s.ReadOnly {
		attrs = unix.MOUNT_ATTR_RDONLY
	}
	mountFD, err := fsMount(contextFD, unix.FSMOUNT_CLOEXEC, attrs)
	if err != nil {
		return nil, mountAPIError("fsmount", err)
	}
	defer unix.Close(mountFD)
	unique, err := uniqueMountID(mountFD)
	if err != nil {
		return nil, fmt.Errorf("%w: unique mount identity: %v", errSharePrerequisiteMissing, err)
	}
	id, err := shareMountID(mountFD)
	if err != nil || id == 0 || id == oldID {
		return nil, fmt.Errorf("%w: detached mount identity", errSharePrerequisiteMissing)
	}
	r.MountID, r.MountUniqueID = id, unique
	r.TargetDevice, r.TargetInode, r.TargetMountID = uint64(original.Dev), original.Ino, oldID
	r.MountPhase = "attaching"
	if err := persist(); err != nil {
		return nil, errShareJournal
	}
	if err := fsMoveMount(mountFD, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return nil, mountAPIError("move detached virtiofs mount", err)
	}
	// The persisted identity already describes the side effect, including if
	// the process exits before this function returns.
	r.State = "mounted"
	cleanup, err := recoverShareIntent(*r)
	if err != nil {
		return nil, errShareJournal
	}
	return cleanup, nil
}
