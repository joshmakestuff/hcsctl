//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var readShareMountInfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// Reopen every ancestor without following links; unlike mountTarget, the final
// directory is expected to be a mount and can contain untrusted guest data.
func recoveryMount(path string) (int, uint64, error) {
	return recoveryTarget(path, true)
}

func recoveryTarget(path string, requireMount bool) (int, uint64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, 0, errors.New("invalid recovery path")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	if err = shareTrustedDirectory(fd); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, 0, e
		}
		fd = next
		if e = shareTrustedDirectory(fd); e != nil {
			unix.Close(fd)
			return -1, 0, e
		}
	}
	parentID, err := shareMountID(fd)
	if err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	child, err := unix.Openat(fd, parts[len(parts)-1], unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	id, err := shareMountID(child)
	unix.Close(child)
	if err != nil || (requireMount && id == parentID) || id == 0 {
		unix.Close(fd)
		return -1, 0, errors.New("mount identity unavailable")
	}
	return fd, id, nil
}

func captureShareIntent(r *shareIntent) error {
	fd, id, err := recoveryMount(r.Path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if r.Transport == "virtiofs" {
		if id != r.MountID {
			return errors.New("mounted identity changed")
		}
		if err := verifyVirtioFSAt(fd, *r); err != nil {
			return err
		}
	}
	r.MountID = id
	return nil
}

func verifyVirtioFSMount(r *shareIntent, id uint64) error {
	b, err := readShareMountInfo()
	if err != nil {
		return err
	}
	return matchVirtioFSMount(string(b), r, id)
}

func matchVirtioFSMount(info string, r *shareIntent, id uint64) error {
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != strconv.FormatUint(id, 10) {
			continue
		}
		sep := -1
		for i, field := range fields {
			if field == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+3 >= len(fields) || fields[sep+1] != "virtiofs" || fields[sep+2] != r.Source {
			return errors.New("virtiofs mount identity changed")
		}
		ro := false
		for _, option := range strings.Split(fields[5], ",") {
			if option == "ro" {
				ro = true
			}
		}
		if ro != r.ReadOnly {
			return errors.New("virtiofs mount policy changed")
		}
		return nil
	}
	return errors.New("virtiofs mount identity unavailable")
}

func verifyVirtioFSAt(parent int, r shareIntent) error {
	if r.MountUniqueID == 0 {
		return errors.New("unique mount identity not recorded")
	}
	fd, err := unix.Openat(parent, filepath.Base(r.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	id, err := shareMountID(fd)
	if err != nil {
		return err
	}
	if id != r.MountID {
		return errors.New("mounted identity changed")
	}
	unique, err := uniqueMountID(fd)
	if err != nil {
		return err
	}
	if unique != r.MountUniqueID {
		return errors.New("unique mount identity changed")
	}
	return verifyVirtioFSMount(&r, id)
}

func recoverVirtioFSPending(e *shareEntry) error {
	r := &e.intent
	if r.MountPhase == "preparing" {
		r.State = "absent"
		e.result.OK, e.result.ErrorCode, e.result.State = true, "", "absent"
		return nil
	}
	if r.MountUniqueID == 0 || r.MountID == 0 || r.TargetInode == 0 || r.TargetMountID == 0 || (r.MountPhase != "attaching" && r.MountPhase != "detaching") {
		return errors.New("incomplete mount journal")
	}
	parent, id, err := recoveryTarget(r.Path, false)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, filepath.Base(r.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	id, err = shareMountID(fd)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if id == r.TargetMountID && uint64(st.Dev) == r.TargetDevice && st.Ino == r.TargetInode {
		r.State = "absent"
		e.result.OK, e.result.ErrorCode, e.result.State = true, "", "absent"
		return nil
	}
	if id != r.MountID {
		return errors.New("foreign mount at target")
	}
	r.State = "mounted"
	cleanup, err := recoverShareIntent(*r)
	if err != nil {
		r.State = "pending"
		return err
	}
	e.cleanup = cleanup
	e.result.OK, e.result.ErrorCode, e.result.State = true, "", "mounted"
	return nil
}

func recoverShareBatch(entries map[string]*shareEntry) {
	for _, e := range entries {
		if e.intent.State != "absent" {
			if e.intent.Transport == "virtiofs" && e.intent.State == "pending" && e.intent.MountPhase != "" {
				if err := recoverVirtioFSPending(e); err != nil {
					fmt.Fprintln(os.Stderr, "share recovery requires reconciliation")
				}
				continue
			}
			var err error
			e.cleanup, err = recoverShareIntent(e.intent)
			if err != nil {
				fmt.Fprintln(os.Stderr, "share recovery requires reconciliation")
			} else if e.intent.Transport == "virtiofs" && e.cleanup != nil {
				e.result.OK, e.result.ErrorCode, e.result.State = true, "", "mounted"
			}
		}
	}
}

func recoverShareIntent(r shareIntent) (func() error, error) {
	if r.State != "mounted" || r.MountID == 0 {
		return nil, errors.New("mount identity not recorded")
	}
	fd, id, err := recoveryMount(r.Path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if id != r.MountID {
		return nil, errors.New("mounted identity changed")
	}
	if r.Transport == "virtiofs" {
		if err := verifyVirtioFSAt(fd, r); err != nil {
			return nil, err
		}
	}
	var relay *shareRelay
	var relayErr error
	if r.Transport == "smb-hvsocket" {
		if r.RelayPort == 0 || r.Port == 0 {
			relayErr = errors.New("relay endpoint not recorded")
		} else {
			relay, relayErr = newShareRelayAt(r.Port, r.RelayPort)
		}
	}
	return func() error {
		fd, id, err := recoveryMount(r.Path)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if id != r.MountID {
			return errors.New("mounted identity changed")
		}
		if r.Transport == "virtiofs" {
			if err := verifyVirtioFSAt(fd, r); err != nil {
				return err
			}
		}
		path := fmt.Sprintf("/proc/self/fd/%d/%s", fd, filepath.Base(r.Path))
		if err := shareUnmount(path, 0); err != nil {
			if errors.Is(err, unix.EBUSY) {
				return errShareBusy
			}
			return err
		}
		if relay != nil {
			relay.close()
		}
		return nil
	}, relayErr
}
