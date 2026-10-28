//go:build linux

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Reopen every ancestor without following links; unlike mountTarget, the final
// directory is expected to be a mount and can contain untrusted guest data.
func recoveryMount(path string) (int, uint64, error) {
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
	if err != nil || id == parentID || id == 0 {
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
	unix.Close(fd)
	r.MountID = id
	return nil
}

func recoverShareIntent(r shareIntent) (func() error, error) {
	if r.State != "mounted" || r.MountID == 0 {
		return nil, errors.New("mount identity not recorded")
	}
	fd, id, err := recoveryMount(r.Path)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	if id != r.MountID {
		return nil, errors.New("mounted identity changed")
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
