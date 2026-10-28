//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// The handle prevents replacement while the target and file ID are checked.
func openOwnedLink(path, target string, deleteAccess bool) (windows.Handle, uint32, uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES)
	if deleteAccess {
		access |= windows.DELETE
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	fail := func(err error) (windows.Handle, uint32, uint64, error) { windows.CloseHandle(h); return 0, 0, 0, err }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return fail(errors.New("not a reparse point"))
	}
	buf := make([]byte, 16*1024)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return fail(err)
	}
	got, err := linkTarget(buf[:n])
	if err != nil || !strings.EqualFold(got, target) {
		return fail(errors.New("link target changed"))
	}
	index := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	if index == 0 {
		return fail(errors.New("link identity unavailable"))
	}
	return h, info.VolumeSerialNumber, index, nil
}

func linkTarget(buf []byte) (string, error) {
	if len(buf) < 20 || binary.LittleEndian.Uint32(buf) != windows.IO_REPARSE_TAG_SYMLINK {
		return "", errors.New("not a symbolic link")
	}
	length := int(binary.LittleEndian.Uint16(buf[4:]))
	if length < 12 || length+8 > len(buf) {
		return "", errors.New("invalid reparse data")
	}
	offset := int(binary.LittleEndian.Uint16(buf[8:]))
	size := int(binary.LittleEndian.Uint16(buf[10:]))
	if offset%2 != 0 || size%2 != 0 || offset+size > length-12 {
		return "", errors.New("invalid link target")
	}
	u := make([]uint16, size/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(buf[20+offset+i*2:])
	}
	target := string(utf16.Decode(u))
	if binary.LittleEndian.Uint32(buf[16:])&1 != 0 {
		return "", errors.New("relative link target")
	}
	if strings.HasPrefix(target, `\??\UNC\`) {
		target = `\\` + target[8:]
	} else if strings.HasPrefix(target, `\??\`) {
		target = target[4:]
	}
	return target, nil
}

func ownedLinkIdentity(path, target string) (uint32, uint64, error) {
	h, volume, index, err := openOwnedLink(path, target, false)
	if err == nil {
		windows.CloseHandle(h)
	}
	return volume, index, err
}

func removeIdentifiedLink(path, target string, volume uint32, index uint64) error {
	h, actualVolume, actualIndex, err := openOwnedLink(path, target, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if actualVolume != volume || actualIndex != index {
		return errors.New("link identity changed")
	}
	disposition := byte(1)
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1)
}

func captureShareIntent(r *shareIntent) error {
	if r.Transport == "smb-tcp" && (r.LinkIndex == 0 || r.MappingToken == "" || r.MappingKey == "") {
		return errors.New("SMB ownership not captured")
	}
	return nil
}

func recoverShareIntent(shareIntent) (func() error, error) {
	return nil, errors.New("native mapping requires reconciliation")
}

var shareGlobalOwners = listGlobalSMBOwnership

func recoverShareBatch(entries map[string]*shareEntry) {
	globalSMB.recoverBatch(entries, shareGlobalOwners)
}

// Every non-absent journal for a UNC participates, including uncertain ones.
// An unverifiable member blocks the entire group, not just that member.
func (m *globalManager) recoverBatch(entries map[string]*shareEntry, owners func() ([]globalRequest, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*globalEntry)
	}
	groups := make(map[string][]*shareEntry)
	for _, e := range entries {
		if e.intent.Transport == "smb-tcp" && e.intent.State != "absent" {
			key := strings.ToLower(e.intent.Source)
			groups[key] = append(groups[key], e)
		} else if e.intent.State != "absent" {
			fmt.Fprintln(os.Stderr, "share recovery requires reconciliation")
		}
	}
	if len(groups) == 0 {
		return
	}
	records, err := owners()
	for key, group := range groups {
		blocked := err != nil
		first := group[0].intent
		var owner globalRequest
		matches := 0
		for _, candidate := range records {
			if strings.EqualFold(candidate.Remote, first.Source) {
				owner = candidate
				matches++
			}
		}
		if matches != 1 || owner.Key != first.MappingKey || owner.Token != first.MappingToken || owner.Port != first.Port {
			blocked = true
		}
		for _, e := range group {
			r := e.intent
			if r.State != "mounted" || r.LinkIndex == 0 || r.MappingKey != first.MappingKey || r.MappingToken != first.MappingToken || r.MappingFingerprint != first.MappingFingerprint || r.Port != first.Port {
				blocked = true
				continue
			}
			volume, index, linkErr := m.ops.linkIdentity(r.Path, r.Source)
			if linkErr != nil || volume != r.LinkVolume || index != r.LinkIndex {
				blocked = true
			}
			for _, other := range entries {
				if other != e && other.intent.State != "absent" && pathsOverlap(sharePath(other.intent.Path), sharePath(r.Path)) {
					blocked = true
				}
			}
		}
		if !blocked && m.ops.verify(owner) != nil {
			blocked = true
		}
		ge := &globalEntry{refs: len(group), fingerprint: first.MappingFingerprint, owner: owner, blocked: blocked}
		m.entries[key] = ge
		if blocked {
			fmt.Fprintln(os.Stderr, "SMB share recovery requires reconciliation")
			continue
		}
		for _, e := range group {
			e.cleanup = m.cleanup(key, ge, e.intent.Path, e.intent.Source, &e.intent)
		}
	}
}
