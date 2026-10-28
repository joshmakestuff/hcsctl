//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A private sibling directory gives the staged link the destination volume and
// makes its contents attributable even before the link's file ID is recorded.
func stageDirectory(path string) (string, windows.Handle, uint32, uint64, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", 0, 0, 0, err
	}
	stage := filepath.Join(filepath.Dir(path), ".hcsguest-stage-"+hex.EncodeToString(token[:]))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", 0, 0, 0, err
	}
	p, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		return "", 0, 0, 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return "", 0, 0, 0, err
	}
	h, volume, index, err := openStageDirectory(stage)
	return stage, h, volume, index, err
}

func openStageDirectory(path string) (windows.Handle, uint32, uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES|windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return 0, 0, 0, err
	}
	index := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || index == 0 {
		windows.CloseHandle(h)
		return 0, 0, 0, errors.New("invalid staging directory")
	}
	return h, info.VolumeSerialNumber, index, nil
}

func validStage(r shareIntent) bool {
	name := filepath.Base(r.StagePath)
	return filepath.IsAbs(r.StagePath) && filepath.Clean(r.StagePath) == r.StagePath && strings.EqualFold(filepath.Dir(r.StagePath), filepath.Dir(r.Path)) && strings.HasPrefix(name, ".hcsguest-stage-") && len(name) == len(".hcsguest-stage-")+32 && r.StageIndex != 0
}

func removeStage(r shareIntent) error {
	if r.StagePath == "" {
		return nil
	}
	if !validStage(r) {
		return errors.New("invalid staging ownership")
	}
	h, volume, index, err := openStageDirectory(r.StagePath)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	if volume != r.StageVolume || index != r.StageIndex {
		return errors.New("staging directory changed")
	}
	link := filepath.Join(r.StagePath, "link")
	lh, lv, li, err := openOwnedLink(link, r.Source, true)
	if err == nil {
		if r.LinkIndex != 0 && (lv != r.LinkVolume || li != r.LinkIndex) {
			windows.CloseHandle(lh)
			return errors.New("staged link changed")
		}
		disposition := byte(1)
		err = windows.SetFileInformationByHandle(lh, windows.FileDispositionInfo, &disposition, 1)
		windows.CloseHandle(lh)
	}
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	disposition := byte(1)
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1)
}

func publishStagedLink(r *shareIntent, persist func() error) error {
	stage, h, volume, index, err := stageDirectory(r.Path)
	if err != nil {
		return err
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	r.StagePath, r.StageVolume, r.StageIndex, r.LinkPhase = stage, volume, index, "staging"
	if err := persist(); err != nil {
		return errShareJournal
	}
	link := filepath.Join(stage, "link")
	if err := os.Symlink(r.Source, link); err != nil {
		return err
	}
	r.LinkVolume, r.LinkIndex, err = ownedLinkIdentity(link, r.Source)
	if err != nil {
		return err
	}
	r.LinkPhase = "ready"
	if err := persist(); err != nil {
		return errShareJournal
	}
	from, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(r.Path)
	if err != nil {
		return err
	}
	if err := windows.MoveFile(from, to); err != nil {
		return fmt.Errorf("publish link: %w", err)
	}
	r.LinkPhase = "published"
	if err := persist(); err != nil {
		return errShareJournal
	}
	// Close the directory handle before reopening for identity-checked removal.
	windows.CloseHandle(h)
	h = 0
	if err := removeStage(*r); err != nil {
		return err
	}
	r.StagePath, r.StageVolume, r.StageIndex = "", 0, 0
	if err := persist(); err != nil {
		return errShareJournal
	}
	return nil
}
