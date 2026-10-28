//go:build windows

package main

import (
	"encoding/json"
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type registryShareJournal struct{}

func newShareJournal() shareJournal { return registryShareJournal{} }

// The durable journal must not inherit read access for ordinary users: it
// contains ownership tokens and credential-derived fingerprints.
func (registryShareJournal) key(access uint32) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\hcsctl\GuestShareJournal`, access|windows.WRITE_DAC)
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;KA;;;SY)(A;;KA;;;BA)")
	if err == nil {
		var dacl *windows.ACL
		dacl, _, err = sd.DACL()
		if err == nil {
			err = windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
	}
	if err != nil {
		k.Close()
		return 0, err
	}
	return k, nil
}
func (j registryShareJournal) load() ([]shareIntent, error) {
	k, err := j.key(registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("ShareJournal")
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []shareIntent
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, err
	}
	return records, nil
}
func (j registryShareJournal) save(records []shareIntent) error {
	b, err := json.Marshal(records)
	if err != nil {
		return err
	}
	k, err := j.key(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetBinaryValue("ShareJournal", b); err != nil {
		return err
	}
	return flushShareJournal(k)
}

var regFlushKey = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey")

func flushShareJournal(k registry.Key) error {
	r, _, _ := regFlushKey.Call(uintptr(k))
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}
