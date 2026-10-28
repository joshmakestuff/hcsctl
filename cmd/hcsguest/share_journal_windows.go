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

// BootIdentity creation establishes this volatile parent in HKLM\HARDWARE.
func (registryShareJournal) key(access uint32) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `HARDWARE\hcsctl\hcsguest`, access)
	return k, err
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
	return k.SetBinaryValue("ShareJournal", b)
}
