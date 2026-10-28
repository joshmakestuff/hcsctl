//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type fileShareJournal struct{ dir string }

func newShareJournal() shareJournal { return fileShareJournal{dir: "/run/hcsguest"} }

func (j fileShareJournal) open() (*os.Root, error) {
	if err := os.Mkdir(j.dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(j.dir)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || st.Uid != 0 {
		return nil, errors.New("untrusted share journal directory")
	}
	return os.OpenRoot(j.dir)
}

func (j fileShareJournal) load() ([]shareIntent, error) {
	r, err := j.open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := r.ReadFile("shares.json")
	if errors.Is(err, os.ErrNotExist) {
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

func (j fileShareJournal) save(records []shareIntent) error {
	r, err := j.open()
	if err != nil {
		return err
	}
	defer r.Close()
	b, err := json.Marshal(records)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(j.dir, ".shares-*")
	if err != nil {
		return err
	}
	name := filepath.Base(f.Name())
	defer r.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = r.Rename(name, "shares.json"); err != nil {
		return err
	}
	dir, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
