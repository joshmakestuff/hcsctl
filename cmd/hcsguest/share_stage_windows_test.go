//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStagedLinkCrashRecovery(t *testing.T) {
	for _, stop := range []int{2, 3, 4} {
		t.Run(string(rune('0'+stop)), func(t *testing.T) {
			root := t.TempDir()
			r := shareIntent{Path: filepath.Join(root, "mount"), Source: `\\server\share`}
			var durable shareIntent
			writes := 0
			err := publishStagedLink(&r, func() error {
				writes++
				if writes == stop {
					return errors.New("crash")
				}
				durable = r
				return nil
			})
			if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				if r.StageIndex != 0 {
					_ = removeStage(r)
				}
				t.Skipf("staging requires Windows symlink and directory privileges: %v", err)
			}
			if !errors.Is(err, errShareJournal) {
				t.Fatalf("expected interrupted journal write, got %v", err)
			}
			if err := removeJournalLinks(durable); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if _, err := os.Lstat(r.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("final link remains: %v", err)
			}
		})
	}
}

func TestStagedLinkPreservesDestination(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mount")
	if err := os.WriteFile(path, []byte("unowned"), 0600); err != nil {
		t.Fatal(err)
	}
	r := shareIntent{Path: path, Source: `\\server\share`}
	err := publishStagedLink(&r, func() error { return nil })
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		if r.StageIndex != 0 {
			_ = removeStage(r)
		}
		t.Skipf("staging requires privileges: %v", err)
	}
	if err == nil {
		t.Fatal("replaced existing destination")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "unowned" {
		t.Fatalf("destination changed: %q %v", data, err)
	}
	if err := removeStage(r); err != nil {
		t.Fatal(err)
	}
}
