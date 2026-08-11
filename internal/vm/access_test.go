//go:build windows

package vm

import (
	"errors"
	"slices"
	"testing"
)

func TestGrantPathsWithRollbackRevokesSuccessfulPrefix(t *testing.T) {
	grantErr := errors.New("base grant failed")
	var granted, revoked []string

	rollback, err := grantPathsWithRollback(
		[]string{"child.vhdx", "base.vhdx"},
		func(path string) error {
			granted = append(granted, path)
			if path == "base.vhdx" {
				return grantErr
			}
			return nil
		},
		func(path string) error {
			revoked = append(revoked, path)
			return nil
		},
	)

	if rollback != nil {
		t.Fatal("rollback returned after partial grant failure")
	}
	if !errors.Is(err, grantErr) {
		t.Fatalf("error = %v, want grant failure", err)
	}
	if !slices.Equal(granted, []string{"child.vhdx", "base.vhdx"}) {
		t.Fatalf("granted = %v", granted)
	}
	if !slices.Equal(revoked, []string{"child.vhdx"}) {
		t.Fatalf("revoked = %v, want successful prefix", revoked)
	}
}

func TestGrantPathsWithRollbackRevokesAllGrantsInReverse(t *testing.T) {
	revokeErr := errors.New("base revoke failed")
	var revoked []string

	rollback, err := grantPathsWithRollback(
		[]string{"child.vhdx", "base.vhdx"},
		func(string) error { return nil },
		func(path string) error {
			revoked = append(revoked, path)
			if path == "base.vhdx" {
				return revokeErr
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("granting access: %v", err)
	}

	if err := rollback(); !errors.Is(err, revokeErr) {
		t.Fatalf("rollback error = %v, want base revoke failure", err)
	}
	if !slices.Equal(revoked, []string{"base.vhdx", "child.vhdx"}) {
		t.Fatalf("revoked = %v, want every grant in reverse", revoked)
	}
}
