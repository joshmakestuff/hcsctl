package files

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestAliasFor(t *testing.T) {
	if got, want := aliasFor("Default Switch"), "vEthernet (Default Switch)"; got != want {
		t.Fatalf("aliasFor = %q, want %q", got, want)
	}
}

func TestStateRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := State{
		Version:          stateVersion,
		Root:             root,
		Shares:           Shares{ReadWrite: ShareRW, ReadOnly: ShareRO},
		User:             UserName,
		CredentialTarget: CredentialTarget,
		RuleName:         RuleName,
		Networks:         []string{"Default Switch", "LAB"},
	}
	if err := writeState(root, want); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(filepath.Clean(root)); err != nil {
		t.Fatalf("readState: %v", err)
	}
	got, err := readState(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestReadStateMissing(t *testing.T) {
	if _, err := readState(t.TempDir()); err == nil {
		t.Fatal("expected an error for a missing state file")
	}
}
