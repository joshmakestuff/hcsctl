package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validRecord(ref string) Record {
	d := "sha256:" + strings.Repeat("0", 64)
	return Record{Ref: ref, OSVersion: "10.0.20348.5386", LayerDigests: []string{d}, DiffIDs: []string{d}}
}

// "a/b:c" and "a_b:c" sanitize to the same filename; their records must not collide.
func TestRecordKeysCannotCollide(t *testing.T) {
	s := testStore(t)
	ref1, ref2 := "a/b:c", "a_b:c"
	if s.RecordPath(ref1) == s.RecordPath(ref2) {
		t.Fatalf("distinct refs share a record path: %s", s.RecordPath(ref1))
	}
	if err := s.WriteRecord(ref1, validRecord(ref1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteRecord(ref2, validRecord(ref2)); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{ref1, ref2} {
		r, err := s.ReadRecord(ref)
		if err != nil {
			t.Fatalf("ReadRecord(%q): %v", ref, err)
		}
		if r.Ref != ref {
			t.Fatalf("ReadRecord(%q) returned record for %q", ref, r.Ref)
		}
	}
}

func TestMissingRecordIsNotExist(t *testing.T) {
	s := testStore(t)
	if _, err := s.ReadRecord("never/pulled:it"); !os.IsNotExist(err) {
		t.Fatalf("missing record must surface as IsNotExist, got %v", err)
	}
}

func TestReadRecordValidates(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name string
		json string
	}{
		{"truncated", `{"ref":"r","layerDigests":["` + good + `"`},
		{"empty object", `{}`},
		{"no layers", `{"ref":"r","layerDigests":[],"diffIDs":[]}`},
		{"mismatched arrays", `{"ref":"r","layerDigests":["` + good + `","` + good + `"],"diffIDs":["` + good + `"]}`},
		{"malformed digest", `{"ref":"r","layerDigests":["sha256:xyz"],"diffIDs":["` + good + `"]}`},
		{"digest with traversal", `{"ref":"r","layerDigests":["` + good + `"],"diffIDs":["sha256:..\\..\\evil"]}`},
		{"digest wrong length", `{"ref":"r","layerDigests":["` + good + `"],"diffIDs":["sha256:abc123"]}`},
		{"missing ref", `{"layerDigests":["` + good + `"],"diffIDs":["` + good + `"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			if err := os.MkdirAll(s.ImagesDir(), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.RecordPath("r"), []byte(tc.json), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := s.ReadRecord("r")
			if err == nil {
				t.Fatal("invalid record read back without error")
			}
			if os.IsNotExist(err) {
				t.Fatal("invalid record reported as missing -- callers would say 'pull it first' about a corrupt file")
			}
		})
	}
}
