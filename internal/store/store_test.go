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

// The defect: "a/b:c" and "a_b:c" sanitized to the same filename and overwrote each other.
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

func TestLegacyRecordReadsAndMigrates(t *testing.T) {
	s := testStore(t)
	ref := "mcr.microsoft.com/windows/nanoserver:ltsc2022"
	if err := s.WriteRecord(ref, validRecord(ref)); err != nil {
		t.Fatal(err)
	}
	// Demote it to the legacy key, as a pre-#22 store would have it.
	if err := os.Rename(s.RecordPath(ref), s.legacyRecordPath(ref)); err != nil {
		t.Fatal(err)
	}

	r, err := s.ReadRecord(ref)
	if err != nil {
		t.Fatalf("legacy record did not read: %v", err)
	}
	if r.Ref != ref {
		t.Fatalf("got record for %q", r.Ref)
	}
	if _, err := os.Stat(s.RecordPath(ref)); err != nil {
		t.Fatalf("legacy record was not migrated to the new key: %v", err)
	}
	if _, err := os.Stat(s.legacyRecordPath(ref)); !os.IsNotExist(err) {
		t.Fatalf("legacy file still present after migration")
	}
}

// A legacy record is only trusted for the ref it names: under the old key, "a/b:c" and
// "a_b:c" shared a file, so a lookup for one may find the other's record.
func TestLegacyRecordForDifferentRefIsRejected(t *testing.T) {
	s := testStore(t)
	if err := s.WriteRecord("a/b:c", validRecord("a/b:c")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.RecordPath("a/b:c"), s.legacyRecordPath("a/b:c")); err != nil {
		t.Fatal(err)
	}
	// "a_b:c" resolves to the same legacy file.
	_, err := s.ReadRecord("a_b:c")
	if err == nil {
		t.Fatal("record for a/b:c was returned for a_b:c")
	}
	if os.IsNotExist(err) {
		t.Fatal("wrong-ref legacy record reported as missing rather than ambiguous")
	}
	if !strings.Contains(err.Error(), "a/b:c") {
		t.Fatalf("error does not name the actual owner: %v", err)
	}
}

func TestWriteRecordSupersedesLegacy(t *testing.T) {
	s := testStore(t)
	ref := "x/y:z"
	if err := os.MkdirAll(s.ImagesDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.legacyRecordPath(ref), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteRecord(ref, validRecord(ref)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.legacyRecordPath(ref)); !os.IsNotExist(err) {
		t.Fatal("stale legacy record survived a write; ls would list the ref twice")
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
