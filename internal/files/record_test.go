package files

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecordRoundTrip(t *testing.T) {
	root := t.TempDir()
	vmID := "11111111-0000-4000-8000-00000000000a"
	if err := os.MkdirAll(filepath.Join(root, vmID), 0o755); err != nil {
		t.Fatal(err)
	}
	want := VMRecord{
		VMID:   vmID,
		Labels: map[string]string{"aspirehcs-apphost-pid": "1234"},
		Exposures: []Exposure{
			{Name: "data-0", Source: `C:\src\data`, Share: ShareRO, ReadOnly: true, ACEAdded: true},
			{Name: "cfg-1", Source: `D:\cfg`, Share: ShareRW, ReadOnly: false, ACEAdded: true},
		},
	}
	if err := writeRecord(root, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRecord(root, vmID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestSourceReferencedElsewhere(t *testing.T) {
	root := t.TempDir()
	a := "aaaaaaaa-0000-4000-8000-00000000000a"
	b := "bbbbbbbb-0000-4000-8000-00000000000b"
	for _, id := range []string{a, b} {
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeRecord(root, VMRecord{VMID: a, Exposures: []Exposure{{Name: "x", Source: `C:\shared`}}})
	writeRecord(root, VMRecord{VMID: b, Exposures: []Exposure{{Name: "y", Source: `C:\Shared`}}}) // case differs

	// b still references C:\shared (case-insensitively), so unexposing a must not revoke.
	if !sourceReferencedElsewhere(root, a, `C:\shared`) {
		t.Fatal("expected the source to be referenced by the other VM")
	}
	// A source only a references is not referenced elsewhere.
	if sourceReferencedElsewhere(root, a, `C:\only-a`) {
		t.Fatal("did not expect an unshared source to be referenced")
	}
}

func TestReservedLabelKeys(t *testing.T) {
	for _, k := range []string{"vmId", "name", "source", "share", "readOnly", "labels", "exposures", "root", "ok", "command"} {
		if !reservedLabelKeys[k] {
			t.Errorf("%q should be a reserved label key", k)
		}
	}
	if reservedLabelKeys["aspirehcs-apphost-pid"] {
		t.Error("an ordinary owner label must not be reserved")
	}
}
