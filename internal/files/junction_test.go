package files

import (
	"encoding/hex"
	"testing"
)

// capturedMountPointBuffer is the REPARSE_DATA_BUFFER `mklink /J` wrote for a junction to
// E:\tmp\g1-other, captured from a running host in findings.md "SMB bind mounts", G8. The
// pure builder must reproduce it exactly.
const capturedMountPointBuffer = "030000a0500000000000260028001e005c003f003f005c0045003a005c0074006d0070005c00670031002d006f007400680065007200000045003a005c0074006d0070005c00670031002d006f0074006800650072000000"

func TestMountPointReparseData(t *testing.T) {
	got := mountPointReparseData(`E:\tmp\g1-other`)
	want, err := hex.DecodeString(capturedMountPointBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != capturedMountPointBuffer {
		t.Fatalf("buffer mismatch:\n got %s\nwant %s", hex.EncodeToString(got), capturedMountPointBuffer)
	}
	if len(got) != len(want) {
		t.Fatalf("length %d, want %d", len(got), len(want))
	}
}
