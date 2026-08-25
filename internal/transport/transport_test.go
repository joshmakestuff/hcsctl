//go:build windows

package transport

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
)

// buildTar assembles an OCI-shaped layer tar in memory. Entries carry the
// MSWINDOWS.fileattr PAX field backuptar.FileInfoFromHeader reads.
type tarEntry struct {
	name     string
	dir      bool
	link     string // hardlink target when set
	whiteout bool
	body     string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	mtime := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:       e.name,
			Mode:       0o644,
			ModTime:    mtime,
			AccessTime: mtime,
			ChangeTime: mtime,
			Format:     tar.FormatPAX,
			PAXRecords: map[string]string{},
		}
		switch {
		case e.whiteout:
			hdr.Typeflag = tar.TypeReg
		case e.link != "":
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = e.link
		case e.dir:
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.PAXRecords["MSWINDOWS.fileattr"] = "16" // FILE_ATTRIBUTE_DIRECTORY
		default:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.body))
			hdr.PAXRecords["MSWINDOWS.fileattr"] = "32" // FILE_ATTRIBUTE_ARCHIVE
		}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var baseEntries = []tarEntry{
	{name: "Files", dir: true},
	{name: "Files/app", dir: true},
	{name: "Files/app/hello.txt", body: "hello transport"},
	{name: "Files/app/link.txt", link: "Files/app/hello.txt"},
}

func stage(t *testing.T, entries []tarEntry, parents []string) (string, Stats) {
	t.Helper()
	dir := t.TempDir()
	st, err := Stage(bytes.NewReader(buildTar(t, entries)), dir, parents)
	if err != nil {
		t.Fatal(err)
	}
	return dir, st
}

func TestStageProducesTransportShape(t *testing.T) {
	dir, st := stage(t, baseEntries, nil)

	if st.Files != 1 || st.Dirs != 2 || st.Links != 1 {
		t.Errorf("stats %+v", st)
	}
	// Every dir under Files (Files included) has a sidecar; Hives has the bare
	// attribute word; the five delta hives and tombstones.txt exist.
	for _, want := range []string{
		`Files.$wcidirs$`, `Files\app.$wcidirs$`, `Files\app\hello.txt`, `Files\app\link.txt`,
		`Hives.$wcidirs$`, `tombstones.txt`,
		`Hives\DefaultUser_Delta`, `Hives\Sam_Delta`, `Hives\Security_Delta`,
		`Hives\Software_Delta`, `Hives\System_Delta`,
	} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("missing %s", want)
		}
	}

	b, err := os.ReadFile(filepath.Join(dir, `Hives.$wcidirs$`))
	if err != nil || !bytes.Equal(b, []byte{0x10, 0x20, 0x00, 0x00}) {
		t.Errorf("Hives.$wcidirs$ = % x, err %v", b, err)
	}

	// The blob: LE u32 attribute word first, then the backup stream.
	blob, err := os.ReadFile(filepath.Join(dir, `Files\app\hello.txt`))
	if err != nil {
		t.Fatal(err)
	}
	if attr := binary.LittleEndian.Uint32(blob[:4]); attr != 32 {
		t.Errorf("attribute word %d, want 32", attr)
	}
	if !bytes.Contains(blob, []byte("hello transport")) {
		t.Error("blob lacks the file content")
	}

	// The hardlink is a real NTFS hardlink between the blobs.
	fa, _ := os.Stat(filepath.Join(dir, `Files\app\hello.txt`))
	fb, _ := os.Stat(filepath.Join(dir, `Files\app\link.txt`))
	if !os.SameFile(fa, fb) {
		t.Error("link.txt is not a hardlink of hello.txt")
	}
}

func TestStageWhiteoutsBecomeTombstones(t *testing.T) {
	dir, st := stage(t, []tarEntry{
		{name: "Files", dir: true},
		{name: "Files/app", dir: true},
		{name: "Files/app/.wh.gone.txt", whiteout: true},
	}, nil)
	if st.Tombstones != 1 {
		t.Fatalf("stats %+v", st)
	}
	b, err := os.ReadFile(filepath.Join(dir, "tombstones.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := "\xef\xbb\xbfVersion 1.0\n\\app\\gone.txt\n"
	if string(b) != want {
		t.Errorf("tombstones.txt = %q, want %q", b, want)
	}
}

func TestStageLinkBeforeTarget(t *testing.T) {
	dir, st := stage(t, []tarEntry{
		{name: "Files", dir: true},
		{name: "Files/early-link.txt", link: "Files/late.txt"},
		{name: "Files/late.txt", body: "the target"},
	}, nil)
	if st.Links != 1 || st.CrossLayerLinks != 0 {
		t.Errorf("stats %+v", st)
	}
	fa, _ := os.Stat(filepath.Join(dir, `Files\early-link.txt`))
	fb, _ := os.Stat(filepath.Join(dir, `Files\late.txt`))
	if !os.SameFile(fa, fb) {
		t.Error("deferred link not materialized")
	}
}

func TestStageCrossLayerLinkMaterializesFromParent(t *testing.T) {
	// A parent layer directory carrying the real file.
	parent := t.TempDir()
	if err := os.MkdirAll(filepath.Join(parent, "Files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, `Files\shared.txt`), []byte("parent payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir, st := stage(t, []tarEntry{
		{name: "Files", dir: true},
		{name: "Files/alias.txt", link: "Files/shared.txt"},
	}, []string{parent})
	if st.CrossLayerLinks != 1 {
		t.Fatalf("stats %+v", st)
	}
	blob, err := os.ReadFile(filepath.Join(dir, `Files\alias.txt`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(blob, []byte("parent payload")) {
		t.Error("materialized blob lacks the parent file's content")
	}
	if attr := binary.LittleEndian.Uint32(blob[:4]); attr&0x20 == 0 {
		t.Errorf("attribute word %#x lacks ARCHIVE", attr)
	}
}

func TestStageWithoutFilesEntryFails(t *testing.T) {
	dir := t.TempDir()
	_, err := Stage(bytes.NewReader(buildTar(t, []tarEntry{
		{name: "Files/app", dir: true},
		{name: "Files/app/x.txt", body: "x"},
	})), dir, nil)
	if err == nil || !strings.Contains(err.Error(), "Files.$wcidirs$") {
		t.Errorf("err = %v, want the Files.$wcidirs$ complaint", err)
	}
}

func TestWriteDeltaHiveStubsIsIdempotentAndKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "System_Delta"), []byte("real delta"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteDeltaHiveStubs(dir); err != nil {
		t.Fatal(err)
	}
	if err := WriteDeltaHiveStubs(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "System_Delta"))
	if string(b) != "real delta" {
		t.Error("an existing delta was overwritten")
	}
	for _, hv := range []string{"DefaultUser", "Sam", "Security", "Software"} {
		fi, err := os.Stat(filepath.Join(dir, hv+"_Delta"))
		if err != nil || fi.Size() != 8192 {
			t.Errorf("%s_Delta: %v, size %d", hv, err, fi.Size())
		}
	}
}

// TestRoundTripFixpoint: Stage -> WalkToTar -> Stage again; the second
// transport must carry the same Files payloads and tombstones as the first.
// Needs SeBackupPrivilege for the walk; skipped unelevated.
func TestRoundTripFixpoint(t *testing.T) {
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege}); err != nil {
		t.Skip("needs SeBackupPrivilege (run elevated):", err)
	}
	first, _ := stage(t, append(baseEntries, tarEntry{name: "Files/app/.wh.dead.txt", whiteout: true}), nil)

	var rt bytes.Buffer
	if err := WalkToTar(context.Background(), &rt, first); err != nil {
		t.Fatal(err)
	}

	second := t.TempDir()
	st, err := Stage(bytes.NewReader(rt.Bytes()), second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Tombstones != 1 {
		t.Errorf("tombstone lost in the round trip: %+v", st)
	}

	for _, rel := range []string{`Files\app\hello.txt`, `Files.$wcidirs$`, `Files\app.$wcidirs$`} {
		a, aerr := os.ReadFile(filepath.Join(first, rel))
		b, berr := os.ReadFile(filepath.Join(second, rel))
		if aerr != nil || berr != nil {
			t.Fatalf("%s: %v / %v", rel, aerr, berr)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs after the round trip", rel)
		}
	}
	// The hardlink pair survives as a pair.
	fa, _ := os.Stat(filepath.Join(second, `Files\app\hello.txt`))
	fb, _ := os.Stat(filepath.Join(second, `Files\app\link.txt`))
	if !os.SameFile(fa, fb) {
		t.Error("hardlink pair broken by the round trip")
	}
}

func TestWalkToTarEmitsWhiteoutAfterDirectory(t *testing.T) {
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege}); err != nil {
		t.Skip("needs SeBackupPrivilege (run elevated):", err)
	}
	dir, _ := stage(t, []tarEntry{
		{name: "Files", dir: true},
		{name: "Files/app", dir: true},
		{name: "Files/app/keep.txt", body: "keep"},
		{name: "Files/app/.wh.gone.txt", whiteout: true},
	}, nil)

	var buf bytes.Buffer
	if err := WalkToTar(context.Background(), &buf, dir); err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "Files/app/.wh.gone.txt") {
		t.Errorf("whiteout missing from %v", names)
	}
	// The whiteout follows its directory entry.
	var dirIdx, whIdx int
	for i, n := range names {
		if n == "Files/app" {
			dirIdx = i
		}
		if strings.HasSuffix(n, ".wh.gone.txt") {
			whIdx = i
		}
	}
	if whIdx < dirIdx {
		t.Errorf("whiteout before its directory: %v", names)
	}
}
