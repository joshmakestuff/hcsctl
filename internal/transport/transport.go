//go:build windows

// Package transport converts between OCI layer tars and the HCS layer
// TRANSPORT format -- the only source shape HcsImportLayer accepts and the
// shape HcsExportLayer produces. No HCS calls live here; the package is pure
// file shuffling, unit-testable and unelevated (staging needs no privileges;
// only the tar side of WalkToTar and parent materialization read with
// SeBackupPrivilege, which the caller holds).
//
// The transport format:
//
//	Files\<path>            blob: LE u32 attribute word + raw Win32 backup
//	                        stream. The blob file's own timestamps carry the
//	                        entry's times; its on-disk attributes stay plain.
//	Files\<dir>             real directory plus a sibling <dir>.$wcidirs$
//	                        sidecar blob, same encoding (Files itself included).
//	Hives\<hive>_Delta      REQUIRED for all five hives, base layers included;
//	                        empty offreg differencing hives satisfy it.
//	Hives.$wcidirs$         bare 4-byte attribute word.
//	tombstones.txt          UTF-8 BOM + "Version 1.0" + LF, then one
//	                        \-prefixed path per line, relative to Files.
//	hardlinks               real NTFS hardlinks between blob files. A tar link
//	                        may precede its target (deferred pass), and may
//	                        target a PARENT layer's file -- materialized as a
//	                        full blob from the parent's real file.
package transport

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
	"golang.org/x/sys/windows"
)

// whiteoutPrefix marks an OCI deletion entry. Local constant so the package
// has no ociwclayer import.
const whiteoutPrefix = ".wh."

// hiveNames are the five registry hives a layer carries deltas for.
var hiveNames = []string{"DefaultUser", "Sam", "Security", "Software", "System"}

// hiveTemplates are empty offreg differencing hives ("OfRg", 8 KB each),
// image-independent. They are the HcsExportLayer product of a layer with no
// registry changes; the programmatic regeneration route is offreg.dll
// ORCreateHive + ORSaveHive.
//
//go:embed hives/*_Delta
var hiveTemplates embed.FS

// Stats reports what a Stage pass wrote.
type Stats struct {
	Files, Dirs, Links, Tombstones int
	CrossLayerLinks                int
	Bytes                          int64
}

// Stage writes the transport form of the OCI layer tar read from r (gzipped
// or plain -- sniffed) into the staging directory. parents are the already
// materialized parent layer directories, topmost first, consulted only to
// materialize hardlinks whose target lives in a parent layer. The UtilityVM
// subtree, when the tar carries one, is always staged: a zero-parent import
// refuses a source without it when present (it wants the boot files).
func Stage(r io.Reader, staging string, parents []string) (Stats, error) {
	var st Stats
	br := bufio.NewReaderSize(r, 1<<20)
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return st, err
		}
		defer gz.Close()
		src = gz
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return st, err
	}

	var tombs []string
	var pendingLinks [][2]string // {target, link} whose target had not been staged yet
	t := tar.NewReader(src)
	hdr, err := t.Next()
	for err == nil {
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		base := path.Base(name)
		switch {
		case strings.HasPrefix(base, whiteoutPrefix):
			target := path.Join(path.Dir(name), strings.TrimPrefix(base, whiteoutPrefix))
			if rel, ok := strings.CutPrefix(target, "Files/"); ok {
				tombs = append(tombs, `\`+filepath.FromSlash(rel))
				st.Tombstones++
			}
			hdr, err = t.Next()
		case hdr.Typeflag == tar.TypeLink:
			linkName := filepath.Join(staging, filepath.FromSlash(name))
			linkTarget := filepath.Join(staging, filepath.FromSlash(hdr.Linkname))
			_ = os.MkdirAll(filepath.Dir(linkName), 0o755)
			if lerr := os.Link(linkTarget, linkName); lerr != nil {
				// A link can precede its target in the tar; defer and retry after the full pass.
				pendingLinks = append(pendingLinks, [2]string{linkTarget, linkName})
			}
			st.Links++
			hdr, err = t.Next()
		default:
			fname, size, info, ferr := backuptar.FileInfoFromHeader(hdr)
			if ferr != nil {
				return st, fmt.Errorf("FileInfoFromHeader(%s): %w", name, ferr)
			}
			isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
			win := filepath.FromSlash(fname)
			underFiles := fname == "Files" || strings.HasPrefix(win, `Files\`) ||
				fname == "UtilityVM" || strings.HasPrefix(win, `UtilityVM\`)
			var next *tar.Header
			switch {
			case underFiles && isDir:
				next, err = writeTransportDir(staging, fname, info, t, hdr)
				st.Dirs++
			case underFiles:
				next, err = writeTransportFile(staging, fname, info, t, hdr)
				st.Files++
			case isDir:
				err = os.MkdirAll(filepath.Join(staging, win), 0o755)
				if err == nil {
					next, err = t.Next()
				}
				st.Dirs++
			default:
				// Hives deltas and anything else outside Files: plain contents.
				next, err = writePlainFile(staging, fname, info, t, hdr)
				st.Files++
			}
			if err != nil && err != io.EOF {
				return st, fmt.Errorf("write %s: %w", fname, err)
			}
			st.Bytes += size
			hdr = next
		}
	}
	if err != io.EOF {
		return st, err
	}

	for _, l := range pendingLinks {
		_ = os.MkdirAll(filepath.Dir(l[1]), 0o755)
		if lerr := os.Link(l[0], l[1]); lerr != nil {
			// The target lives in a parent layer. The export transport
			// materializes such files as full blobs, so synthesize one from
			// the parent's real file: attribute word + BackupRead stream.
			rel, rerr := filepath.Rel(staging, l[0])
			if rerr != nil {
				return st, rerr
			}
			if merr := materializeFromParents(l[1], rel, parents); merr != nil {
				return st, fmt.Errorf("deferred hardlink %s -> %s: %v; parent materialize: %w", l[1], l[0], lerr, merr)
			}
			st.CrossLayerLinks++
		}
	}

	// The export shape always carries these even when empty.
	if err := os.MkdirAll(filepath.Join(staging, "Hives"), 0o755); err != nil {
		return st, err
	}
	p := filepath.Join(staging, "Hives.$wcidirs$")
	if _, serr := os.Stat(p); serr != nil {
		if werr := os.WriteFile(p, []byte{0x10, 0x20, 0x00, 0x00}, 0o644); werr != nil {
			return st, werr
		}
	}
	if _, serr := os.Stat(filepath.Join(staging, "Files.$wcidirs$")); serr != nil {
		return st, fmt.Errorf("tar carried no Files/ directory entry; Files.$wcidirs$ missing")
	}
	if err := WriteDeltaHiveStubs(filepath.Join(staging, "Hives")); err != nil {
		return st, err
	}

	// tombstones.txt: BOM + version line, then the collected deletions.
	tf := "\xef\xbb\xbfVersion 1.0\n"
	if len(tombs) > 0 {
		tf += strings.Join(tombs, "\n") + "\n"
	}
	if err := os.WriteFile(filepath.Join(staging, "tombstones.txt"), []byte(tf), 0o644); err != nil {
		return st, err
	}
	return st, nil
}

// WriteDeltaHiveStubs writes the five empty offreg delta hives into hivesDir
// for any hive not already present. Two callers: Stage (HcsImportLayer
// requires the deltas even for zero-parent imports) and the import pipeline
// after SetupContainerBaseLayer (which strips them, and HcsExportLayer of the
// base later requires them).
func WriteDeltaHiveStubs(hivesDir string) error {
	for _, hv := range hiveNames {
		p := filepath.Join(hivesDir, hv+"_Delta")
		if _, serr := os.Stat(p); serr == nil {
			continue
		}
		b, rerr := hiveTemplates.ReadFile("hives/" + hv + "_Delta")
		if rerr != nil {
			return fmt.Errorf("embedded delta hive template: %w", rerr)
		}
		if werr := os.WriteFile(p, b, 0o644); werr != nil {
			return werr
		}
	}
	return nil
}

// materializeFromParents writes a transport blob at dest for a hardlink whose
// target (rel, e.g. Files\...) is not in this layer's tar: the file lives in a
// parent layer as a real file. Needs SeBackupPrivilege for the parent read.
func materializeFromParents(dest, rel string, parents []string) error {
	for _, p := range parents {
		src := filepath.Join(p, rel)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		f, err := winio.OpenForBackup(src, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, syscall.OPEN_EXISTING)
		if err != nil {
			return fmt.Errorf("open parent %s: %w", src, err)
		}
		defer f.Close()
		bi, err := winio.GetFileBasicInfo(f)
		if err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := out.Write(attrWord(bi.FileAttributes)); err != nil {
			return err
		}
		br := winio.NewBackupFileReader(f, true)
		defer br.Close()
		if _, err := io.Copy(out, br); err != nil {
			return fmt.Errorf("backup stream of %s: %w", src, err)
		}
		bo := *bi
		bo.FileAttributes = windows.FILE_ATTRIBUTE_ARCHIVE
		return winio.SetFileBasicInfo(out, &bo)
	}
	return fmt.Errorf("hardlink target %s not found in any parent layer", rel)
}

func attrWord(attrs uint32) []byte {
	return []byte{byte(attrs), byte(attrs >> 8), byte(attrs >> 16), byte(attrs >> 24)}
}

func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	return `\\?\` + p
}

// writeTransportFile writes a Files\ entry as a transport blob: attribute
// word, then the raw backup stream backuptar reconstructs from the tar entry
// (consuming its alternate-stream entries). Returns io.EOF at archive end.
func writeTransportFile(staging, fname string, info *winio.FileBasicInfo, t *tar.Reader, hdr *tar.Header) (*tar.Header, error) {
	p := filepath.Join(staging, filepath.FromSlash(fname))
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	f, err := os.OpenFile(longPath(p), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return writeBlob(f, info, t, hdr)
}

// writeTransportDir creates the real directory plus its .$wcidirs$ sidecar
// blob (same encoding; a directory's stream carries security and, for
// junctions, reparse data).
func writeTransportDir(staging, fname string, info *winio.FileBasicInfo, t *tar.Reader, hdr *tar.Header) (*tar.Header, error) {
	p := filepath.Join(staging, filepath.FromSlash(fname))
	if err := os.MkdirAll(p, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(longPath(p+".$wcidirs$"), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return writeBlob(f, info, t, hdr)
}

func writeBlob(f *os.File, info *winio.FileBasicInfo, t *tar.Reader, hdr *tar.Header) (*tar.Header, error) {
	if _, err := f.Write(attrWord(info.FileAttributes)); err != nil {
		return nil, err
	}
	next, werr := backuptar.WriteBackupStreamFromTarFile(f, t, hdr)
	if werr != nil && werr != io.EOF {
		return next, werr
	}
	// The blob's own times carry the entry's times; its on-disk attributes
	// must stay plain (the attribute word inside carries the real ones).
	bi := *info
	bi.FileAttributes = windows.FILE_ATTRIBUTE_ARCHIVE
	if serr := winio.SetFileBasicInfo(f, &bi); serr != nil {
		return next, serr
	}
	return next, werr
}

// writePlainFile writes a non-Files entry (Hives deltas) as ordinary contents.
func writePlainFile(staging, fname string, info *winio.FileBasicInfo, t *tar.Reader, hdr *tar.Header) (*tar.Header, error) {
	p := filepath.Join(staging, filepath.FromSlash(fname))
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	f, err := os.OpenFile(longPath(p), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := io.Copy(f, t); err != nil {
		return nil, err
	}
	bi := *info
	bi.FileAttributes = windows.FILE_ATTRIBUTE_ARCHIVE
	if serr := winio.SetFileBasicInfo(f, &bi); serr != nil {
		return nil, serr
	}
	return t.Next()
}
