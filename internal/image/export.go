//go:build windows

package image

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	hcsshim "github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/computestorage"
	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

// Layer export route, measured on host 26200 (hcsspike/exportprobe/expmat, 2026-08-25,
// three images, ltsc2022 and ltsc2025 layouts):
//
//   - Base layer (no parents): ociwclayer.ExportLayerToTar -- hcsshim's Go base-layer reader
//     walks the directory itself; vmcompute is never called.
//   - Every higher layer: the legacy vmcompute.ExportLayer that ExportLayerToTar wraps fails
//     ERROR_PATH_NOT_FOUND (0x3) on the layer directly above the base -- consistently, across
//     images and layouts, independent of destination, HomeDir shape, SeSecurityPrivilege, and
//     prepared-state. computestorage.HcsExportLayer exports every layer, and its transport
//     directory is the same format as the legacy product (Files as backup streams with a
//     4-byte attribute word, .$wcidirs$ sidecars for directories, tombstones.txt, Hives).
//     Higher layers therefore go through HcsExportLayer, and the transport directory is
//     walked exactly the way hcsshim's internal legacyLayerReader walks the legacy product.
//
// A merged-volume manifest comparison (path, kind, size, sha256) of the original chain versus
// a chain re-imported from these tars matches, with the only differences being the
// import-regenerated artifacts the import path itself documents (hives, blank VHDs, BCD).

type exportResult struct {
	OK      bool             `json:"ok"`
	Command string           `json:"command"`
	Ref     string           `json:"ref"`
	Out     string           `json:"out"`
	Layers  []exportLayerDoc `json:"layers"`
}

type exportLayerDoc struct {
	Index  int    `json:"index"`
	DiffID string `json:"diffID"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Sha256 string `json:"sha256"`
}

// tarName makes order and identity explicit in the filename: index, then the DiffID with the
// digest-algorithm separator flattened so the name is a single path segment.
func tarName(index int, diffID string) string {
	return fmt.Sprintf("%03d-%s.tar", index, strings.ReplaceAll(diffID, ":", "-"))
}

func exportImage(ref, out, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Usagef("no record for %s in %s -- pull it first", ref, st.Root)
		}
		return err
	}

	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absOut); err == nil {
		return cli.Usagef("output already exists: %s -- export never overwrites", absOut)
	}

	// Export only reads layers. SeBackupPrivilege is the whole requirement; SeRestore and the
	// BUILTIN\Administrators group check belong to import's ProcessBaseLayer, not here.
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege}); err != nil {
		return fmt.Errorf("enable backup privilege (rerun elevated): %w", err)
	}
	e.Progress("privilege: SeBackupPrivilege enabled")

	dirs := make([]string, len(rec.DiffIDs))
	for i, diffID := range rec.DiffIDs {
		dirs[i] = st.LayerPath(diffID)
		// The same presence test import uses for "already materialized": the Files tree is the
		// last thing extraction produces.
		if _, err := os.Stat(filepath.Join(dirs[i], "Files")); err != nil {
			return fmt.Errorf("layer %d/%d (%s) is not materialized -- run image import --ref %s",
				i+1, len(rec.DiffIDs), dirs[i], rec.Ref)
		}
	}

	// Stage in a sibling of the destination so the final publish is one rename on the same
	// volume; a failure mid-export removes the staging dir and leaves no partial output.
	staging, err := os.MkdirTemp(filepath.Dir(absOut), filepath.Base(absOut)+".staging-")
	if err != nil {
		return fmt.Errorf("create staging next to %s: %w", absOut, err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()

	ctx := context.Background()
	layers := make([]exportLayerDoc, 0, len(dirs))
	for i, dir := range dirs {
		name := tarName(i, rec.DiffIDs[i])
		e.Progress("  layer %d/%d -> %s", i+1, len(dirs), name)
		start := time.Now()

		tarPath := filepath.Join(staging, name)
		f, err := os.Create(tarPath)
		if err != nil {
			return err
		}
		cw := &countHashWriter{w: f, h: sha256.New()}
		if i == 0 {
			err = ociwclayer.ExportLayerToTar(ctx, cw, dir, nil)
		} else {
			var transport string
			transport, err = os.MkdirTemp(staging, fmt.Sprintf(".transport-%03d-", i))
			if err == nil {
				err = exportUpperLayer(ctx, cw, dir, dirs[:i], transport)
				_ = os.RemoveAll(transport)
			}
		}
		f.Close()
		if err != nil {
			return fmt.Errorf("export layer %d/%d (%s): %w", i+1, len(dirs), rec.DiffIDs[i], err)
		}

		e.Progress("     %d MB in %s", cw.n/(1024*1024), time.Since(start).Round(time.Millisecond))
		layers = append(layers, exportLayerDoc{
			Index:  i,
			DiffID: rec.DiffIDs[i],
			Path:   name,
			Bytes:  cw.n,
			Sha256: "sha256:" + hex.EncodeToString(cw.h.Sum(nil)),
		})
	}

	if err := os.Rename(staging, absOut); err != nil {
		return fmt.Errorf("publish %s -> %s: %w", staging, absOut, err)
	}
	published = true

	res := exportResult{OK: true, Command: "image export", Ref: rec.Ref, Out: absOut, Layers: layers}
	e.Result(res, func() {
		fmt.Printf("exported %d layer(s) of %s to %s\n", len(layers), rec.Ref, absOut)
		for _, l := range layers {
			fmt.Printf("  %s  %d MB\n", l.Path, l.Bytes/(1024*1024))
		}
	})
	return nil
}

// exportUpperLayer exports one non-base layer to a tar stream. The activate/prepare/unprepare
// dance mirrors what ociwclayer.ExportLayerToTar does internally: it initializes the layer,
// and a layer mounted elsewhere fails at PrepareLayer with an actionable error instead of
// exporting garbage. Parents are ordered lowest to highest, the order ociwclayer documents.
func exportUpperLayer(ctx context.Context, w io.Writer, layer string, parentsLowestFirst []string, transport string) error {
	info := hcsshim.DriverInfo{}
	if err := hcsshim.ActivateLayer(info, layer); err != nil {
		return fmt.Errorf("activate layer: %w", err)
	}
	defer func() { _ = hcsshim.DeactivateLayer(info, layer) }()
	if err := hcsshim.PrepareLayer(info, layer, parentsLowestFirst); err != nil {
		return fmt.Errorf("prepare layer (is it mounted elsewhere?): %w", err)
	}
	if err := hcsshim.UnprepareLayer(info, layer); err != nil {
		return fmt.Errorf("unprepare layer: %w", err)
	}

	if err := csExportLayer(ctx, layer, transport, parentsLowestFirst); err != nil {
		return fmt.Errorf("computestorage export: %w", err)
	}
	return walkTransportToTar(ctx, w, transport)
}

// csExportLayer is computestorage.ExportLayer with the parent descriptors built the way the
// probe measured them: NameToGuid of the directory name, absolute paths, lowest first.
func csExportLayer(ctx context.Context, layer, dest string, parentsLowestFirst []string) error {
	data := computestorage.LayerData{SchemaVersion: computestorage.Version{Major: 2, Minor: 1}}
	for _, p := range parentsLowestFirst {
		g, err := hcsshim.NameToGuid(filepath.Base(p))
		if err != nil {
			return err
		}
		data.Layers = append(data.Layers, computestorage.Layer{
			Id:       g.ToString(),
			Path:     p,
			PathType: "AbsolutePath",
		})
	}
	return computestorage.ExportLayer(ctx, layer, dest, data, computestorage.ExportLayerOptions{})
}

// countHashWriter counts bytes and hashes what passes through, so the result document carries
// both without a second pass over multi-gigabyte tars.
type countHashWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countHashWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if n > 0 {
		c.h.Write(b[:n])
		c.n += int64(n)
	}
	return n, err
}

// ---------- transport format -> tar ----------
//
// walkTransportToTar mirrors hcsshim's internal/wclayer legacyLayerReader combined with
// pkg/ociwclayer's writeTarFromLayer: same entry order (lexical walk, tombstones emitted right
// after their directory), same skips, same per-entry handling, same tar shapes. The transport
// directory may come from HcsExportLayer or from the legacy ExportLayer; the formats agree.

// readTombstones parses the transport tombstones.txt. Absent means the layer deletes nothing;
// a present-but-malformed file is an error.
func readTombstones(root string) (map[string][]string, error) {
	ts := make(map[string][]string)
	tf, err := os.Open(filepath.Join(root, "tombstones.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return ts, nil
		}
		return nil, err
	}
	defer tf.Close()
	s := bufio.NewScanner(tf)
	if !s.Scan() || s.Text() != "\xef\xbb\xbfVersion 1.0" {
		return nil, errors.New("invalid tombstones.txt")
	}
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, `\`) {
			return nil, fmt.Errorf("invalid tombstone line %q", line)
		}
		t := filepath.Join("Files", line[1:])
		ts[filepath.Dir(t)] = append(ts[filepath.Dir(t)], t)
	}
	return ts, s.Err()
}

func hasPathPrefix(p, prefix string) bool {
	return strings.HasPrefix(p, prefix) && len(p) > len(prefix) && p[len(prefix)] == '\\'
}

// findBackupStreamSize is hcsshim's: the size of the BackupData component of a raw stream.
func findBackupStreamSize(r io.Reader) (int64, error) {
	br := winio.NewBackupStreamReader(r)
	for {
		hdr, err := br.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return 0, err
		}
		if hdr.Id == winio.BackupData {
			return hdr.Size, nil
		}
	}
}

type transportEntry struct {
	path string // absolute
	rel  string // native separators, relative to the transport root
	fi   os.FileInfo
	tomb string // set for synthesized tombstones: native relative target
}

func walkTransportToTar(ctx context.Context, w io.Writer, root string) error {
	ts, err := readTombstones(root)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}

	var entries []transportEntry
	err = filepath.Walk(rootAbs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// hcsshim skips the recycle bin (unicode names in it break Lstat); skips the root,
		// tombstones.txt, and the .$wcidirs$ sidecars, which are consumed via their directory.
		if strings.EqualFold(p, filepath.Join(rootAbs, `Files\$Recycle.Bin`)) && info.IsDir() {
			return filepath.SkipDir
		}
		if p == rootAbs || p == filepath.Join(rootAbs, "tombstones.txt") || strings.HasSuffix(p, ".$wcidirs$") {
			return nil
		}
		rel, err := filepath.Rel(rootAbs, p)
		if err != nil {
			return err
		}
		entries = append(entries, transportEntry{path: p, rel: rel, fi: info})
		if info.IsDir() {
			for _, t := range ts[rel] {
				entries = append(entries, transportEntry{tomb: t})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	t := tar.NewWriter(w)
	linkRecords := make(map[[16]byte]string)

	for _, ent := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if ent.tomb != "" {
			// Whiteout, shaped exactly like writeTarFromLayer does.
			name := filepath.ToSlash(ent.tomb)
			err := t.WriteHeader(&tar.Header{
				Name: path.Join(path.Dir(name), ociwclayer.WhiteoutPrefix+path.Base(name)),
			})
			if err != nil {
				return err
			}
			continue
		}

		name := filepath.ToSlash(ent.rel)
		openPath := ent.path
		if ent.fi.IsDir() && hasPathPrefix(ent.rel, "Files") {
			// Directory metadata under Files lives in the sidecar.
			openPath += ".$wcidirs$"
		}
		f, err := winio.OpenForBackup(openPath, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, syscall.OPEN_EXISTING)
		if err != nil {
			return fmt.Errorf("open %s: %w", openPath, err)
		}

		fileInfo, err := winio.GetFileBasicInfo(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("file info %s: %w", openPath, err)
		}

		var size int64
		if hasPathPrefix(ent.rel, "Files") {
			// Entries under Files are stored as a 4-byte attribute word followed by the raw
			// backup stream; read both, then rewind to the stream.
			var attr uint32
			if err := binary.Read(f, binary.LittleEndian, &attr); err != nil {
				f.Close()
				return fmt.Errorf("attribute word %s: %w", openPath, err)
			}
			fileInfo.FileAttributes = attr
			if !ent.fi.IsDir() {
				size, err = findBackupStreamSize(f)
				if err != nil {
					f.Close()
					return fmt.Errorf("backup stream size %s: %w", openPath, err)
				}
			}
			if _, err := f.Seek(4, io.SeekStart); err != nil {
				f.Close()
				return err
			}
		} else {
			// Hives, UtilityVM, top-level metadata: ordinary files, streamed on the fly.
			size = ent.fi.Size()
			if ent.rel == "Hives" || ent.rel == "Files" {
				// hcsshim: the Hives directory's file time is non-deterministic from import;
				// take System_Delta's. Tolerate its absence rather than fail the export.
				if g, err := os.Open(filepath.Join(rootAbs, "Hives", "System_Delta")); err == nil {
					if gi, err := winio.GetFileBasicInfo(g); err == nil {
						attr := fileInfo.FileAttributes
						fileInfo = gi
						fileInfo.FileAttributes = attr
					}
					g.Close()
				}
			}
			fileInfo.CreationTime = fileInfo.LastWriteTime
			fileInfo.LastAccessTime = fileInfo.LastWriteTime
		}

		std, err := winio.GetFileStandardInfo(f)
		if err != nil {
			f.Close()
			return err
		}
		if std.NumberOfLinks > 1 {
			id, err := winio.GetFileID(f)
			if err != nil {
				f.Close()
				return err
			}
			if prev, ok := linkRecords[id.FileID]; ok {
				hdr := backuptar.BasicInfoHeader(name, 0, fileInfo)
				hdr.Mode = 0644
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = prev
				if err := t.WriteHeader(hdr); err != nil {
					f.Close()
					return err
				}
				f.Close()
				continue
			}
			linkRecords[id.FileID] = name
		}

		// Under Files the disk content already IS the backup stream: read it raw. Everywhere
		// else, synthesize one with BackupRead.
		var r io.Reader = f
		var br *winio.BackupFileReader
		if !hasPathPrefix(ent.rel, "Files") {
			br = winio.NewBackupFileReader(f, false)
			r = br
		}
		err = backuptar.WriteTarFileFromBackupStream(t, r, name, size, fileInfo)
		if br != nil {
			br.Close()
		}
		f.Close()
		if err != nil {
			return fmt.Errorf("tar %s: %w", name, err)
		}
	}
	return t.Close()
}
