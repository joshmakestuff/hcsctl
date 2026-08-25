//go:build windows

package transport

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
)

// WalkToTar writes the OCI layer tar for a transport directory -- the reverse
// of Stage. It mirrors hcsshim's internal legacyLayerReader combined with
// ociwclayer's writeTarFromLayer: same entry order (lexical walk, tombstones
// emitted right after their directory), same skips, same tar shapes. The
// caller holds SeBackupPrivilege for the OpenForBackup reads.
func WalkToTar(ctx context.Context, w io.Writer, root string) error {
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
		// hcsshim skips the recycle bin (unicode names in it break Lstat);
		// skips the root, tombstones.txt, and the .$wcidirs$ sidecars, which
		// are consumed via their directory.
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
				Name: path.Join(path.Dir(name), whiteoutPrefix+path.Base(name)),
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
			// Entries under Files are stored as a 4-byte attribute word
			// followed by the raw backup stream; read both, rewind to the
			// stream.
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
			// Hives, UtilityVM, top-level metadata: ordinary files, streamed
			// on the fly.
			size = ent.fi.Size()
			if ent.rel == "Hives" || ent.rel == "Files" {
				// hcsshim: the Hives directory's file time is
				// non-deterministic from import; take System_Delta's.
				// Tolerate its absence rather than fail the export.
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

		// Under Files the disk content already IS the backup stream: read it
		// raw. Everywhere else, synthesize one with BackupRead.
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

type transportEntry struct {
	path string // absolute
	rel  string // native separators, relative to the transport root
	fi   os.FileInfo
	tomb string // set for synthesized tombstones: native relative target
}

// readTombstones parses the transport tombstones.txt. Absent means the layer
// deletes nothing; a present-but-malformed file is an error.
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

// findBackupStreamSize is hcsshim's: the size of the BackupData component of a
// raw stream.
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
