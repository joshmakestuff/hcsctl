//go:build windows

package cim

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"golang.org/x/sys/windows"
)

type walkStats struct {
	Files   int   `json:"files"`
	Dirs    int   `json:"directories"`
	Links   int   `json:"links"`
	Streams int   `json:"streams"`
	Bytes   int64 `json:"bytes"`
}

// writeTree adds the tree under src to the writer: directories and files with their
// security descriptors, reparse points as reparse points (not followed), hard links as
// links, zero-length alternate data streams as streams. The root itself is not added.
//
// Two captures are impossible through public pkg/cimfs and are handled explicitly:
//
//   - A nonzero alternate-data-stream payload is a hard error naming the stream. The
//     writer's Write refuses bytes after CreateAlternateStream (its internal budget is set
//     only by AddFile) and CimCreateFile rejects stream-spelled
//     paths, so the payload cannot be written; failing loudly beats dropping data.
//   - Extended attributes are not captured: nothing public reads them off a live tree.
func writeTree(w *cimfs.CimFsWriter, src string) (walkStats, error) {
	var st walkStats
	// Hard links: first sighting of a multi-link file carries the data, later sightings
	// become links to it. Keyed on (volume serial, file id).
	firstSeen := map[winio.FileIDInfo]string{}

	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == src {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		return addEntry(w, path, rel, &st, firstSeen)
	})
	return st, err
}

func addEntry(w *cimfs.CimFsWriter, path, rel string, st *walkStats, firstSeen map[winio.FileIDInfo]string) error {
	f, err := winio.OpenForBackup(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	defer f.Close()

	bi, err := winio.GetFileBasicInfo(f)
	if err != nil {
		return err
	}
	si, err := winio.GetFileStandardInfo(f)
	if err != nil {
		return err
	}
	sd, err := securityDescriptorOf(f)
	if err != nil {
		return fmt.Errorf("security descriptor of %s: %w", path, err)
	}

	isDir := bi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	isReparse := bi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0

	switch {
	case isReparse:
		// Captured as the reparse point itself, never followed. The data stream of a
		// reparse file is not reachable through a reparse-preserving open, so the entry
		// is metadata plus the reparse buffer.
		rd, err := reparseDataOf(f)
		if err != nil {
			return fmt.Errorf("reparse data of %s: %w", path, err)
		}
		if err := w.AddFile(rel, bi, 0, sd, nil, rd); err != nil {
			return err
		}
		if isDir {
			st.Dirs++
		} else {
			st.Files++
		}
	case isDir:
		if err := w.AddFile(rel, bi, 0, sd, nil, nil); err != nil {
			return err
		}
		st.Dirs++
	default:
		if si.NumberOfLinks > 1 {
			id, err := winio.GetFileID(f)
			if err != nil {
				return err
			}
			if first, seen := firstSeen[*id]; seen {
				if err := w.AddLink(first, rel); err != nil {
					return err
				}
				st.Links++
				return nil
			}
			firstSeen[*id] = rel
		}
		if err := w.AddFile(rel, bi, si.EndOfFile, sd, nil, nil); err != nil {
			return err
		}
		n, err := io.Copy(w, io.LimitReader(f, si.EndOfFile))
		if err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		if n != si.EndOfFile {
			return fmt.Errorf("write %s: %d bytes copied, expected %d", path, n, si.EndOfFile)
		}
		st.Bytes += n
		st.Files++
	}

	if !isReparse {
		if err := addStreams(w, path, rel, st); err != nil {
			return err
		}
	}
	return nil
}

func securityDescriptorOf(f *os.File) ([]byte, error) {
	// Owner, group and DACL only: no SACL, so no SeSecurityPrivilege is required
	// and the walk stays unprivileged.
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length()), nil
}

func reparseDataOf(f *os.File) ([]byte, error) {
	buf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var n uint32
	if err := windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_GET_REPARSE_POINT,
		nil, 0, &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// addStreams records the entry's named alternate data streams. Zero-length streams are
// created; a stream with a payload is the hard error documented on writeTree.
func addStreams(w *cimfs.CimFsWriter, path, rel string, st *walkStats) error {
	streams, err := namedStreams(path)
	if err != nil {
		return fmt.Errorf("enumerate streams of %s: %w", path, err)
	}
	for _, s := range streams {
		if s.size != 0 {
			return fmt.Errorf("%s has alternate data stream %q with %d bytes -- "+
				"stream payloads cannot be written through public hcsshim pkg/cimfs; "+
				"remove the stream or drop the file", path, s.name, s.size)
		}
		if err := w.CreateAlternateStream(rel+":"+s.name, 0); err != nil {
			return err
		}
		st.Streams++
	}
	return nil
}

// FindFirstStreamW/FindNextStreamW are not in x/sys/windows; bound directly --
// documented entry points only, no hcsshim internals copied.
var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW = kernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = kernel32.NewProc("FindNextStreamW")
)

// win32FindStreamData is WIN32_FIND_STREAM_DATA: a LARGE_INTEGER size and a
// MAX_PATH+36 name buffer.
type win32FindStreamData struct {
	size int64
	name [windows.MAX_PATH + 36]uint16
}

type namedStream struct {
	name string
	size int64
}

// namedStreams lists the alternate data streams of a file or directory. The default
// stream ::$DATA is excluded; names come back bare (without the ::$DATA decoration).
func namedStreams(path string) ([]namedStream, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var fsd win32FindStreamData
	// 0 = FindStreamInfoStandard.
	h, _, errno := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&fsd)), 0)
	if windows.Handle(h) == windows.InvalidHandle {
		if errno == windows.ERROR_HANDLE_EOF {
			return nil, nil // no streams at all (directories without ADS)
		}
		return nil, errno
	}
	defer windows.FindClose(windows.Handle(h))

	var streams []namedStream
	for {
		full := windows.UTF16ToString(fsd.name[:])
		// ":name:$DATA"; the anonymous stream is "::$DATA".
		if name, ok := streamName(full); ok {
			streams = append(streams, namedStream{name: name, size: fsd.size})
		}
		r, _, errno := procFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&fsd)))
		if r == 0 {
			if errno == windows.ERROR_HANDLE_EOF {
				return streams, nil
			}
			return nil, errno
		}
	}
}

// streamName extracts the bare stream name from ":name:$DATA"; false for the anonymous
// stream and for non-$DATA stream types (none are expressible in a CIM).
func streamName(full string) (string, bool) {
	if len(full) < 2 || full[0] != ':' {
		return "", false
	}
	rest := full[1:]
	i := len(rest) - len(":$DATA")
	if i <= 0 || rest[i:] != ":$DATA" {
		return "", false
	}
	return rest[:i], true
}
