//go:build windows

package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

type pullResult struct {
	OK        bool     `json:"ok"`
	Command   string   `json:"command"`
	Ref       string   `json:"ref"`
	Store     string   `json:"store"`
	OSVersion string   `json:"osVersion"`
	Layers    int      `json:"layers"`
	Digests   []string `json:"layerDigests"`
	Bytes     int64    `json:"bytes"`
}

func pull(ref, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}

	parsed, err := name.ParseReference(ref)
	if err != nil {
		return cli.Usagef("%v", err)
	}

	e.Progress("ref:   %s", parsed)
	e.Progress("store: %s", st.Root)

	img, err := remote.Image(parsed, remote.WithPlatform(v1.Platform{OS: "windows", Architecture: "amd64"}))
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	// Checked against the image's OWN config, not the manifest-list entry that advertised it.
	// A pull by digest never passes through platform selection at all, so the index entry
	// cannot be relied on to have gated anything.
	if cfg.OS != "windows" || cfg.Architecture != "amd64" {
		return fmt.Errorf("image declares %s/%s, not windows/amd64", cfg.OS, cfg.Architecture)
	}
	e.Progress("config: windows/amd64 os.version=%s", cfg.OSVersion)

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}

	rec := store.Record{
		Ref:       parsed.String(),
		OSVersion: cfg.OSVersion,
		PulledUTC: time.Now().UTC().Format(time.RFC3339),
	}
	var total int64

	for i, l := range layers {
		dig, err := l.Digest()
		if err != nil {
			return fmt.Errorf("layer %d digest: %w", i, err)
		}
		diffID, err := l.DiffID()
		if err != nil {
			return fmt.Errorf("layer %d diffID: %w", i, err)
		}

		blob := st.BlobPath(dig.Hex)
		if err := os.MkdirAll(filepath.Dir(blob), 0o755); err != nil {
			return err
		}

		n, downloaded, err := ensureBlob(blob, dig.Hex, l.Compressed)
		if err != nil {
			return fmt.Errorf("layer %d download: %w", i, err)
		}
		if downloaded {
			e.Progress("  layer %d/%d %s %d MB", i+1, len(layers), dig, n/(1024*1024))
		} else {
			e.Progress("  layer %d/%d %s verified (%d MB)", i+1, len(layers), dig, n/(1024*1024))
		}
		total += n

		rec.LayerDigests = append(rec.LayerDigests, dig.String())
		rec.DiffIDs = append(rec.DiffIDs, diffID.String())
	}

	if err := st.WriteRecord(ref, rec); err != nil {
		return fmt.Errorf("write record: %w", err)
	}

	res := pullResult{
		OK: true, Command: "image pull", Ref: parsed.String(), Store: st.Root,
		OSVersion: cfg.OSVersion, Layers: len(layers), Digests: rec.LayerDigests, Bytes: total,
	}
	e.Result(res, func() {
		fmt.Printf("pulled %d layer(s), %d MB\nrecord: %s\n", res.Layers, res.Bytes/(1024*1024), st.RecordPath(ref))
	})
	return nil
}

// writeVerified streams to a unique temp file, refuses to keep bytes whose digest does not
// match, and atomically publishes on success. The temp is unique per writer, so concurrent
// pulls of the same digest never interleave; concurrent writers hold identical verified bytes
// and converge on the same destination.
func writeVerified(path string, r io.Reader, wantHex string) (int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".partial-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		return 0, fmt.Errorf("digest mismatch: got sha256:%s want sha256:%s", got, wantHex)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		// Concurrent writers publish identical verified bytes to the same destination, so a
		// Windows rename collision means another writer already holds it. That writer's rename
		// briefly locks the destination; retry the verification until it reads back clean.
		for range 100 {
			if m, verr := blobSizeVerified(path, wantHex); verr == nil {
				return m, nil
			}
			time.Sleep(time.Millisecond)
		}
		return 0, err
	}
	return n, nil
}

var errCorruptBlob = errors.New("cached blob digest mismatch")

// blobSizeVerified returns the size of path when its content hashes to wantHex. Missing files
// wrap os.ErrNotExist; a mismatched digest wraps errCorruptBlob.
func blobSizeVerified(path, wantHex string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		return 0, fmt.Errorf("%w: got sha256:%s want sha256:%s", errCorruptBlob, got, wantHex)
	}
	return n, nil
}

// ensureBlob makes path hold a verified blob for wantHex. An existing matching blob is
// reported as present; a missing or corrupt blob is downloaded through dl and atomically
// published. dl is called only when a download is needed and must return a fresh reader.
func ensureBlob(path, wantHex string, dl func() (io.ReadCloser, error)) (size int64, downloaded bool, err error) {
	if n, err := blobSizeVerified(path, wantHex); err == nil {
		return n, false, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errCorruptBlob) {
		return 0, false, err
	}
	rc, err := dl()
	if err != nil {
		return 0, false, err
	}
	defer rc.Close()
	n, err := writeVerified(path, rc, wantHex)
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}
