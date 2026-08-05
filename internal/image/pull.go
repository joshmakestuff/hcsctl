//go:build windows

package image

import (
	"crypto/sha256"
	"encoding/hex"
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

func pull(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--ref", "--store"); err != nil {
		return cli.Usage, err
	}
	ref, err := a.Require("--ref")
	if err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}

	parsed, err := name.ParseReference(ref)
	if err != nil {
		return cli.Usage, cli.Usagef("%v", err)
	}

	e.Progress("ref:   %s", parsed)
	e.Progress("store: %s", st.Root)

	img, err := remote.Image(parsed, remote.WithPlatform(v1.Platform{OS: "windows", Architecture: "amd64"}))
	if err != nil {
		return cli.Failed, fmt.Errorf("fetch manifest: %w", err)
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return cli.Failed, fmt.Errorf("fetch config: %w", err)
	}

	// Checked against the image's OWN config, not the manifest-list entry that advertised it.
	// A pull by digest never passes through platform selection at all, so the index entry
	// cannot be relied on to have gated anything.
	if cfg.OS != "windows" || cfg.Architecture != "amd64" {
		return cli.Failed, fmt.Errorf("image declares %s/%s, not windows/amd64", cfg.OS, cfg.Architecture)
	}
	e.Progress("config: windows/amd64 os.version=%s", cfg.OSVersion)

	layers, err := img.Layers()
	if err != nil {
		return cli.Failed, fmt.Errorf("read layers: %w", err)
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
			return cli.Failed, fmt.Errorf("layer %d digest: %w", i, err)
		}
		diffID, err := l.DiffID()
		if err != nil {
			return cli.Failed, fmt.Errorf("layer %d diffID: %w", i, err)
		}

		blob := st.BlobPath(dig.Hex)
		if err := os.MkdirAll(filepath.Dir(blob), 0o755); err != nil {
			return cli.Failed, err
		}

		if fi, err := os.Stat(blob); err == nil {
			e.Progress("  layer %d/%d %s present (%d MB)", i+1, len(layers), dig, fi.Size()/(1024*1024))
			total += fi.Size()
		} else {
			rc, err := l.Compressed()
			if err != nil {
				return cli.Failed, fmt.Errorf("layer %d download: %w", i, err)
			}
			n, err := writeVerified(blob, rc, dig.Hex)
			rc.Close()
			if err != nil {
				return cli.Failed, fmt.Errorf("layer %d download: %w", i, err)
			}
			e.Progress("  layer %d/%d %s %d MB", i+1, len(layers), dig, n/(1024*1024))
			total += n
		}

		rec.LayerDigests = append(rec.LayerDigests, dig.String())
		rec.DiffIDs = append(rec.DiffIDs, diffID.String())
	}

	if err := st.WriteRecord(ref, rec); err != nil {
		return cli.Failed, fmt.Errorf("write record: %w", err)
	}

	res := pullResult{
		OK: true, Command: "image pull", Ref: parsed.String(), Store: st.Root,
		OSVersion: cfg.OSVersion, Layers: len(layers), Digests: rec.LayerDigests, Bytes: total,
	}
	e.Result(res, func() {
		fmt.Printf("pulled %d layer(s), %d MB\nrecord: %s\n", res.Layers, res.Bytes/(1024*1024), st.RecordPath(ref))
	})
	return cli.OK, nil
}

// writeVerified streams to disk and refuses to keep bytes whose digest does not match, so a
// truncated or substituted blob never lands in the store under a name that claims otherwise.
func writeVerified(path string, r io.Reader, wantHex string) (int64, error) {
	tmp := path + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		os.Remove(tmp)
		return 0, fmt.Errorf("digest mismatch: got sha256:%s want sha256:%s", got, wantHex)
	}
	return n, os.Rename(tmp, path)
}
