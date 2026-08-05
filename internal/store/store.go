// Package store is the on-disk layout hcsctl owns.
//
//	<root>/blobs/sha256/<hex>     layer blobs, named by their compressed digest
//	<root>/images/<ref>.json      one record per pulled reference
//	<root>/layers/<diffID hex>/   materialized layers, named by diffID
//
// Per-user by default, not %ProgramData%: a machine-wide store would make every pull a shared
// side effect and invite ACL problems on the unelevated path.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Store struct{ Root string }

func New(root string) (*Store, error) {
	if root == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(cache, "hcsctl", "store")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{Root: abs}, nil
}

// Record is what pull writes and import reads.
type Record struct {
	Ref          string   `json:"ref"`
	OSVersion    string   `json:"osVersion"`
	LayerDigests []string `json:"layerDigests"`
	DiffIDs      []string `json:"diffIDs"`
	PulledUTC    string   `json:"pulledUtc"`
}

func (s *Store) BlobPath(digestHex string) string {
	return filepath.Join(s.Root, "blobs", "sha256", digestHex)
}

// LayerPath is keyed by diffID, so the same layer pulled via two references materializes once.
func (s *Store) LayerPath(diffID string) string {
	return filepath.Join(s.Root, "layers", strings.TrimPrefix(diffID, "sha256:"))
}

func (s *Store) ImagesDir() string { return filepath.Join(s.Root, "images") }

// RecordPath sanitizes the reference into a filename. Collisions are possible in principle;
// this is a local store keyed by what the user typed, not a content-addressed index.
func (s *Store) RecordPath(ref string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", "@", "_", "\\", "_").Replace(ref)
	return filepath.Join(s.ImagesDir(), safe+".json")
}

func (s *Store) WriteRecord(ref string, r Record) error {
	if err := os.MkdirAll(s.ImagesDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.RecordPath(ref), b, 0o644)
}

func (s *Store) ReadRecord(ref string) (Record, error) {
	var r Record
	b, err := os.ReadFile(s.RecordPath(ref))
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

// Records lists every record in the store, newest first is not attempted -- callers sort.
func (s *Store) Records() ([]Record, error) {
	entries, err := os.ReadDir(s.ImagesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.ImagesDir(), e.Name()))
		if err != nil {
			// An unreadable record is reported by the caller, never silently skipped into
			// a blank row.
			out = append(out, Record{Ref: e.Name() + " (unreadable)"})
			continue
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			out = append(out, Record{Ref: e.Name() + " (corrupt)"})
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
