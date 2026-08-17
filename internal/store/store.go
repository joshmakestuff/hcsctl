// Package store is the on-disk layout hcsctl owns.
//
//	<root>/blobs/sha256/<hex>     layer blobs, named by their compressed digest
//	<root>/images/<ref>.json      one record per pulled reference
//	<root>/layers/<diffID hex>/   materialized layers, named by diffID
//
// Per-user by default.
package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// RecordPath keys a record by the sanitized reference plus a short hash of the raw one, so
// distinct references cannot share a file ("a/b" and "a_b" sanitize identically). The
// sanitized half keeps the directory greppable; the hash half makes the key unambiguous.
func (s *Store) RecordPath(ref string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", "@", "_", "\\", "_").Replace(ref)
	h := sha256.Sum256([]byte(ref))
	return filepath.Join(s.ImagesDir(), fmt.Sprintf("%s-%x.json", safe, h[:8]))
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

// RemoveRecord removes a reference's record. Absence is not an error -- the caller decides
// what a missing record means.
func (s *Store) RemoveRecord(ref string) error {
	if err := os.Remove(s.RecordPath(ref)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReadRecord is the validation boundary for persisted image metadata: every consumer
// indexes LayerDigests alongside DiffIDs and joins digests into store paths, so a record
// that reads back successfully is guaranteed structurally sound. A missing record surfaces
// as os.IsNotExist, which callers turn into "pull it first".
func (s *Store) ReadRecord(ref string) (Record, error) {
	return s.readRecordFile(s.RecordPath(ref))
}

func (s *Store) readRecordFile(path string) (Record, error) {
	var r Record
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("record %s is not valid JSON: %w -- re-pull to rewrite it", path, err)
	}
	if err := r.validate(); err != nil {
		return r, fmt.Errorf("record %s: %w -- re-pull to rewrite it", path, err)
	}
	return r, nil
}

// digestRe is exactly what pull writes. Nothing that matches it can escape the store when
// joined into a blob or layer path -- no separators, no traversal, fixed length.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (r Record) validate() error {
	if r.Ref == "" {
		return errors.New("has no ref")
	}
	if len(r.DiffIDs) == 0 {
		return errors.New("lists no layers")
	}
	if len(r.LayerDigests) != len(r.DiffIDs) {
		return fmt.Errorf("lists %d layerDigests but %d diffIDs", len(r.LayerDigests), len(r.DiffIDs))
	}
	for _, d := range r.LayerDigests {
		if !digestRe.MatchString(d) {
			return fmt.Errorf("malformed layer digest %q", d)
		}
	}
	for _, d := range r.DiffIDs {
		if !digestRe.MatchString(d) {
			return fmt.Errorf("malformed diffID %q", d)
		}
	}
	return nil
}

// Records lists every record in the store, unsorted; callers sort.
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
			// An unreadable record is reported by the caller, never silently skipped.
			out = append(out, Record{Ref: e.Name() + " (unreadable)"})
			continue
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			out = append(out, Record{Ref: e.Name() + " (corrupt)"})
			continue
		}
		if err := r.validate(); err != nil {
			out = append(out, Record{Ref: fmt.Sprintf("%s (invalid: %v)", e.Name(), err)})
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
