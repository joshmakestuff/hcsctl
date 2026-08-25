//go:build windows

// Package layerid derives the GUIDs that name layers in computestorage
// LayerData and in v2 container documents, locally.
//
// The legacy producer was NameToGuid -- a vmcompute.dll export. Measured
// (hcsspike modernlc, guidid cell, 2026-08-25): HCS only requires the id for
// a given layer to be CONSISTENT across ImportLayer parents,
// InitializeWritableLayer, AttachLayerStorageFilter, and the document's
// Storage.Layers -- the derivation itself is free. So the id is an RFC-4122
// v5 (SHA-1 name-based) GUID under a fixed namespace, computed here with no
// DLL involved.
//
// Key discipline: one key per layer, chosen by the caller -- the store uses
// the layer directory's base name (which is the diffID hex for store layers),
// raw-path verbs use the path's base name, and a \\?\Volume{guid} layer uses
// the volume GUID itself.
package layerid

import (
	"crypto/sha1"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/computestorage"
)

// namespace is the fixed v5 namespace for hcsctl layer ids. Arbitrary but
// permanent: changing it orphans every imported layer's identity.
var namespace = []byte{
	0x3c, 0x9f, 0x1e, 0x42, 0x7a, 0x55, 0x4d, 0x08,
	0x9b, 0xd1, 0x6e, 0x0c, 0x27, 0x81, 0x5a, 0xe6,
}

// For derives the layer GUID for a key (RFC-4122 v5 under the hcsctl
// namespace). The key is case-folded: NTFS paths compare case-insensitively,
// and the same layer reached through different casings must not fork ids.
func For(key string) string {
	h := sha1.New()
	h.Write(namespace)
	h.Write([]byte(strings.ToLower(key)))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// volPrefix marks a layer given as a mounted volume rather than a directory.
const volPrefix = `\\?\Volume{`

// ForPath derives the id for a layer named by path: a \\?\Volume{guid} layer
// keeps the volume's own GUID (the volume identity IS the layer identity);
// anything else keys on the path's base name.
func ForPath(p string) (string, error) {
	if strings.HasPrefix(p, volPrefix) {
		i := strings.Index(p, "}")
		if i < 0 {
			return "", fmt.Errorf(`%s is not a \\?\Volume{guid} path`, p)
		}
		g, err := guid.FromString(p[len(volPrefix):i])
		if err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
		return g.String(), nil
	}
	return For(filepath.Base(strings.TrimSuffix(p, `\`))), nil
}

// DataFor builds the LayerData every computestorage call takes: parents
// topmost first, absolute paths, schema 2.1. An empty parent list is a base
// layer. Topmost-first is the measured order end to end (import, initialize,
// filter attach, document, export).
func DataFor(parentsTopFirst []string) (computestorage.LayerData, error) {
	data := computestorage.LayerData{SchemaVersion: computestorage.Version{Major: 2, Minor: 1}}
	for _, p := range parentsTopFirst {
		id, err := ForPath(p)
		if err != nil {
			return data, err
		}
		data.Layers = append(data.Layers, computestorage.Layer{Id: id, Path: p, PathType: "AbsolutePath"})
	}
	return data, nil
}
