//go:build windows

package cim

import (
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

// mountNamespace is the fixed namespace for deriving a mount volume GUID from a CIM's
// identity (V5). Deterministic so a caller that lost the mount result -- or a crashed
// script -- can recompute the volume from the CIM path alone: cim unmount accepts the same
// --cim/--block addressing mount does.
var mountNamespace = guid.GUID{
	Data1: 0x8a7c5c44, Data2: 0x31d0, Data3: 0x4a9f,
	Data4: [8]byte{0x9b, 0x0e, 0x2f, 0x61, 0x84, 0xcd, 0x5a, 0x27},
}

// mountGUID derives the volume GUID for a CIM identity. The identity is lowercased first:
// Windows paths are case-insensitive, so two spellings of the same CIM must derive the
// same volume.
func mountGUID(identity string) (guid.GUID, error) {
	return guid.NewV5(mountNamespace, []byte(strings.ToLower(identity)))
}

// cimIdentity is the canonical identity string a mount GUID is derived from: the absolute
// path for a standard CIM, blockPath::name for a block CIM (:: matching the --source
// spelling).
func cimIdentity(cimPath string) (string, error) {
	abs, err := filepath.Abs(cimPath)
	if err != nil {
		return "", cli.Usagef("--cim %s: %v", cimPath, err)
	}
	return abs, nil
}

func blockIdentity(b *cimfs.BlockCIM) (string, error) {
	abs := b.BlockPath
	if !isDevicePath(b.BlockPath) {
		var err error
		if abs, err = filepath.Abs(b.BlockPath); err != nil {
			return "", cli.Usagef("--block %s: %v", b.BlockPath, err)
		}
	}
	return abs + "::" + b.CimName, nil
}

// isDevicePath reports the raw-device spelling. Everything else is treated as a
// single-file block CIM: the two on-disk shapes hcsshim distinguishes are a raw block
// device and a block-formatted regular file, and \\.\ is how a device is addressed.
func isDevicePath(p string) bool {
	return strings.HasPrefix(p, `\\.\`)
}

// blockCIMFor builds the BlockCIM for a --block/--name pair. An empty name defaults from
// the block path's basename with its extension replaced by .cim (layer.bcim -> layer.cim),
// so a source respelled without a name resolves identically at create, merge and mount
// time. A device path has no useful basename, so it requires the explicit name.
func blockCIMFor(flag, blockPath, name string) (*cimfs.BlockCIM, error) {
	if name == "" {
		var err error
		if name, err = defaultCimName(flag, blockPath); err != nil {
			return nil, err
		}
	}
	t := cimfs.BlockCIMTypeSingleFile
	if isDevicePath(blockPath) {
		t = cimfs.BlockCIMTypeDevice
	}
	return &cimfs.BlockCIM{Type: t, BlockPath: blockPath, CimName: name}, nil
}

func defaultCimName(flag, blockPath string) (string, error) {
	if isDevicePath(blockPath) {
		return "", cli.Usagef("%s %s is a device path -- a CIM name is required (--name or ::name)", flag, blockPath)
	}
	base := filepath.Base(blockPath)
	name := strings.TrimSuffix(base, filepath.Ext(base)) + ".cim"
	if name == ".cim" {
		return "", cli.Usagef("%s %s has no basename to derive a CIM name from", flag, blockPath)
	}
	return name, nil
}

// parseSource parses one --source value: <blockPath>[::<name>]. The separator is ::,
// which cannot occur in a path (a colon is legal only in the drive spec and stream
// suffixes, never doubled), so the last occurrence splits unambiguously.
func parseSource(s string) (*cimfs.BlockCIM, error) {
	blockPath, name := s, ""
	if i := strings.LastIndex(s, "::"); i >= 0 {
		blockPath, name = s[:i], s[i+2:]
		if name == "" {
			return nil, cli.Usagef("--source %s: empty CIM name after ::", s)
		}
	}
	if blockPath == "" {
		return nil, cli.Usagef("--source %s: empty block path", s)
	}
	return blockCIMFor("--source", blockPath, name)
}

// rootHashSize is the CIM verification digest size. pkg/cimfs validates the same length
// but does not export the constant, so the flag owns the check to make a wrong length
// exit 64 instead of a run failure.
const rootHashSize = 32

func parseRootHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, cli.Usagef("--root-hash is not hex: %v", err)
	}
	if len(b) != rootHashSize {
		return nil, cli.Usagef("--root-hash must be %d hex characters (%d bytes), got %d bytes", rootHashSize*2, rootHashSize, len(b))
	}
	return b, nil
}
