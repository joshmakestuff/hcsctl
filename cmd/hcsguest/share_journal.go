package main

import (
	"path/filepath"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// shareIntent deliberately excludes credentials. A pending record is not proof
// that any native operation completed or that a pathname is safe to remove.
type shareIntent struct {
	BootID             string   `json:"bootId"`
	ID                 string   `json:"id"`
	Generation         uint64   `json:"generation"`
	Path               string   `json:"path"`
	Source             string   `json:"source"`
	Transport          string   `json:"transport"`
	ReadOnly           bool     `json:"readOnly"`
	Port               uint32   `json:"port"`
	UID                int      `json:"uid"`
	GID                int      `json:"gid"`
	MountID            uint64   `json:"mountId,omitempty"`
	RelayPort          uint16   `json:"relayPort,omitempty"`
	LinkVolume         uint32   `json:"linkVolume,omitempty"`
	LinkIndex          uint64   `json:"linkIndex,omitempty"`
	MappingKey         string   `json:"mappingKey,omitempty"`
	MappingToken       string   `json:"mappingToken,omitempty"`
	MappingFingerprint [32]byte `json:"mappingFingerprint,omitempty"`
	Fingerprint        [32]byte `json:"fingerprint"`
	State              string   `json:"state"`
}

type shareJournal interface {
	load() ([]shareIntent, error)
	save([]shareIntent) error
}

func newShareIntent(s *guestproto.Share, bootID string, fingerprint [32]byte) shareIntent {
	return shareIntent{BootID: bootID, ID: s.ID, Generation: s.Generation, Path: s.Path, Source: s.Source, Transport: s.Transport, ReadOnly: s.ReadOnly, Port: s.Port, UID: s.UID, GID: s.GID, Fingerprint: fingerprint, State: "pending"}
}

func (r shareIntent) valid() bool {
	return validBootID(r.BootID) && validShareID(r.ID) && r.Generation != 0 && filepath.IsAbs(r.Path) && filepath.Clean(r.Path) == r.Path && r.Source != "" && r.Transport != "" && r.UID >= 0 && r.GID >= 0 && (r.State == "pending" || r.State == "mounted" || r.State == "absent")
}
