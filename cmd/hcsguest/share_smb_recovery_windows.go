//go:build windows

package main

import (
	"errors"
	"strings"
)

// Connection records are only candidates; verifyGlobalSMB must also verify the
// current boot, logon session, phase and connected identity.
func listGlobalSMBOwnership() ([]globalRequest, error) {
	store := registryWNetStore{}
	base, err := store.root()
	if err != nil {
		return nil, err
	}
	defer base.Close()
	names, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	return filterGlobalSMBOwnership(names, store.get)
}

func filterGlobalSMBOwnership(names []string, get func(string) (wnetRecord, bool, error)) ([]globalRequest, error) {
	result := make([]globalRequest, 0, len(names))
	for _, name := range names {
		rec, exists, err := get(name)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		if len(name) != 64 || len(rec.Owner.Token) != 32 || rec.Owner.Remote == "" || rec.Owner.User == "" || rec.Owner.Port > 65535 || strings.ContainsAny(name+rec.Owner.Token, `\/`) {
			return nil, errors.New("incomplete global mapping ownership record")
		}
		result = append(result, rec.Owner)
	}
	return result, nil
}
