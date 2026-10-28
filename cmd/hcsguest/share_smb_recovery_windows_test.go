//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestFilterGlobalOwnershipSkipsEmptyKeys(t *testing.T) {
	key := strings.Repeat("a", 64)
	owner := globalRequest{Key: key, Token: strings.Repeat("b", 32), Remote: `\\server\share`, User: "user"}
	got, err := filterGlobalSMBOwnership([]string{"empty", key}, func(name string) (wnetRecord, bool, error) {
		if name == "empty" {
			return wnetRecord{}, false, nil
		}
		return wnetRecord{Owner: owner}, true, nil
	})
	if err != nil || len(got) != 1 || got[0] != owner {
		t.Fatalf("owners: %+v, %v", got, err)
	}
}
