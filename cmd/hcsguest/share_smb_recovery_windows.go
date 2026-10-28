//go:build windows

package main

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// listGlobalSMBOwnership exposes boot-scoped intent to the future coordinator.
// An incomplete or tampered record is an error, never permission to remove.
func listGlobalSMBOwnership() ([]globalRequest, error) {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\hcsctl\GuestSMB`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer base.Close()
	names, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	result := make([]globalRequest, 0, len(names))
	for _, name := range names {
		k, e := registry.OpenKey(base, name, registry.QUERY_VALUE)
		if e != nil {
			return nil, e
		}
		token, _, e1 := k.GetStringValue("Token")
		remote, _, e2 := k.GetStringValue("Remote")
		user, _, e3 := k.GetStringValue("User")
		port, _, e4 := k.GetIntegerValue("Port")
		k.Close()
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(name) != 64 || len(token) != 32 || remote == "" || user == "" || port > 65535 || strings.ContainsAny(name+token, `\/`) {
			return nil, errors.New("incomplete global mapping ownership record")
		}
		result = append(result, globalRequest{Op: "remove", Key: name, Token: token, Remote: remote, User: user, Port: uint32(port)})
	}
	return result, nil
}
