//go:build windows

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/windows"
)

func TestWindowsShareRejectsInvalidSource(t *testing.T) {
	for _, source := range []string{"", ".", "..", `a\b`, "a/b", "a:b", "a\x00b"} {
		t.Run(source, func(t *testing.T) {
			cleanup, err := mountManagedShare(&guestproto.Share{Transport: "vsmb", Source: source})
			if err == nil || cleanup != nil {
				t.Fatalf("invalid source accepted: %q", source)
			}
		})
	}
}

func TestBindAvailabilityClassification(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		unavailable bool
	}{
		{"missing dll", windows.ERROR_MOD_NOT_FOUND, true},
		{"missing function", windows.ERROR_PROC_NOT_FOUND, true},
		{"access denied", windows.ERROR_ACCESS_DENIED, false},
		{"invalid parameter", windows.ERROR_INVALID_PARAMETER, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyBindAvailability(fmt.Errorf("load: %w", tc.err))
			if errors.Is(err, errShareTransportUnavailable) != tc.unavailable || !errors.Is(err, tc.err) {
				t.Fatalf("classification: %v", err)
			}
		})
	}
}
func TestWindowsShareUnsupportedTransport(t *testing.T) {
	cleanup, err := mountManagedShare(&guestproto.Share{Transport: "unknown"})
	if !errors.Is(err, errShareNotImplemented) || cleanup != nil {
		t.Fatalf("got %v", err)
	}
}
