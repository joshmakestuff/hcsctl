//go:build windows

package main

import (
	"errors"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
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
func TestWindowsShareUnsupportedTransport(t *testing.T) {
	cleanup, err := mountManagedShare(&guestproto.Share{Transport: "unknown"})
	if !errors.Is(err, errShareNotImplemented) || cleanup != nil {
		t.Fatalf("got %v", err)
	}
}
