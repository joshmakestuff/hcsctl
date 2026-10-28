//go:build windows

package main

import (
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestMountRejectsUnenforcedReadOnly(t *testing.T) {
	_, err := applyMount(&guestproto.Mount{
		UNC: `\\host\share`, Path: `C:\share`, User: "user", ReadOnly: true,
	})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only refusal, got %v", err)
	}
}
