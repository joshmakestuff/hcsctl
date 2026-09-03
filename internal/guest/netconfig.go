//go:build windows

package guest

import (
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// ApplyNetConfig sends a netconfig request to a VM's agent and returns the guest's post-apply
// attestation. Used by `vm netconfig`.
func ApplyNetConfig(vmid guid.GUID, nc guestproto.NetConfig, timeout time.Duration) (*guestproto.NetConfigResult, error) {
	return call[guestproto.NetConfigResult](vmid, guestproto.Request{
		Protocol:  guestproto.Protocol,
		Verb:      "netconfig",
		NetConfig: &nc,
	}, timeout)
}
