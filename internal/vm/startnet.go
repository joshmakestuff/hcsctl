//go:build windows

package vm

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/guest"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

type startNetworkResult struct {
	Applied   string               `json:"applied"`
	Requested guestproto.NetConfig `json:"requested"`
	Addresses []guestproto.Address `json:"addresses"`
}

func configureStartNetwork(id string, st state, netw *hcn.HostComputeNetwork, timeout time.Duration) (startNetworkResult, error) {
	addrs, err := addressesOf(st.EndpointID)
	if err != nil {
		return startNetworkResult{}, fmt.Errorf("reading endpoint %s: %w", st.EndpointID, err)
	}
	nc, err := newNetConfig(addrs, netw, "", st.DNS)
	if err != nil {
		return startNetworkResult{}, err
	}
	vmid, _ := guid.FromString(id)
	if err = waitForGuestAgent(vmid, timeout); err != nil {
		return startNetworkResult{}, err
	}
	res, err := guest.ApplyNetConfig(vmid, nc, timeout)
	if err != nil {
		return startNetworkResult{}, fmt.Errorf("configuring guest network: %w", err)
	}
	if !guestHasAddress(res.Addresses, addrs[0]) {
		return startNetworkResult{}, fmt.Errorf("guest did not attest endpoint address %s", addrs[0])
	}
	return startNetworkResult{Applied: res.Applied, Requested: nc, Addresses: res.Addresses}, nil
}

func waitForGuestAgent(vmid guid.GUID, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		attempt := 10 * time.Second
		if remaining < attempt {
			attempt = remaining
		}
		if _, err := guest.ReadInfo(vmid, attempt); err == nil {
			return nil
		} else {
			last = err
		}
		if time.Until(deadline) > time.Second {
			time.Sleep(time.Second)
		}
	}
	return fmt.Errorf("guest agent did not become available within %s: %w", timeout, last)
}

func guestHasAddress(addrs []guestproto.Address, expected string) bool {
	want, err := netip.ParsePrefix(expected)
	if err != nil {
		return false
	}
	for _, ad := range addrs {
		got, err := netip.ParsePrefix(ad.Address)
		if err == nil && got.Addr() == want.Addr() {
			return true
		}
	}
	return false
}

// guestIPv4Addresses returns only guest evidence. When HCN allocated an address, it is an
// identity to match, never an answer returned on its own.
func guestIPv4Addresses(addrs []guestproto.Address, expected []string) []string {
	out := []string{}
	for _, ad := range addrs {
		p, err := netip.ParsePrefix(ad.Address)
		if err != nil || !p.Addr().Is4() || p.Addr().IsLoopback() {
			continue
		}
		if len(expected) > 0 && !guestHasAddress([]guestproto.Address{ad}, expected[0]) {
			continue
		}
		out = append(out, ad.Address)
	}
	return out
}
