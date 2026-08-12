//go:build windows

package vm

import (
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
)

func natNetwork() *hcn.HostComputeNetwork {
	return &hcn.HostComputeNetwork{
		Id: "net-1", Name: "hcsctl-nat", Type: hcn.NAT,
		Ipams: []hcn.Ipam{{Type: "Static", Subnets: []hcn.Subnet{{
			IpAddressPrefix: "172.29.130.0/24",
			Routes:          []hcn.Route{{NextHop: "172.29.130.1", DestinationPrefix: "0.0.0.0/0"}},
		}}}},
	}
}

func TestNewNetConfig(t *testing.T) {
	t.Run("derives gateway from the subnet holding the allocation", func(t *testing.T) {
		nc, err := newNetConfig([]string{"172.29.130.74/24"}, natNetwork(), "", "1.1.1.1, 8.8.8.8")
		if err != nil {
			t.Fatal(err)
		}
		if nc.Gateway != "172.29.130.1" {
			t.Fatalf("gateway = %q", nc.Gateway)
		}
		if nc.Interface != "" {
			t.Fatalf("interface = %q, want empty -- the guest's default is the agent's call, not the host's", nc.Interface)
		}
		if len(nc.DNS) != 2 || nc.DNS[0] != "1.1.1.1" || nc.DNS[1] != "8.8.8.8" {
			t.Fatalf("dns = %v", nc.DNS)
		}
	})

	t.Run("no allocation is an explicit error, not an empty config", func(t *testing.T) {
		_, err := newNetConfig(nil, natNetwork(), "", "")
		if err == nil || !strings.Contains(err.Error(), "no allocation") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("allocation outside every subnet yields no gateway", func(t *testing.T) {
		nc, err := newNetConfig([]string{"10.9.9.9/24"}, natNetwork(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if nc.Gateway != "" {
			t.Fatalf("gateway = %q, want empty for an unmatched subnet", nc.Gateway)
		}
	})

	t.Run("bad dns entry is a usage error", func(t *testing.T) {
		_, err := newNetConfig([]string{"172.29.130.74/24"}, natNetwork(), "", "1.1.1.1,not-an-ip")
		if err == nil || !strings.Contains(err.Error(), "not an IP address") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("dns is empty, never nil, when unset", func(t *testing.T) {
		nc, err := newNetConfig([]string{"172.29.130.74/24"}, natNetwork(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if nc.DNS == nil {
			t.Fatal("DNS is nil")
		}
	})
}
