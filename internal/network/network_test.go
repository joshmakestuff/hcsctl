//go:build windows

package network

import (
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
)

func TestNewNetwork(t *testing.T) {
	t.Run("NAT builds the measured HCN document", func(t *testing.T) {
		network, err := newNetwork("hcsctl-test", "nat", "192.168.199.0/24", "192.168.199.1")
		if err != nil {
			t.Fatal(err)
		}
		if network.Name != "hcsctl-test" || network.Type != hcn.NAT {
			t.Fatalf("network identity = %#v", network)
		}
		if network.SchemaVersion != (hcn.SchemaVersion{Major: 2, Minor: 0}) {
			t.Fatalf("schema = %#v", network.SchemaVersion)
		}
		if len(network.Ipams) != 1 || network.Ipams[0].Type != "Static" {
			t.Fatalf("IPAM = %#v", network.Ipams)
		}
		subnets := network.Ipams[0].Subnets
		if len(subnets) != 1 || subnets[0].IpAddressPrefix != "192.168.199.0/24" {
			t.Fatalf("subnets = %#v", subnets)
		}
		if len(subnets[0].Routes) != 1 || subnets[0].Routes[0].NextHop != "192.168.199.1" ||
			subnets[0].Routes[0].DestinationPrefix != "0.0.0.0/0" {
			t.Fatalf("routes = %#v", subnets[0].Routes)
		}
	})

	t.Run("private requires no address configuration", func(t *testing.T) {
		network, err := newNetwork("hcsctl-test", "private", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if network.Type != hcn.Private || len(network.Ipams) != 0 {
			t.Fatalf("network = %#v", network)
		}
	})

	for _, tc := range []struct {
		name, kind, subnet, gateway, want string
	}{
		{"unknown type", "overlay", "", "", "must be nat or private"},
		{"NAT needs subnet", "nat", "", "192.168.1.1", "--subnet is required"},
		{"NAT needs gateway", "nat", "192.168.1.0/24", "", "--gateway is required"},
		{"private rejects subnet", "private", "192.168.1.0/24", "", "does not take"},
		{"empty name", "private", "", "", "--name must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "hcsctl-test"
			if tc.name == "empty name" {
				name = " "
			}
			_, err := newNetwork(name, tc.kind, tc.subnet, tc.gateway)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateNatSubnet(t *testing.T) {
	tests := []struct {
		name, subnet, gateway, wantPrefix, wantGateway, wantError string
	}{
		{"valid", "192.168.199.0/24", "192.168.199.1", "192.168.199.0/24", "192.168.199.1", ""},
		{"IPv6 subnet", "fd00::/64", "fd00::1", "", "", "IPv4 CIDR"},
		{"host bits", "192.168.199.3/24", "192.168.199.1", "", "", "must name the network"},
		{"slash zero", "0.0.0.0/0", "1.1.1.1", "", "", "leave a gateway"},
		{"slash thirty-one", "192.168.199.0/31", "192.168.199.1", "", "", "leave a gateway"},
		{"gateway outside", "192.168.199.0/24", "192.168.200.1", "", "", "outside"},
		{"network address", "192.168.199.0/24", "192.168.199.0", "", "", "not a usable"},
		{"broadcast address", "192.168.199.0/24", "192.168.199.255", "", "", "not a usable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix, gateway, err := validateNatSubnet(tc.subnet, tc.gateway)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if prefix != tc.wantPrefix || gateway != tc.wantGateway {
				t.Fatalf("got (%q, %q), want (%q, %q)", prefix, gateway, tc.wantPrefix, tc.wantGateway)
			}
		})
	}
}
