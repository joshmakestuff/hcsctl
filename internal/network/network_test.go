//go:build windows

package network

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
)

func TestNewNetworkInspectResult(t *testing.T) {
	t.Run("empty network keeps every slice non-nil", func(t *testing.T) {
		res := newNetworkInspectResult(&hcn.HostComputeNetwork{Id: "id-1", Name: "n"}, nil, nil)
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "null") {
			t.Fatalf("marshalled result contains null: %s", raw)
		}
		for name, s := range map[string][]string{
			"flagNames": res.FlagNames, "macRanges": res.MacRanges, "endpoints": res.Endpoints,
			"dns.search": res.Dns.Search, "dns.serverList": res.Dns.ServerList, "dns.options": res.Dns.Options,
		} {
			if s == nil {
				t.Fatalf("%s is nil", name)
			}
		}
		if res.Ipams == nil || res.Policies == nil {
			t.Fatal("ipams or policies is nil")
		}
	})

	t.Run("identity and flag decoding", func(t *testing.T) {
		res := newNetworkInspectResult(&hcn.HostComputeNetwork{
			Id: "id-1", Name: "nat", Type: hcn.NAT,
			SchemaVersion: hcn.SchemaVersion{Major: 2, Minor: 0},
			Flags:         hcn.NetworkFlags(32 | 1024),
		}, nil, nil)
		if !res.OK || res.Command != "network inspect" {
			t.Fatalf("header = %#v", res)
		}
		if res.SchemaVersion != "2.0" || res.Flags != 1056 {
			t.Fatalf("schema/flags = %q/%d", res.SchemaVersion, res.Flags)
		}
		if len(res.FlagNames) != 2 || res.FlagNames[0] != "EnableDhcp" || res.FlagNames[1] != "DisableHostPort" {
			t.Fatalf("flagNames = %v", res.FlagNames)
		}
	})

	t.Run("subnets, routes, MAC ranges and policies pass through", func(t *testing.T) {
		res := newNetworkInspectResult(&hcn.HostComputeNetwork{
			Id: "id-1",
			Ipams: []hcn.Ipam{{Type: "Static", Subnets: []hcn.Subnet{{
				IpAddressPrefix: "192.168.199.0/24",
				Routes:          []hcn.Route{{NextHop: "192.168.199.1", DestinationPrefix: "0.0.0.0/0"}},
			}}}},
			MacPool:  hcn.MacPool{Ranges: []hcn.MacRange{{StartMacAddress: "00-15-5D-00-00-00", EndMacAddress: "00-15-5D-00-00-FF"}}},
			Policies: []hcn.NetworkPolicy{{Type: "NetAdapterName", Settings: json.RawMessage(`{"NetworkAdapterName":"x"}`)}},
		}, nil, nil)
		if len(res.Ipams) != 1 || res.Ipams[0].Subnets[0].Prefix != "192.168.199.0/24" ||
			res.Ipams[0].Subnets[0].Routes[0].NextHop != "192.168.199.1" {
			t.Fatalf("ipams = %#v", res.Ipams)
		}
		if len(res.MacRanges) != 1 || res.MacRanges[0] != "00-15-5D-00-00-00-00-15-5D-00-00-FF" {
			t.Fatalf("macRanges = %v", res.MacRanges)
		}
		if len(res.Policies) != 1 || res.Policies[0].Type != "NetAdapterName" ||
			string(res.Policies[0].Settings) != `{"NetworkAdapterName":"x"}` {
			t.Fatalf("policies = %#v", res.Policies)
		}
	})

	t.Run("endpoints filter to this network, case-insensitively, sorted", func(t *testing.T) {
		res := newNetworkInspectResult(&hcn.HostComputeNetwork{Id: "ABC-1"}, []hcn.HostComputeEndpoint{
			{Id: "ep-2", HostComputeNetwork: "abc-1"},
			{Id: "ep-1", HostComputeNetwork: "ABC-1"},
			{Id: "ep-3", HostComputeNetwork: "other"},
		}, nil)
		if len(res.Endpoints) != 2 || res.Endpoints[0] != "ep-1" || res.Endpoints[1] != "ep-2" {
			t.Fatalf("endpoints = %v", res.Endpoints)
		}
		if res.EndpointsError != "" {
			t.Fatalf("endpointsError = %q", res.EndpointsError)
		}
	})

	t.Run("enumeration failure reports the sibling error, not zero endpoints", func(t *testing.T) {
		res := newNetworkInspectResult(&hcn.HostComputeNetwork{Id: "id-1"},
			[]hcn.HostComputeEndpoint{{Id: "ep-1", HostComputeNetwork: "id-1"}},
			errors.New("access denied"))
		if res.EndpointsError != "access denied" {
			t.Fatalf("endpointsError = %q", res.EndpointsError)
		}
		if len(res.Endpoints) != 0 {
			t.Fatalf("endpoints listed despite error: %v", res.Endpoints)
		}
	})
}

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
