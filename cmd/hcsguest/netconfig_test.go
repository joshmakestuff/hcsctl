package main

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestValidateNetConfig(t *testing.T) {
	t.Run("defaults the interface per OS and accepts a full config", func(t *testing.T) {
		nc := &guestproto.NetConfig{
			Addresses: []string{"172.29.130.74/24"},
			Gateway:   "172.29.130.1",
			DNS:       []string{"1.1.1.1"},
		}
		if err := validateNetConfig(nc); err != nil {
			t.Fatal(err)
		}
		// eth0 on Linux; empty on Windows, where applyNetConfig selects the single
		// connected adapter instead of trusting a name.
		want := map[string]string{"linux": "eth0", "windows": ""}[runtime.GOOS]
		if nc.Interface != want {
			t.Fatalf("interface = %q, want %q on %s", nc.Interface, want, runtime.GOOS)
		}
	})

	for _, tc := range []struct {
		name string
		nc   *guestproto.NetConfig
		want string
	}{
		{"nil payload", nil, "needs a payload"},
		{"no addresses", &guestproto.NetConfig{}, "at least one address"},
		{"address without prefix", &guestproto.NetConfig{Addresses: []string{"172.29.130.74"}}, "not CIDR"},
		{"garbage gateway", &guestproto.NetConfig{Addresses: []string{"172.29.130.74/24"}, Gateway: "gw"}, "not an address"},
		{"garbage dns", &guestproto.NetConfig{Addresses: []string{"172.29.130.74/24"}, DNS: []string{"dns"}}, "not an address"},
		{"ipv6 address", &guestproto.NetConfig{Addresses: []string{"fd00::2/64"}}, "not IPv4"},
		{"ipv6 gateway", &guestproto.NetConfig{Addresses: []string{"172.29.130.74/24"}, Gateway: "fd00::1"}, "not IPv4"},
		{"ipv6 dns", &guestproto.NetConfig{Addresses: []string{"172.29.130.74/24"}, DNS: []string{"2606:4700:4700::1111"}}, "not IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNetConfig(tc.nc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNmcliModArgs(t *testing.T) {
	nc := &guestproto.NetConfig{
		Interface: "eth0",
		Addresses: []string{"172.29.130.74/24", "172.29.130.75/24"},
		Gateway:   "172.29.130.1",
		DNS:       []string{"1.1.1.1", "8.8.8.8"},
	}
	got := nmcliModArgs(nc)
	want := []string{"con", "mod", "eth0",
		"ipv4.method", "manual",
		"ipv4.addresses", "172.29.130.74/24,172.29.130.75/24",
		"ipv4.gateway", "172.29.130.1",
		"ipv4.dns", "1.1.1.1,8.8.8.8",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}

	t.Run("gateway and dns are omitted when absent", func(t *testing.T) {
		got := nmcliModArgs(&guestproto.NetConfig{Interface: "eth0", Addresses: []string{"10.0.0.2/24"}})
		for _, a := range got {
			if a == "ipv4.gateway" || a == "ipv4.dns" {
				t.Fatalf("args carry %s for a config without one: %q", a, got)
			}
		}
	})
}

func TestNetshCmds(t *testing.T) {
	// The single-address, gateway-and-dns shape is the measured netsh sequence verbatim; extra
	// addresses and dns servers ride the corresponding `add` verbs.
	nc := &guestproto.NetConfig{
		Addresses: []string{"172.29.172.38/24", "172.29.172.39/24"},
		Gateway:   "172.29.172.1",
		DNS:       []string{"1.1.1.1", "8.8.8.8"},
	}
	got := netshCmds(nc, 7)
	want := [][]string{
		{"interface", "ipv4", "set", "address", "name=7", "source=static",
			"address=172.29.172.38", "mask=255.255.255.0", "gateway=172.29.172.1"},
		{"interface", "ipv4", "add", "address", "name=7",
			"address=172.29.172.39", "mask=255.255.255.0"},
		{"interface", "ipv4", "set", "dnsservers", "name=7", "source=static",
			"address=1.1.1.1", "register=none", "validate=no"},
		{"interface", "ipv4", "add", "dnsservers", "name=7",
			"address=8.8.8.8", "index=2", "validate=no"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmds =\n%q\nwant\n%q", got, want)
	}

	t.Run("gateway and dns are omitted when absent", func(t *testing.T) {
		got := netshCmds(&guestproto.NetConfig{Addresses: []string{"10.0.0.2/16"}}, 3)
		want := [][]string{
			{"interface", "ipv4", "set", "address", "name=3", "source=static",
				"address=10.0.0.2", "mask=255.255.0.0"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("cmds = %q, want %q", got, want)
		}
	})
}
