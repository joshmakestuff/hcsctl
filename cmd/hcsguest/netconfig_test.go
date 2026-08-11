package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func TestValidateNetConfig(t *testing.T) {
	t.Run("defaults the interface and accepts a full config", func(t *testing.T) {
		nc := &guestproto.NetConfig{
			Addresses: []string{"172.29.130.74/24"},
			Gateway:   "172.29.130.1",
			DNS:       []string{"1.1.1.1"},
		}
		if err := validateNetConfig(nc); err != nil {
			t.Fatal(err)
		}
		if nc.Interface != "eth0" {
			t.Fatalf("interface = %q, want eth0 default", nc.Interface)
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
