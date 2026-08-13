//go:build windows

package vm

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// addr builds guest evidence for one address. Family is derived from the address so the IPv6
// rows are honest; guestIPv4Addresses parses the CIDR and never consults Family.
func addr(cidr string) guestproto.Address {
	family := "ipv4"
	if p, err := netip.ParsePrefix(cidr); err == nil && p.Addr().Is6() {
		family = "ipv6"
	}
	return guestproto.Address{Interface: "eth0", Address: cidr, Family: family}
}

func TestGuestIPv4Addresses(t *testing.T) {
	tests := []struct {
		name     string
		addrs    []guestproto.Address
		expected []string
		want     []string
	}{
		{
			name:  "keeps ordinary addresses in order",
			addrs: []guestproto.Address{addr("10.0.0.5/24"), addr("172.16.0.1/24")},
			want:  []string{"10.0.0.5/24", "172.16.0.1/24"},
		},
		{
			name:  "drops loopback",
			addrs: []guestproto.Address{addr("127.0.0.1/8"), addr("10.0.0.5/24")},
			want:  []string{"10.0.0.5/24"},
		},
		{
			name:  "drops APIPA link-local",
			addrs: []guestproto.Address{addr("169.254.10.20/16"), addr("10.0.0.5/24")},
			want:  []string{"10.0.0.5/24"},
		},
		{
			name:  "drops IPv6",
			addrs: []guestproto.Address{addr("2001:db8::1/64"), addr("10.0.0.5/24")},
			want:  []string{"10.0.0.5/24"},
		},
		{
			name:     "honours the expected filter",
			addrs:    []guestproto.Address{addr("10.0.0.5/24"), addr("10.0.0.6/24")},
			expected: []string{"10.0.0.5/24"},
			want:     []string{"10.0.0.5/24"},
		},
		{
			name:     "empty result when nothing matches the filter",
			addrs:    []guestproto.Address{addr("10.0.0.6/24")},
			expected: []string{"10.0.0.5/24"},
			want:     []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := guestIPv4Addresses(tc.addrs, tc.expected)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("guestIPv4Addresses(%v, %v) = %v, want %v", tc.addrs, tc.expected, got, tc.want)
			}
		})
	}
}
