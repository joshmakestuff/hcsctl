//go:build windows

package vm

// vm netconfig: program a guest's interface with the addressing the host already knows.
//
// On an hcsctl-owned network there is no DHCP server -- HNS allocates the endpoint's address
// at create and nothing delivers it to the guest. This verb reads that allocation from the
// endpoint document, derives the gateway from the network's route, and hands both to the
// agent over hvsocket. The agent applies them through the guest's own mechanism --
// NetworkManager on Linux, netsh on Windows -- and answers with what the interface actually
// holds, so the result attests the guest's state rather than restating the request.

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guest"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/spf13/cobra"
)

type netconfigResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	ID      string `json:"id"`
	// Applied is the guest-side mechanism, from the agent's own report.
	Applied string `json:"applied"`
	// Requested is what the host derived and sent.
	Requested guestproto.NetConfig `json:"requested"`
	// Addresses is what the interface holds AFTER applying, per the agent. This is the field
	// a consumer trusts; Requested is what to diff it against when it looks wrong.
	Addresses []guestproto.Address `json:"addresses"`
}

// newNetConfig derives the wire payload from the endpoint's allocation and the network
// document. Pure, so the derivation is testable without HCN: addrs is addressesOf's result,
// netw the network the endpoint is on.
func newNetConfig(addrs []string, netw *hcn.HostComputeNetwork, iface string, dns []string) (guestproto.NetConfig, error) {
	if len(addrs) == 0 {
		return guestproto.NetConfig{}, fmt.Errorf("the endpoint has no allocation to program -- " +
			"on an ICS network the guest leases for itself, and netconfig has nothing to do")
	}
	first, err := netip.ParsePrefix(addrs[0])
	if err != nil {
		return guestproto.NetConfig{}, fmt.Errorf("endpoint address %q is not CIDR: %v", addrs[0], err)
	}

	// The gateway is the default route of the subnet holding the allocation. A NAT network
	// document carries exactly this shape; a network without it yields a config with no
	// gateway, which is reported rather than invented.
	gateway := ""
	for _, ipam := range netw.Ipams {
		for _, s := range ipam.Subnets {
			prefix, perr := netip.ParsePrefix(s.IpAddressPrefix)
			if perr != nil || !prefix.Contains(first.Addr()) {
				continue
			}
			for _, r := range s.Routes {
				if r.DestinationPrefix == "0.0.0.0/0" && r.NextHop != "" {
					gateway = r.NextHop
				}
			}
		}
	}

	// An empty interface stays empty on the wire: it means the guest's own default (eth0 on
	// Linux, the single connected adapter on Windows), and only the agent knows which OS it
	// is.
	return guestproto.NetConfig{
		Interface: iface,
		Addresses: addrs,
		Gateway:   gateway,
		DNS:       dns,
	}, nil
}

func netconfigCmd(e cli.Emit) *cobra.Command {
	var id *cli.GUIDFlag
	var storeDir *string
	var dnsCSV, iface string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "netconfig --id <guid> [--dns <ip,ip>] [--interface eth0] [--timeout 45s] [--store <dir>]",
		Short: "program the guest's interface with the endpoint's HNS allocation",
		Long: `Program the guest's interface with the endpoint's HNS allocation, through the
agent and the guest's own NetworkManager. For hcsctl-owned networks (NAT),
which have no DHCP server. The result reports what the interface holds
afterwards, not what was asked.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			dns, err := parseDNS(dnsCSV)
			if err != nil {
				return err
			}
			return netconfig(id.Value(), dns, iface, timeout, *storeDir, e)
		},
	}
	id, storeDir = idStoreFlags(cmd)
	cli.StringOnce(cmd.Flags(), &dnsCSV, "dns", "comma-separated IPv4 DNS servers to program")
	cli.StringOnce(cmd.Flags(), &iface, "interface", "guest interface to program (default: the guest's own default)")
	cli.Duration(cmd.Flags(), &timeout, "timeout", 45*time.Second, 0, "agent call deadline")
	return cmd
}

func netconfig(vmid guid.GUID, dns []string, iface string, timeout time.Duration, storeDir string, e cli.Emit) error {
	id := vmid.String()
	s, err := store.New(storeDir)
	if err != nil {
		return err
	}
	st, err := readState(s, id)
	if err != nil {
		return fmt.Errorf("no vm %s in this store: %w", id, err)
	}
	if st.EndpointID == "" {
		return fmt.Errorf("vm %s has no endpoint -- it was created without --network", id)
	}

	addrs, err := addressesOf(st.EndpointID)
	if err != nil {
		return fmt.Errorf("reading endpoint %s: %w", st.EndpointID, err)
	}
	netw, err := hcn.GetNetworkByID(st.NetworkID)
	if err != nil {
		return fmt.Errorf("the network %s this vm's endpoint is on: %w", st.NetworkID, err)
	}

	nc, err := newNetConfig(addrs, netw, iface, dns)
	if err != nil {
		// A *cli.UsageError from here still means exit 64; the type carries the code.
		return err
	}

	ifaceLabel := nc.Interface
	if ifaceLabel == "" {
		ifaceLabel = "the guest's default interface"
	}
	e.Progress("programming %s on %s via the agent", strings.Join(nc.Addresses, ","), ifaceLabel)
	res, err := guest.ApplyNetConfig(vmid, nc, timeout)
	if err != nil {
		return err
	}

	out := netconfigResult{
		OK: true, Command: "vm netconfig", ID: id,
		Applied: res.Applied, Requested: nc, Addresses: res.Addresses,
	}
	if out.Addresses == nil {
		out.Addresses = []guestproto.Address{}
	}
	// The agent's attestation names the interface it actually programmed; prefer that over
	// the request, which may not have named one.
	if len(out.Addresses) > 0 {
		ifaceLabel = out.Addresses[0].Interface
	}
	e.Result(out, func() {
		fmt.Printf("applied via %s on %s\n", out.Applied, ifaceLabel)
		for _, ad := range out.Addresses {
			fmt.Printf("  %s %s\n", ad.Interface, ad.Address)
		}
	})
	return nil
}
