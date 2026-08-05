//go:build windows

// Package network is the `hcsctl network` verb group: reading the Host Compute Network state
// that containers attach to.
//
// Read-only for now, and unelevated. Measured 2026-08-05 against HNS schema 16.0: listing
// networks, endpoints and namespaces all work from a filtered token. `hcn.GetGlobals` is the one
// call that needs elevation, which is why it is reported as optional detail rather than as the
// header it looks like it should be.
//
// Creating and deleting networks is deliberately absent. Windows permits one NAT network per
// host, hosts that run Docker already have it, and a second one plausibly breaks Docker and WSL.
// That is a decision to make explicitly, not a verb to add quietly.
package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "ls":
		return list(a, e)
	case "endpoints":
		return endpoints(a, e)
	case "":
		return cli.Usage, cli.Usagef("network needs a subcommand: ls, endpoints")
	default:
		return cli.Usage, cli.Usagef("unknown network subcommand %q (expected ls, endpoints)", a.Word(1))
	}
}

type networkRow struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Subnets []string `json:"subnets"`
	// Endpoints is a count rather than a list: `network ls` is the overview, and `network
	// endpoints` is where you go when the count is surprising.
	Endpoints int `json:"endpoints"`
}

func list(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown(); err != nil {
		return cli.Usage, err
	}
	nets, err := hcn.ListNetworks()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListNetworks: %w", err)
	}

	// One enumeration of every endpoint, bucketed by network, rather than a per-network query.
	// ListEndpointsOfNetwork would be N round trips to say the same thing.
	perNetwork := map[string]int{}
	eps, epErr := hcn.ListEndpoints()
	if epErr != nil {
		e.Progress("ListEndpoints: %v -- endpoint counts omitted", epErr)
	}
	for _, ep := range eps {
		perNetwork[strings.ToLower(ep.HostComputeNetwork)]++
	}

	rows := make([]networkRow, 0, len(nets))
	for _, n := range nets {
		r := networkRow{
			ID: n.Id, Name: n.Name, Type: string(n.Type),
			Endpoints: perNetwork[strings.ToLower(n.Id)],
			Subnets:   []string{},
		}
		for _, ipam := range n.Ipams {
			for _, s := range ipam.Subnets {
				if s.IpAddressPrefix != "" {
					r.Subnets = append(r.Subnets, s.IpAddressPrefix)
				}
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	e.Result(map[string]any{"ok": true, "command": "network ls", "networks": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no networks")
			return
		}
		fmt.Printf("%-26s %-12s %-20s %5s  %s\n", "NAME", "TYPE", "SUBNETS", "EPS", "ID")
		for _, r := range rows {
			fmt.Printf("%-26s %-12s %-20s %5d  %s\n",
				trunc(r.Name, 26), r.Type, strings.Join(r.Subnets, ","), r.Endpoints, r.ID)
		}
	})
	return cli.OK, nil
}

type endpointRow struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	NetworkID string   `json:"networkId"`
	Network   string   `json:"network"`
	Addresses []string `json:"addresses"`
	MAC       string   `json:"mac"`
}

func endpoints(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--network"); err != nil {
		return cli.Usage, err
	}
	nets, err := hcn.ListNetworks()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListNetworks: %w", err)
	}
	// Names, so the output is readable without a second lookup, and so --network can accept
	// either a name or an ID.
	nameByID := map[string]string{}
	for _, n := range nets {
		nameByID[strings.ToLower(n.Id)] = n.Name
	}

	var filterID string
	if want := a.Option("--network"); want != "" {
		for _, n := range nets {
			if strings.EqualFold(n.Name, want) || strings.EqualFold(n.Id, want) {
				filterID = strings.ToLower(n.Id)
				break
			}
		}
		if filterID == "" {
			return cli.Usage, cli.Usagef("no network named or with id %q -- try `hcsctl network ls`", want)
		}
	}

	eps, err := hcn.ListEndpoints()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListEndpoints: %w", err)
	}

	rows := make([]endpointRow, 0, len(eps))
	for _, ep := range eps {
		netID := strings.ToLower(ep.HostComputeNetwork)
		if filterID != "" && netID != filterID {
			continue
		}
		r := endpointRow{
			ID: ep.Id, Name: ep.Name, NetworkID: ep.HostComputeNetwork,
			Network: nameByID[netID], MAC: ep.MacAddress, Addresses: []string{},
		}
		for _, ip := range ep.IpConfigurations {
			r.Addresses = append(r.Addresses, fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength))
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	e.Result(map[string]any{"ok": true, "command": "network endpoints", "endpoints": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no endpoints")
			return
		}
		fmt.Printf("%-26s %-20s %-19s %-18s %s\n", "NAME", "NETWORK", "ADDRESS", "MAC", "ID")
		for _, r := range rows {
			fmt.Printf("%-26s %-20s %-19s %-18s %s\n",
				trunc(r.Name, 26), trunc(r.Network, 20),
				strings.Join(r.Addresses, ","), r.MAC, r.ID)
		}
	})
	return cli.OK, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}
