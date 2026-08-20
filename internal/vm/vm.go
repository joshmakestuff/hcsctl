//go:build windows

// Package vm creates and drives full Hyper-V virtual machines -- not utility VMs hosting a
// container, but a VM booting a VHDX of its own.
//
// Unelevated. Membership of Hyper-V Administrators is sufficient, the same posture as the
// container path and the guest agent.
//
// A VM's id is a GUID because the id is also its hvsocket address: `vm create` prints an id
// that `guest info --vmid` takes unchanged. A VHDX with the agent installed boots here, and the
// guest answers over a Hyper-V socket with no network adapter attached.
package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/guest"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/vmcompute"
	"github.com/spf13/cobra"
)

// Command is `hcsctl vm`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("vm", "create and drive full Hyper-V virtual machines",
		createCmd(e), startCmd(e), stopCmd(e), rmCmd(e), lsCmd(e), inspectCmd(e),
		ipCmd(e), netconfigCmd(e), consoleCmd(e))
}

// spec is what buildDocument turns into a v2 document.
type spec struct {
	DiskPath   string
	CPUs       uint64
	MemoryMB   uint64
	SerialPipe string
	EndpointID string
	MacAddress string
}

// state is what a later invocation needs and HCS does not hold: where the disk came from and
// what this tool made. The compute system itself is host-global and reopenable by id.
type state struct {
	ID          string `json:"id"`
	BaseVHDX    string `json:"baseVhdx"`
	DiskPath    string `json:"diskPath"`
	CopyOnWrite bool   `json:"copyOnWrite"`
	CPUs        uint64 `json:"cpus"`
	MemoryMB    uint64 `json:"memoryMb"`
	SerialPipe  string `json:"serialPipe,omitempty"`
	CreatedUTC  string `json:"createdUtc"`

	// The endpoint this tool made, and the adapter it is behind. The id has to survive the
	// process: an endpoint is host-global, so a `vm rm` running in a later invocation -- or
	// after a crash -- is the only thing that will ever delete it.
	NetworkID   string   `json:"networkId,omitempty"`
	NetworkName string   `json:"networkName,omitempty"`
	EndpointID  string   `json:"endpointId,omitempty"`
	MacAddress  string   `json:"macAddress,omitempty"`
	DNS         []string `json:"dns,omitempty"`

	// Labels are stored and reported, never interpreted. Ownership and run identity are the
	// consumer's policy: hcsctl has no scavenger and no opinion about what "dead" means -- a
	// stopped VM has no owning process to check. It provides the facts a consumer joins: a
	// label here, the vm id in the endpoint's name, and `vm ls --all` for what HCS says is
	// running.
	Labels map[string]string `json:"labels,omitempty"`
}

// reservedLabelKeys are the field names a consumer sees when it flattens state.json or an
// inspect document. A label may not shadow one. Grown alongside the structs in this file.
var reservedLabelKeys = map[string]bool{
	"id": true, "baseVhdx": true, "diskPath": true, "copyOnWrite": true, "cpus": true,
	"memoryMb": true, "serialPipe": true, "createdUtc": true, "labels": true,
	"networkId": true, "networkName": true, "network": true, "endpointId": true,
	"macAddress": true, "dns": true, "addresses": true, "endpointError": true,
	"ok": true, "command": true, "state": true, "hcs": true, "hcsError": true,
	"store": true, "vms": true, "systems": true,
}

// Timeouts. Create and start are the two that wait on a guest-side event; the rest are
// bookkeeping. A start that has not completed in two minutes has failed at the firmware, not
// been slow.
const (
	createTimeout    = 60 * time.Second
	startTimeout     = 120 * time.Second
	terminateTimeout = 60 * time.Second
	shutdownTimeout  = 120 * time.Second
)

func vmsDir(s *store.Store) string           { return filepath.Join(s.Root, "vms") }
func vmDir(s *store.Store, id string) string { return filepath.Join(vmsDir(s), id) }

func readState(s *store.Store, id string) (state, error) {
	var st state
	b, err := os.ReadFile(filepath.Join(vmDir(s, id), "state.json"))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("state for %s is not valid JSON: %w", id, err)
	}
	return st, nil
}

func writeState(s *store.Store, st state) error {
	// Failpoint: a state-write failure happens only after vm create has acquired a
	// differencing disk, VHDX grants, and a compute system. This env var makes that rollback
	// observable in the local smoke test without an HCS failure.
	if os.Getenv("HCSCTL_TEST_FAIL_WRITESTATE") != "" {
		return fmt.Errorf("injected failure: HCSCTL_TEST_FAIL_WRITESTATE is set")
	}
	if err := os.MkdirAll(vmDir(s, st.ID), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(vmDir(s, st.ID), "state.json"), b, 0o644)
}

// requireID takes --id's value and insists it is a GUID. A friendly name would not be usable
// as an hvsocket address, and silently accepting one would produce a VM that `guest info`
// cannot reach with the id this tool printed.
func requireID(raw string) (string, error) {
	if err := cli.Require("--id", raw); err != nil {
		return "", err
	}
	g, err := guid.FromString(raw)
	if err != nil {
		return "", cli.Usagef("--id is not a GUID: %v", err)
	}
	return g.String(), nil
}

// -- create ------------------------------------------------------------------------------

type createResult struct {
	OK          bool   `json:"ok"`
	Command     string `json:"command"`
	ID          string `json:"id"`
	DiskPath    string `json:"diskPath"`
	CopyOnWrite bool   `json:"copyOnWrite"`
	CPUs        uint64 `json:"cpus"`
	MemoryMB    uint64 `json:"memoryMb"`
	SerialPipe  string `json:"serialPipe,omitempty"`

	Network    string   `json:"network,omitempty"`
	NetworkID  string   `json:"networkId,omitempty"`
	EndpointID string   `json:"endpointId,omitempty"`
	MacAddress string   `json:"macAddress,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	// Addresses is empty until the endpoint has one; a caller polls `vm inspect` for it. See
	// addressesOf.
	Addresses []string `json:"addresses"`
}

// createOptions is create's validated intake: everything argument-shaped has already been
// checked, parsed and resolved, so the body starts acquiring resources knowing exit 64 is
// behind it.
type createOptions struct {
	ID          string
	Base        string // absolute, and it exists
	CPUs        uint64
	MemoryMB    uint64
	SerialPipe  string // empty means the default console pipe
	CopyOnWrite bool
	Network     *hcn.HostComputeNetwork // nil without --network
	DNS         []string
	Labels      map[string]string
	StoreDir    string
}

func createCmd(e cli.Emit) *cobra.Command {
	var vhdx, id, cpusStr, memoryStr, network, dnsCSV, serialPipe, storeDir string
	var noCopyOnWrite bool
	var labelVals []string
	cmd := &cobra.Command{
		Use:   `create --vhdx <path> [--id <guid>] [--cpus N] [--memory-mb N] [--network <name|id|default>] [--dns <IPv4,...>] [--serial-pipe \\.\pipe\name] [--no-copy-on-write] [--label key=value]... [--store <dir>]`,
		Short: "make a Hyper-V VM that boots a Gen 2 VHDX; does not start it",
		Long: `Make a Hyper-V VM that boots a Gen 2 VHDX. By default the disk is a
differencing child, so the image is never written to; --no-copy-on-write boots
the image itself and MUTATES it. The id is a GUID because it is also the VM's
hvsocket address -- guest info --vmid takes it unchanged. Unelevated;
Hyper-V Administrators is enough. Does not start it.

--network default picks the Hyper-V Default Switch, whose DHCP configures an
arbitrary guest image. NAT and non-Default-Switch ICS networks require --dns and
are the only networks that accept it; vm start programs their HCN allocation in
the guest and succeeds only after its agent attests the address. The endpoint is
deleted by vm rm and nothing else.

--label stores opaque key=value pairs in state.json, reported by ls and inspect
and never interpreted -- record an owner pid; scavenge only on proof it is dead.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			labels, err := cli.ParseLabels(labelVals, reservedLabelKeys)
			if err != nil {
				return err
			}

			if err := cli.Require("--vhdx", vhdx); err != nil {
				return err
			}
			base, err := filepath.Abs(vhdx)
			if err != nil {
				return cli.Usagef("--vhdx %v", err)
			}
			if _, err := os.Stat(base); err != nil {
				return cli.Usagef("--vhdx %s: %v", base, err)
			}

			vmID := ""
			if id != "" {
				if vmID, err = requireID(id); err != nil {
					return err
				}
			} else {
				g, gerr := guid.NewV4()
				if gerr != nil {
					return gerr
				}
				vmID = g.String()
			}

			cpus := uint64(2)
			if cpusStr != "" {
				if cpus, err = cli.ParseUint(cpusStr, 256); err != nil {
					return cli.Usagef("--cpus %v", err)
				}
			}
			memoryMB := uint64(2048)
			if memoryStr != "" {
				if memoryMB, err = cli.ParseUint(memoryStr, 1<<20); err != nil {
					return cli.Usagef("--memory-mb %v", err)
				}
			}

			// Resolved before anything is made. This is argument validation -- a name that
			// matches no network is exit 64, and 64 means nothing was attempted, so it cannot
			// happen after a differencing disk has been written and rolled back. A failure
			// listing the networks has always been 64 here too, so it is kept that way.
			var netw *hcn.HostComputeNetwork
			if network != "" {
				if netw, err = resolveVMNetwork(network); err != nil {
					var ue *cli.UsageError
					if errors.As(err, &ue) {
						return err
					}
					return cli.Usagef("%v", err)
				}
			}
			dns, err := parseDNS(dnsCSV)
			if err != nil {
				return err
			}
			if err := validateDNSForNetwork(dns, netw); err != nil {
				return err
			}

			return create(createOptions{
				ID: vmID, Base: base, CPUs: cpus, MemoryMB: memoryMB,
				SerialPipe: serialPipe, CopyOnWrite: !noCopyOnWrite,
				Network: netw, DNS: dns, Labels: labels, StoreDir: storeDir,
			}, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &vhdx, "vhdx", "Gen 2 VHDX the VM boots")
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID; also its hvsocket address (default: generated)")
	cli.StringOnce(cmd.Flags(), &cpusStr, "cpus", "virtual processor count (default 2)")
	cli.StringOnce(cmd.Flags(), &memoryStr, "memory-mb", "memory in MB (default 2048)")
	cli.StringOnce(cmd.Flags(), &network, "network", "attach an endpoint on this network; 'default' picks the Hyper-V Default Switch")
	cli.StringOnce(cmd.Flags(), &dnsCSV, "dns", "comma-separated IPv4 DNS servers; required for NAT and non-Default-Switch ICS networks")
	cli.StringOnce(cmd.Flags(), &serialPipe, "serial-pipe", `named pipe for the COM port (default: \\.\pipe\hcsctl-<id>)`)
	cmd.Flags().BoolVar(&noCopyOnWrite, "no-copy-on-write", false, "boot the image itself and MUTATE it, instead of a differencing child")
	cli.StringArray(cmd.Flags(), &labelVals, "label", "opaque key=value stored in state.json, repeatable; never interpreted")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func create(opt createOptions, e cli.Emit) error {
	id := opt.ID
	st, err := store.New(opt.StoreDir)
	if err != nil {
		return err
	}
	if _, err := readState(st, id); err == nil {
		return fmt.Errorf("vm %s already exists -- rm it first", id)
	}
	dir := vmDir(st, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	disk := opt.Base
	if opt.CopyOnWrite {
		disk = filepath.Join(dir, "disk.vhdx")
		e.Progress("creating a differencing disk over %s", opt.Base)
		if err := createDifferencing(opt.Base, disk); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
	} else {
		if children, cerr := childrenOf(st, opt.Base, id); cerr != nil {
			_ = os.RemoveAll(dir)
			return cerr
		} else if len(children) > 0 {
			_ = os.RemoveAll(dir)
			return fmt.Errorf(
				"%s is the parent of %d differencing disk(s) -- booting it directly writes to it "+
					"and corrupts every child: %s", opt.Base, len(children), strings.Join(children, ", "))
		}
		e.Progress("booting %s directly -- this MUTATES it", opt.Base)
	}

	// Both the child and the parent need the grant. The VM worker opens the whole chain, and
	// a missing grant on the parent fails at start with the child's path in the message.
	revokeAccess, err := grantPathsWithRollback(
		grantPaths(disk, opt.Base, opt.CopyOnWrite),
		func(path string) error { return vmcompute.GrantVmAccess(id, path) },
		func(path string) error { return vmcompute.RevokeVmAccess(id, path) },
	)
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}

	// Every VM gets a COM port. It costs nothing to boot: a guest whose pipe nobody reads
	// boots in the same time as one with no COM port at all. It is the only way into a guest
	// whose agent is broken.
	pipe := opt.SerialPipe
	if pipe == "" {
		pipe = consolePipe(id)
	}

	record := state{
		ID: id, BaseVHDX: opt.Base, DiskPath: disk, CopyOnWrite: opt.CopyOnWrite,
		CPUs: opt.CPUs, MemoryMB: opt.MemoryMB, SerialPipe: pipe,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339),
		Labels:     opt.Labels, DNS: opt.DNS,
	}
	var sys *vmcompute.System

	// undo takes back every resource acquired so far, in reverse. It exists before the
	// endpoint so failures creating it, or anything after it, also revoke the VHDX grants.
	undo := func() {
		if sys != nil {
			if terr := sys.Terminate(terminateTimeout); terr != nil {
				e.Progress("WARNING: leaked compute system %s: %v", id, terr)
			}
			sys.Close()
			sys = nil
		}
		if record.EndpointID != "" {
			if derr := deleteVMEndpoint(record.EndpointID); derr != nil {
				e.Progress("WARNING: leaked endpoint %s: %v", record.EndpointID, derr)
			}
		}
		if rerr := revokeAccess(); rerr != nil {
			e.Progress("WARNING: leaked VHDX access grant: %v", rerr)
		}
		_ = os.RemoveAll(dir)
	}

	// The endpoint is made before the compute system, because the document names it. From here
	// on every failure uses undo: the endpoint and access grants are host-global, and no store
	// record points at them until writeState succeeds.
	if opt.Network != nil {
		mac, merr := generateMAC()
		if merr != nil {
			undo()
			return merr
		}
		ep, eerr := createVMEndpoint(opt.Network, "", endpointName(id), mac)
		if eerr != nil {
			undo()
			return eerr
		}
		record.NetworkID, record.NetworkName = opt.Network.Id, opt.Network.Name
		record.EndpointID, record.MacAddress = ep.Id, mac
		e.Progress("endpoint:  %s on %s (mac %s)", ep.Id, opt.Network.Name, mac)
	}

	e.Progress("creating compute system %s", id)
	sys, err = createSystem(record)
	if err != nil {
		undo()
		return err
	}

	if err := writeState(st, record); err != nil {
		undo()
		return err
	}
	// Closing the handle does not stop the VM: the document sets
	// ShouldTerminateOnLastHandleClosed false so it survives this process exiting.
	sys.Close()
	sys = nil

	// Read the endpoint now that it is attached to a NIC but before anything has started. HNS
	// fills in no address at attach time; the address comes from the guest's own DHCP client
	// and a caller has to wait for it (see ip).
	var addrs []string
	if record.EndpointID != "" {
		var aerr error
		if addrs, aerr = addressesOf(record.EndpointID); aerr != nil {
			e.Progress("WARNING: reading endpoint %s: %v", record.EndpointID, aerr)
		}
		e.Progress("addresses after attach, before start: %v", addrs)
	}

	e.Result(createResult{
		OK: true, Command: "vm create", ID: id, DiskPath: disk, CopyOnWrite: opt.CopyOnWrite,
		CPUs: opt.CPUs, MemoryMB: opt.MemoryMB, SerialPipe: record.SerialPipe,
		Network: record.NetworkName, NetworkID: record.NetworkID,
		EndpointID: record.EndpointID, MacAddress: record.MacAddress,
		DNS:       record.DNS,
		Addresses: addrs,
	}, func() {
		fmt.Printf("created %s\n", id)
		fmt.Printf("  disk    %s\n", disk)
		fmt.Printf("  cpus    %d\n  memory  %d MB\n", opt.CPUs, opt.MemoryMB)
		if record.EndpointID != "" {
			fmt.Printf("  network %s\n", record.NetworkName)
			fmt.Printf("  mac     %s\n", record.MacAddress)
			if len(addrs) == 0 {
				fmt.Printf("  address none yet -- the guest has not leased one\n")
			} else {
				fmt.Printf("  address %s\n", strings.Join(addrs, ","))
			}
		}
		fmt.Printf("start it with: hcsctl vm start --id %s\n", id)
	})
	return nil
}

// childrenOf lists the ids of VMs whose differencing disk has base as its parent, ignoring
// the VM being created.
//
// A differencing disk is only valid while its parent is unchanged, and nothing in the format
// enforces that -- writing to a parent silently corrupts every child. --no-copy-on-write is
// the one path in this tool that writes to a base image, so it is the one that has to look.
//
// This sees only VMs in this store. A copy of the same image elsewhere, or a child made by
// anything other than hcsctl, is invisible here. The guard removes the foreseeable mistake;
// it is not a lock.
func childrenOf(s *store.Store, base, exceptID string) ([]string, error) {
	entries, err := os.ReadDir(vmsDir(s))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == exceptID {
			continue
		}
		record, rerr := readState(s, entry.Name())
		if rerr != nil {
			// An unreadable record cannot be shown to be safe, so it counts as a child.
			out = append(out, entry.Name()+" (unreadable record)")
			continue
		}
		if record.CopyOnWrite && samePath(record.BaseVHDX, base) {
			out = append(out, record.ID)
		}
	}
	return out, nil
}

// samePath compares two Windows paths for the purpose of "is this the same file". Case
// insensitive, and both sides are already absolute. It does not resolve links or 8.3 names,
// so it can say "different" about one file reached two ways.
func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// createSystem turns a store record into a live compute system. Both create and start go
// through it: a VM that has exited no longer exists as a compute system, so starting one again
// is literally creating it again over the same disk.
func createSystem(record state) (*vmcompute.System, error) {
	doc := buildDocument(specFor(record))
	return vmcompute.Create(record.ID, doc, createTimeout)
}

// spec for the record, so create and start build the same document from the same source.
func specFor(record state) spec {
	return spec{
		DiskPath:   record.DiskPath,
		CPUs:       record.CPUs,
		MemoryMB:   record.MemoryMB,
		SerialPipe: record.SerialPipe,
		EndpointID: record.EndpointID,
		MacAddress: record.MacAddress,
	}
}

func grantPaths(disk, base string, copyOnWrite bool) []string {
	if !copyOnWrite {
		return []string{disk}
	}
	return []string{disk, base}
}

// grantPathsWithRollback acquires every VHDX access grant or revokes the successful prefix.
// Its returned closure is the caller's rollback once every grant has been acquired.
func grantPathsWithRollback(paths []string, grant func(string) error, revoke func(string) error) (func() error, error) {
	granted := make([]string, 0, len(paths))
	rollback := func() error {
		var errs []error
		for i := len(granted) - 1; i >= 0; i-- {
			if err := revoke(granted[i]); err != nil {
				errs = append(errs, fmt.Errorf("revoke %s: %w", granted[i], err))
			}
		}
		return errors.Join(errs...)
	}

	for _, path := range paths {
		if err := grant(path); err != nil {
			return nil, errors.Join(err, rollback())
		}
		granted = append(granted, path)
	}
	return rollback, nil
}

// -- start -------------------------------------------------------------------------------

type startResult struct {
	OK        bool   `json:"ok"`
	Command   string `json:"command"`
	ID        string `json:"id"`
	ElapsedMS int64  `json:"elapsedMs"`
	// Started means the firmware is running. It does NOT mean the guest OS is up -- unlike a
	// container, where start returning is the guest being ready. Ask guest info for that.
	Started bool `json:"started"`
	// Recreated says the compute system had to be made again from the store record, because
	// the previous one exited. The disk is the same one, so this is a power cycle and not a
	// fresh VM -- but it is worth reporting, since the id is all HCS ever held.
	Recreated bool                `json:"recreated"`
	Network   *startNetworkResult `json:"network,omitempty"`
}

func startCmd(e cli.Emit) *cobra.Command {
	var id, storeDir string
	cmd := &cobra.Command{
		Use:   "start --id <guid> [--store <dir>]",
		Short: "start a VM; recreates the compute system if it exited",
		Long: `On NAT and non-Default-Switch ICS networks, success means the guest agent has
applied and attested static IPv4 networking. Other starts mean firmware running.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			return start(vmID, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func start(id, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no vm %s in this store", id)
		}
		return err
	}

	recreated := false
	sys, err := vmcompute.Open(id)
	if vmcompute.IsNotFound(err) {
		// HCS destroys a compute system when it exits, so a VM that has been stopped is
		// simply not there any more -- "stopped" is not a state HCS keeps. The store record
		// and the disk are what survive a power cycle, so start rebuilds the system from
		// them rather than reporting a VM the caller can plainly see in `vm ls` as missing.
		e.Progress("%s is not running; recreating it over %s", id, record.DiskPath)
		// The endpoint has to be remade with the system. An endpoint that was attached to the
		// compute system that just exited cannot be attached to the new one -- HCS rejects the
		// document with 0x803b0014, blaming a missing device. See remakeVMEndpoint.
		if record.EndpointID != "" {
			e.Progress("remaking endpoint %s so it can be attached again", record.EndpointID)
			if rerr := remakeVMEndpoint(record.NetworkID, record.EndpointID,
				endpointName(record.ID), record.MacAddress); rerr != nil {
				return rerr
			}
		}
		if sys, err = createSystem(record); err != nil {
			return err
		}
		recreated = true
	} else if err != nil {
		return err
	}
	defer sys.Close()

	e.Progress("starting %s", id)
	began := time.Now()
	if err := sys.Start(startTimeout); err != nil {
		return err
	}
	var network *startNetworkResult
	if record.EndpointID != "" {
		netw, nerr := hcn.GetNetworkByID(record.NetworkID)
		if nerr != nil {
			return fmt.Errorf("the network %s this vm's endpoint is on: %w", record.NetworkID, nerr)
		}
		if modeOf(netw) == networkStatic {
			configured, cerr := configureStartNetwork(id, record, netw, startTimeout)
			if cerr != nil {
				return cerr
			}
			network = &configured
		}
	}
	elapsed := time.Since(began).Milliseconds()

	e.Result(startResult{OK: true, Command: "vm start", ID: id, ElapsedMS: elapsed,
		Started: true, Recreated: recreated, Network: network}, func() {
		fmt.Printf("started %s in %d ms\n", id, elapsed)
		fmt.Printf("the firmware is running; the guest OS is not necessarily up yet\n")
		fmt.Printf("wait for it with: hcsctl guest info --vmid %s\n", id)
	})
	return nil
}

// -- stop --------------------------------------------------------------------------------

type stopResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	ID      string `json:"id"`
	Method  string `json:"method"`
}

func stopCmd(e cli.Emit) *cobra.Command {
	var id, storeDir string
	var force bool
	cmd := &cobra.Command{
		Use:   "stop --id <guid> [--force] [--store <dir>]",
		Short: "shut down through the guest, or power off with --force",
		Long: `Without --force, asks the guest through the shutdown integration service; a
guest that lacks one cannot be asked. --force powers it off.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			return stop(vmID, force, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cmd.Flags().BoolVar(&force, "force", false, "power off instead of asking the guest")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func stop(id string, force bool, e cli.Emit) error {
	sys, err := vmcompute.Open(id)
	if vmcompute.IsNotFound(err) {
		// Already stopped: stop asks for a state, and the VM is in it. Success, so a teardown
		// script can run twice.
		e.Result(stopResult{OK: true, Command: "vm stop", ID: id, Method: "already stopped"}, func() {
			fmt.Printf("%s is already stopped\n", id)
		})
		return nil
	}
	if err != nil {
		return err
	}
	defer sys.Close()

	method := "shutdown"
	if force {
		method = "terminate"
		e.Progress("terminating %s", id)
		if err := sys.Terminate(terminateTimeout); err != nil {
			return err
		}
	} else {
		e.Progress("shutting down %s through the guest integration service", id)
		if err := sys.Shutdown(shutdownTimeout); err != nil {
			return fmt.Errorf("%w -- a guest without the shutdown integration service "+
				"cannot be asked; use --force to power it off", err)
		}
	}

	e.Result(stopResult{OK: true, Command: "vm stop", ID: id, Method: method}, func() {
		fmt.Printf("stopped %s (%s)\n", id, method)
	})
	return nil
}

// -- rm ----------------------------------------------------------------------------------

type removeResult struct {
	OK         bool     `json:"ok"`
	Command    string   `json:"command"`
	ID         string   `json:"id"`
	Terminated bool     `json:"terminated"`
	Removed    []string `json:"removed"`
	Warnings   []string `json:"warnings,omitempty"`
}

func rmCmd(e cli.Emit) *cobra.Command {
	var id, storeDir string
	var force bool
	cmd := &cobra.Command{
		Use:   "rm --id <guid> [--force] [--store <dir>]",
		Short: "terminate, then remove only what this tool made",
		Long: `Terminates, then removes only what this tool made. A --no-copy-on-write VM's
base image is never removed.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			return remove(vmID, force, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cmd.Flags().BoolVar(&force, "force", false, "remove even when terminate, endpoint delete or the directory removal fails")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func remove(id string, force bool, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	record, staterr := readState(st, id)
	if staterr != nil && !os.IsNotExist(staterr) {
		return staterr
	}

	res := removeResult{OK: true, Command: "vm rm", ID: id}

	// Terminate first. A VM still running holds its disk open, so the delete below would
	// fail with a sharing violation and leave half a removal behind.
	if sys, oerr := vmcompute.Open(id); oerr == nil {
		terr := sys.Terminate(terminateTimeout)
		sys.Close()
		switch {
		case terr == nil:
			res.Terminated = true
		case force:
			res.Warnings = append(res.Warnings, "terminate: "+terr.Error())
		default:
			return terr
		}
	} else if !vmcompute.IsNotFound(oerr) {
		// A VM that is simply not running is the ordinary case for rm and says nothing.
		// Anything else is reported, without failing the removal -- the disk and the record
		// still have to go.
		res.Warnings = append(res.Warnings, "open: "+oerr.Error())
	}

	// Every grant create made comes back off. An ACE naming a VM that no longer exists is not
	// a security problem, but nothing else ever removes one, so a base image that has backed a
	// hundred VMs would carry a hundred dead "NT VIRTUAL MACHINE\<guid>" entries.
	//
	// Failures are warnings, not errors: the ACE is inert, and refusing to remove the VM over one
	// would leave a compute system behind.
	if staterr == nil {
		for _, p := range grantPaths(record.DiskPath, record.BaseVHDX, record.CopyOnWrite) {
			if rerr := vmcompute.RevokeVmAccess(id, p); rerr != nil {
				res.Warnings = append(res.Warnings, "revoke "+p+": "+rerr.Error())
			}
		}
	}

	// The endpoint goes after the terminate and before the store record. After, because an
	// endpoint attached to a running VM is in use; before, because the record is the only thing
	// that knows the endpoint's id -- delete the record first and a failure here leaks it with
	// nothing left pointing at it.
	if record.EndpointID != "" {
		if derr := deleteVMEndpoint(record.EndpointID); derr != nil {
			if !force {
				return fmt.Errorf("%w -- the store record is kept so the endpoint can "+
					"still be found; --force removes the vm anyway and leaks it", derr)
			}
			res.Warnings = append(res.Warnings, "endpoint "+record.EndpointID+": "+derr.Error())
		} else {
			res.Removed = append(res.Removed, "endpoint "+record.EndpointID)
		}
	}

	// Only what this tool made. A --no-copy-on-write VM points at the caller's own image, and
	// removing the VM must never remove that.
	dir := vmDir(st, id)
	if record.CopyOnWrite || staterr != nil {
		if err := os.RemoveAll(dir); err != nil {
			if !force {
				return err
			}
			res.Warnings = append(res.Warnings, "remove "+dir+": "+err.Error())
		} else {
			res.Removed = append(res.Removed, dir)
		}
	} else {
		if err := os.RemoveAll(dir); err != nil && !force {
			return err
		}
		res.Removed = append(res.Removed, dir)
		res.Warnings = append(res.Warnings, "the base image "+record.BaseVHDX+
			" was booted directly and has been modified; it was not removed")
	}

	e.Result(res, func() {
		fmt.Printf("removed %s\n", id)
		for _, w := range res.Warnings {
			fmt.Printf("  warning: %s\n", w)
		}
	})
	return nil
}

// -- ip ----------------------------------------------------------------------------------

type ipResult struct {
	OK         bool     `json:"ok"`
	Command    string   `json:"command"`
	ID         string   `json:"id"`
	EndpointID string   `json:"endpointId"`
	Addresses  []string `json:"addresses"`
	WaitedMS   int64    `json:"waitedMs"`
}

// ipPollInterval is how often the endpoint is re-read. A DHCP handshake is not fast enough for
// a tighter loop to find the answer sooner, and each read is an HNS call.
const ipPollInterval = 2 * time.Second

func ipCmd(e cli.Emit) *cobra.Command {
	var id, timeoutStr, storeDir string
	cmd := &cobra.Command{
		Use:   "ip --id <guid> [--timeout 60s] [--store <dir>]",
		Short: "wait for guest-reported IPv4 addresses and print them",
		Long: `Wait for guest-reported IPv4 addresses and print them. Endpoint allocations are
used only to identify the guest address, never returned without guest evidence.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			timeout := 60 * time.Second
			if timeoutStr != "" {
				d, perr := time.ParseDuration(timeoutStr)
				if perr != nil || d <= 0 {
					return cli.Usagef("--timeout must be a positive duration, e.g. 60s")
				}
				timeout = d
			}
			return ip(vmID, timeout, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cli.StringOnce(cmd.Flags(), &timeoutStr, "timeout", "how long to wait for an address (default 60s)")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

// ip waits for the address the guest leases.
//
// An endpoint carries no address when it is created, none when it is attached to a NIC, and
// none while the compute system runs without a guest OS in it. The address can only come from
// the guest's own DHCP client, so a consumer that wants one has to wait.
//
// It waits rather than answering once. `vm start` returning means the firmware is running --
// the guest has not booted, let alone leased -- so a single-shot read would answer "none".
func ip(id string, timeout time.Duration, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no vm %s in the store", id)
		}
		return err
	}
	if record.EndpointID == "" {
		return fmt.Errorf("vm %s has no network endpoint -- it was created without --network", id)
	}

	began := time.Now()
	deadline := began.Add(timeout)
	for {
		expected, aerr := addressesOf(record.EndpointID)
		if aerr != nil {
			return fmt.Errorf("reading endpoint %s: %w", record.EndpointID, aerr)
		}
		vmid, _ := guid.FromString(id)
		info, ierr := guest.ReadInfo(vmid, ipPollInterval)
		if ierr == nil {
			addrs := guestIPv4Addresses(info.Addresses, expected)
			if len(addrs) > 0 {
				waited := time.Since(began).Milliseconds()
				e.Result(ipResult{OK: true, Command: "vm ip", ID: id, EndpointID: record.EndpointID,
					Addresses: addrs, WaitedMS: waited}, func() {
					fmt.Printf("%s\n", strings.Join(addrs, "\n"))
				})
				return nil
			}
		}
		if time.Now().After(deadline) {
			// Named as the guest's failure: the endpoint and HNS are fine, and nothing on the
			// host can produce an address on its own.
			return fmt.Errorf(
				"vm %s has no address after %s -- the guest has not taken a DHCP lease. Check that "+
					"it booted (hcsctl vm console --id %s) and that its NIC is configured for DHCP",
				id, timeout, id)
		}
		e.Progress("no address yet; waiting")
		time.Sleep(ipPollInterval)
	}
}

// -- ls ----------------------------------------------------------------------------------

type listEntry struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	DiskPath string            `json:"diskPath"`
	CPUs     uint64            `json:"cpus"`
	MemoryMB uint64            `json:"memoryMb"`
	Created  string            `json:"createdUtc"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// systemEntry is a compute system on the host, whether or not this store made it. Passed
// through from HcsEnumerateComputeSystems rather than reshaped.
//
// An endpoint whose name carries a vm id, and no running system with that id, is a leftover
// candidate. hcsctl does not draw the conclusion -- see the note on state.Labels.
type systemEntry struct {
	ID         string `json:"id"`
	SystemType string `json:"systemType,omitempty"`
	Owner      string `json:"owner,omitempty"`
	RuntimeID  string `json:"runtimeId,omitempty"`
	State      string `json:"state,omitempty"`
}

type listResult struct {
	OK      bool        `json:"ok"`
	Command string      `json:"command"`
	VMs     []listEntry `json:"vms"`
	// Systems is present only with --all, and is host-wide: other tools' VMs, WSL's, and
	// anything else HCS is running. Absent without the flag rather than empty, so a consumer
	// cannot mistake "not asked for" for "none".
	Systems []systemEntry `json:"systems,omitempty"`
}

func lsCmd(e cli.Emit) *cobra.Command {
	var storeDir string
	var all bool
	cmd := &cobra.Command{
		Use:   "ls [--all] [--store <dir>]",
		Short: "VMs and the state HCS reports for each",
		Long: `VMs and the state HCS reports for each. --all also lists every compute system
on the host with its owner, state and runtime id -- other tools' VMs included.
hcsctl does not scavenge. A consumer that does joins three facts: its own
--label on a vm, the vm id carried in the endpoint's name, and this list.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return list(all, storeDir, e)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "also list every compute system on the host")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func list(all bool, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(vmsDir(st))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	res := listResult{OK: true, Command: "vm ls", VMs: []listEntry{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		record, rerr := readState(st, entry.Name())
		if rerr != nil {
			res.VMs = append(res.VMs, listEntry{ID: entry.Name(), State: "unreadable"})
			continue
		}
		res.VMs = append(res.VMs, listEntry{
			ID: record.ID, State: hcsState(record.ID), DiskPath: record.DiskPath,
			CPUs: record.CPUs, MemoryMB: record.MemoryMB, Created: record.CreatedUTC,
			Labels: record.Labels,
		})
	}
	sort.Slice(res.VMs, func(i, j int) bool { return res.VMs[i].Created < res.VMs[j].Created })

	if all {
		systems, serr := hostSystems()
		if serr != nil {
			return serr
		}
		res.Systems = systems
	}

	e.Result(res, func() {
		if len(res.VMs) == 0 {
			fmt.Println("no vms")
			return
		}
		fmt.Printf("%-38s %-10s %-6s %-8s %s\n", "ID", "STATE", "CPUS", "MEMORY", "DISK")
		for _, v := range res.VMs {
			fmt.Printf("%-38s %-10s %-6d %-8d %s\n", v.ID, v.State, v.CPUs, v.MemoryMB, v.DiskPath)
		}
		if res.Systems == nil {
			return
		}
		fmt.Printf("\nevery compute system on the host:\n")
		fmt.Printf("%-38s %-24s %-16s %s\n", "ID", "OWNER", "STATE", "RUNTIMEID")
		for _, s := range res.Systems {
			fmt.Printf("%-38s %-24s %-16s %s\n", s.ID, orDash(s.Owner), orDash(s.State), s.RuntimeID)
		}
	})
	return nil
}

// hostSystems asks HCS what compute systems exist, host-wide. The Owner is whatever each
// system's own document set -- hcsctl's VMs say "hcsctl", WSL's say "WSL" -- so this is also how
// a consumer tells its own leftovers from another tool's.
//
// A system that has exited is simply absent: HCS destroys it rather than keeping a stopped
// state, so this cannot be read as "everything that was ever created".
func hostSystems() ([]systemEntry, error) {
	doc, err := vmcompute.Enumerate("")
	if err != nil {
		return nil, err
	}
	var systems []systemEntry
	if err := json.Unmarshal([]byte(doc), &systems); err != nil {
		return nil, fmt.Errorf("HcsEnumerateComputeSystems returned something unparseable: %w", err)
	}
	sort.Slice(systems, func(i, j int) bool { return systems[i].ID < systems[j].ID })
	return systems, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hcsState asks HCS for the live state, so ls reports that rather than what this tool last
// wrote. "stopped" is a store-side reading, not an HCS one: HCS has no stopped state, it
// destroys the compute system when it exits, so what is measured is its absence.
func hcsState(id string) string {
	sys, err := vmcompute.Open(id)
	if vmcompute.IsNotFound(err) {
		return "stopped"
	}
	if err != nil {
		return "unknown"
	}
	defer sys.Close()
	props, err := sys.Properties("")
	if err != nil {
		return "unknown"
	}
	var p struct {
		State string `json:"State"`
	}
	if json.Unmarshal([]byte(props), &p) != nil {
		return "unknown"
	}
	if p.State == "" {
		// HCS omits State entirely for a compute system that exists but has never been started.
		// A consumer deciding whether a VM is abandoned needs "created" and "cannot tell" kept
		// apart.
		return "created"
	}
	return strings.ToLower(p.State)
}

// -- inspect -----------------------------------------------------------------------------

type inspectResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	ID      string `json:"id"`
	Store   state  `json:"store"`
	// HCS is whatever the property document says, passed through rather than reshaped: this
	// is the verb for finding out what HCS actually holds.
	HCS json.RawMessage `json:"hcs,omitempty"`
	// HCSError records why the HCS half is missing, instead of an empty object that reads
	// like the VM has no properties.
	HCSError string `json:"hcsError,omitempty"`
	// Addresses is what the endpoint holds right now, which is the field a consumer polls
	// while it waits for the guest to take a lease. Empty for a VM with no endpoint, and
	// empty for one whose guest has not leased yet -- EndpointError tells those apart.
	Addresses     []string `json:"addresses"`
	EndpointError string   `json:"endpointError,omitempty"`
}

func inspectCmd(e cli.Emit) *cobra.Command {
	var id, storeDir string
	cmd := &cobra.Command{
		Use:   "inspect --id <guid> [--store <dir>]",
		Short: "the store's record plus the HCS properties",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			vmID, err := requireID(id)
			if err != nil {
				return err
			}
			return inspect(vmID, storeDir, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &id, "id", "VM id, a GUID")
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func inspect(id, storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no vm %s in the store", id)
		}
		return err
	}

	res := inspectResult{OK: true, Command: "vm inspect", ID: id, Store: record, Addresses: []string{}}
	if record.EndpointID != "" {
		if addrs, aerr := addressesOf(record.EndpointID); aerr != nil {
			res.EndpointError = aerr.Error()
		} else {
			res.Addresses = addrs
		}
	}
	if sys, oerr := vmcompute.Open(id); oerr == nil {
		props, perr := sys.Properties("")
		sys.Close()
		if perr != nil {
			res.HCSError = perr.Error()
		} else if json.Valid([]byte(props)) {
			res.HCS = json.RawMessage(props)
		}
	} else {
		res.HCSError = oerr.Error()
	}

	e.Result(res, func() {
		fmt.Printf("%s\n", id)
		fmt.Printf("  disk     %s\n", record.DiskPath)
		fmt.Printf("  base     %s\n", record.BaseVHDX)
		fmt.Printf("  cow      %t\n", record.CopyOnWrite)
		fmt.Printf("  cpus     %d\n  memory   %d MB\n", record.CPUs, record.MemoryMB)
		fmt.Printf("  state    %s\n", hcsState(id))
		if record.EndpointID != "" {
			fmt.Printf("  network  %s\n", record.NetworkName)
			fmt.Printf("  endpoint %s (mac %s)\n", record.EndpointID, record.MacAddress)
			switch {
			case res.EndpointError != "":
				fmt.Printf("  address  %s\n", res.EndpointError)
			case len(res.Addresses) == 0:
				fmt.Printf("  address  none yet\n")
			default:
				fmt.Printf("  address  %s\n", strings.Join(res.Addresses, ","))
			}
		}
		for _, k := range sortedKeys(record.Labels) {
			fmt.Printf("  label    %s=%s\n", k, record.Labels[k])
		}
		if res.HCSError != "" {
			fmt.Printf("  hcs      %s\n", res.HCSError)
		}
	})
	return nil
}

// sortedKeys gives label output a stable order. A map's iteration order is randomised, and a
// consumer diffing two inspect outputs should not see spurious changes.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
