//go:build windows

// Package vm creates and drives full Hyper-V virtual machines -- not utility VMs hosting a
// container, but a VM booting a VHDX of its own (#34).
//
// Unelevated. Membership of Hyper-V Administrators is sufficient, which is the same posture
// the container path and the guest agent already have.
//
// A VM's id is a GUID because the id is also its hvsocket address: `vm create` prints an id
// that `guest info --vmid` takes unchanged. That is the loop this package closes -- hc-images
// builds a VHDX with the agent in it, this boots it, and the guest answers over a Hyper-V
// socket with no network adapter attached at all.
package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/vmcompute"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "create":
		return create(a, e)
	case "start":
		return start(a, e)
	case "stop":
		return stop(a, e)
	case "rm":
		return remove(a, e)
	case "ls":
		return list(a, e)
	case "inspect":
		return inspect(a, e)
	case "console":
		return console(a, e)
	case "ip":
		return ip(a, e)
	case "":
		return cli.Usage, cli.Usagef("vm needs a subcommand: create, start, stop, rm, ls, inspect, ip, console")
	default:
		return cli.Usage, cli.Usagef("unknown vm subcommand %q (expected create, start, stop, rm, ls, inspect, ip, console)", a.Word(1))
	}
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
	NetworkID   string `json:"networkId,omitempty"`
	NetworkName string `json:"networkName,omitempty"`
	EndpointID  string `json:"endpointId,omitempty"`
	MacAddress  string `json:"macAddress,omitempty"`
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

func openStore(a *cli.Args) (*store.Store, error) { return store.New(a.Option("--store")) }

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
	if err := os.MkdirAll(vmDir(s, st.ID), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(vmDir(s, st.ID), "state.json"), b, 0o644)
}

// requireID takes --id and insists it is a GUID. A friendly name would not be usable as an
// hvsocket address, and silently accepting one would produce a VM that `guest info` cannot
// reach with the id this tool printed.
func requireID(a *cli.Args) (string, error) {
	raw, err := a.Require("--id")
	if err != nil {
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

	Network     string `json:"network,omitempty"`
	NetworkID   string `json:"networkId,omitempty"`
	EndpointID  string `json:"endpointId,omitempty"`
	MacAddress  string `json:"macAddress,omitempty"`
	// Addresses is empty until the endpoint has one, and that is a real answer rather than a
	// missing one -- a caller polls `vm inspect` for it. See addressesOf and #43.
	Addresses []string `json:"addresses"`
}

func create(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--vhdx", "--cpus", "--memory-mb", "--serial-pipe", "--store", "--no-copy-on-write", "--network"); err != nil {
		return cli.Usage, err
	}

	base, err := a.Require("--vhdx")
	if err != nil {
		return cli.Usage, err
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return cli.Usage, cli.Usagef("--vhdx %v", err)
	}
	if _, err := os.Stat(base); err != nil {
		return cli.Usage, cli.Usagef("--vhdx %s: %v", base, err)
	}

	id := ""
	if a.Option("--id") != "" {
		if id, err = requireID(a); err != nil {
			return cli.Usage, err
		}
	} else {
		g, gerr := guid.NewV4()
		if gerr != nil {
			return cli.Failed, gerr
		}
		id = g.String()
	}

	cpus := uint64(2)
	if s := a.Option("--cpus"); s != "" {
		if cpus, err = cli.ParseUint(s, 256); err != nil {
			return cli.Usage, cli.Usagef("--cpus %v", err)
		}
	}
	memoryMB := uint64(2048)
	if s := a.Option("--memory-mb"); s != "" {
		if memoryMB, err = cli.ParseUint(s, 1<<20); err != nil {
			return cli.Usage, cli.Usagef("--memory-mb %v", err)
		}
	}

	// Resolved before anything is made. This is argument validation -- a name that matches no
	// network is exit 64, and 64 means nothing was attempted, so it cannot happen after a
	// differencing disk has been written and rolled back.
	var netw *hcn.HostComputeNetwork
	if want := a.Option("--network"); want != "" {
		if netw, err = resolveVMNetwork(want); err != nil {
			return cli.Usage, err
		}
	}

	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	if _, err := readState(st, id); err == nil {
		return cli.Failed, fmt.Errorf("vm %s already exists -- rm it first", id)
	}
	dir := vmDir(st, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return cli.Failed, err
	}

	copyOnWrite := !a.Flag("--no-copy-on-write")
	disk := base
	if copyOnWrite {
		disk = filepath.Join(dir, "disk.vhdx")
		e.Progress("creating a differencing disk over %s", base)
		if err := createDifferencing(base, disk); err != nil {
			_ = os.RemoveAll(dir)
			return cli.Failed, err
		}
	} else {
		if children, cerr := childrenOf(st, base, id); cerr != nil {
			_ = os.RemoveAll(dir)
			return cli.Failed, cerr
		} else if len(children) > 0 {
			_ = os.RemoveAll(dir)
			return cli.Failed, fmt.Errorf(
				"%s is the parent of %d differencing disk(s) -- booting it directly writes to it "+
					"and corrupts every child: %s", base, len(children), strings.Join(children, ", "))
		}
		e.Progress("booting %s directly -- this MUTATES it", base)
	}

	// Both the child and the parent need the grant. The VM worker opens the whole chain, and
	// a missing grant on the parent fails at start with the child's path in the message.
	for _, p := range grantPaths(disk, base, copyOnWrite) {
		if err := vmcompute.GrantVmAccess(id, p); err != nil {
			_ = os.RemoveAll(dir)
			return cli.Failed, err
		}
	}

	// Every VM gets a COM port. It costs nothing to boot -- measured: a guest whose pipe
	// nobody reads boots in the same time as one with no COM port at all -- and it is the
	// only way into a guest whose agent is the broken thing.
	pipe := a.Option("--serial-pipe")
	if pipe == "" {
		pipe = consolePipe(id)
	}

	record := state{
		ID: id, BaseVHDX: base, DiskPath: disk, CopyOnWrite: copyOnWrite,
		CPUs: cpus, MemoryMB: memoryMB, SerialPipe: pipe,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339),
	}

	// The endpoint is made before the compute system, because the document names it. From here
	// on every failure has to take it back down: it is host-global, and nothing in the store
	// yet points at it, so an early return without this leaks it permanently.
	if netw != nil {
		mac, merr := generateMAC()
		if merr != nil {
			_ = os.RemoveAll(dir)
			return cli.Failed, merr
		}
		ep, eerr := createVMEndpoint(netw, "", endpointName(id), mac)
		if eerr != nil {
			_ = os.RemoveAll(dir)
			return cli.Failed, eerr
		}
		record.NetworkID, record.NetworkName = netw.Id, netw.Name
		record.EndpointID, record.MacAddress = ep.Id, mac
		e.Progress("endpoint:  %s on %s (mac %s)", ep.Id, netw.Name, mac)
	}

	// undo takes back everything made so far, in reverse. Used on every failure below.
	undo := func() {
		if record.EndpointID != "" {
			if derr := deleteVMEndpoint(record.EndpointID); derr != nil {
				e.Progress("WARNING: leaked endpoint %s: %v", record.EndpointID, derr)
			}
		}
		_ = os.RemoveAll(dir)
	}

	e.Progress("creating compute system %s", id)
	sys, err := createSystem(record)
	if err != nil {
		undo()
		return cli.Failed, err
	}
	// Closing the handle does not stop the VM: the document sets
	// ShouldTerminateOnLastHandleClosed false precisely so it survives this process exiting.
	sys.Close()

	if err := writeState(st, record); err != nil {
		undo()
		return cli.Failed, err
	}

	// Read the endpoint now that it is attached to a NIC but before anything has started. This
	// is the measurement #43 is waiting on: an address here means HNS fills one in at attach
	// time and no wait verb is needed; nothing here means it comes from the guest's own DHCP
	// client and a caller has to wait for it.
	var addrs []string
	if record.EndpointID != "" {
		var aerr error
		if addrs, aerr = addressesOf(record.EndpointID); aerr != nil {
			e.Progress("WARNING: reading endpoint %s: %v", record.EndpointID, aerr)
		}
		e.Progress("addresses after attach, before start: %v", addrs)
	}

	e.Result(createResult{
		OK: true, Command: "vm create", ID: id, DiskPath: disk, CopyOnWrite: copyOnWrite,
		CPUs: cpus, MemoryMB: memoryMB, SerialPipe: record.SerialPipe,
		Network: record.NetworkName, NetworkID: record.NetworkID,
		EndpointID: record.EndpointID, MacAddress: record.MacAddress,
		Addresses: addrs,
	}, func() {
		fmt.Printf("created %s\n", id)
		fmt.Printf("  disk    %s\n", disk)
		fmt.Printf("  cpus    %d\n  memory  %d MB\n", cpus, memoryMB)
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
	return cli.OK, nil
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
			// An unreadable record cannot be shown to be safe, so it counts as a child. The
			// alternative is skipping it, which turns a corrupt file into permission to
			// destroy a disk.
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
	Recreated bool `json:"recreated"`
}

func start(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--store"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}

	recreated := false
	sys, err := vmcompute.Open(id)
	if vmcompute.IsNotFound(err) {
		// HCS destroys a compute system when it exits, so a VM that has been stopped is
		// simply not there any more -- "stopped" is not a state HCS keeps. The store record
		// and the disk are what survive a power cycle, so start rebuilds the system from
		// them rather than reporting a VM the caller can plainly see in `vm ls` as missing.
		st, serr := openStore(a)
		if serr != nil {
			return cli.Failed, serr
		}
		record, rerr := readState(st, id)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				return cli.Failed, fmt.Errorf("no vm %s: not running, and no record in the store", id)
			}
			return cli.Failed, rerr
		}
		e.Progress("%s is not running; recreating it over %s", id, record.DiskPath)
		// The endpoint has to be remade with the system. An endpoint that was attached to the
		// compute system that just exited cannot be attached to the new one -- HCS rejects the
		// document with 0x803b0014, blaming a missing device. See remakeVMEndpoint.
		if record.EndpointID != "" {
			e.Progress("remaking endpoint %s so it can be attached again", record.EndpointID)
			if rerr := remakeVMEndpoint(record.NetworkID, record.EndpointID,
				endpointName(record.ID), record.MacAddress); rerr != nil {
				return cli.Failed, rerr
			}
		}
		if sys, err = createSystem(record); err != nil {
			return cli.Failed, err
		}
		recreated = true
	} else if err != nil {
		return cli.Failed, err
	}
	defer sys.Close()

	e.Progress("starting %s", id)
	began := time.Now()
	if err := sys.Start(startTimeout); err != nil {
		return cli.Failed, err
	}
	elapsed := time.Since(began).Milliseconds()

	e.Result(startResult{OK: true, Command: "vm start", ID: id, ElapsedMS: elapsed,
		Started: true, Recreated: recreated}, func() {
		fmt.Printf("started %s in %d ms\n", id, elapsed)
		fmt.Printf("the firmware is running; the guest OS is not necessarily up yet\n")
		fmt.Printf("wait for it with: hcsctl guest info --vmid %s\n", id)
	})
	return cli.OK, nil
}

// -- stop --------------------------------------------------------------------------------

type stopResult struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	ID      string `json:"id"`
	Method  string `json:"method"`
}

func stop(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--force", "--store"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}

	sys, err := vmcompute.Open(id)
	if vmcompute.IsNotFound(err) {
		// Already stopped. Reporting success is right: stop asks for a state, and the VM is
		// in it. An error here would make a teardown script fail on its second run.
		e.Result(stopResult{OK: true, Command: "vm stop", ID: id, Method: "already stopped"}, func() {
			fmt.Printf("%s is already stopped\n", id)
		})
		return cli.OK, nil
	}
	if err != nil {
		return cli.Failed, err
	}
	defer sys.Close()

	method := "shutdown"
	if a.Flag("--force") {
		method = "terminate"
		e.Progress("terminating %s", id)
		if err := sys.Terminate(terminateTimeout); err != nil {
			return cli.Failed, err
		}
	} else {
		e.Progress("shutting down %s through the guest integration service", id)
		if err := sys.Shutdown(shutdownTimeout); err != nil {
			return cli.Failed, fmt.Errorf("%w -- a guest without the shutdown integration service "+
				"cannot be asked; use --force to power it off", err)
		}
	}

	e.Result(stopResult{OK: true, Command: "vm stop", ID: id, Method: method}, func() {
		fmt.Printf("stopped %s (%s)\n", id, method)
	})
	return cli.OK, nil
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

func remove(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--force", "--store"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}
	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	record, staterr := readState(st, id)
	if staterr != nil && !os.IsNotExist(staterr) {
		return cli.Failed, staterr
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
		case a.Flag("--force"):
			res.Warnings = append(res.Warnings, "terminate: "+terr.Error())
		default:
			return cli.Failed, terr
		}
	} else if !vmcompute.IsNotFound(oerr) {
		// A VM that is simply not running is the ordinary case for rm and says nothing.
		// Anything else is reported, without failing the removal -- the disk and the record
		// still have to go.
		res.Warnings = append(res.Warnings, "open: "+oerr.Error())
	}

	// The endpoint goes after the terminate and before the store record. After, because an
	// endpoint attached to a running VM is in use; before, because the record is the only thing
	// that knows the endpoint's id -- delete the record first and a failure here leaks it with
	// nothing left pointing at it.
	if record.EndpointID != "" {
		if derr := deleteVMEndpoint(record.EndpointID); derr != nil {
			if !a.Flag("--force") {
				return cli.Failed, fmt.Errorf("%w -- the store record is kept so the endpoint can "+
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
			if !a.Flag("--force") {
				return cli.Failed, err
			}
			res.Warnings = append(res.Warnings, "remove "+dir+": "+err.Error())
		} else {
			res.Removed = append(res.Removed, dir)
		}
	} else {
		if err := os.RemoveAll(dir); err != nil && !a.Flag("--force") {
			return cli.Failed, err
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
	return cli.OK, nil
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

// ip waits for the address the guest leases.
//
// This verb exists because of a measurement, not a guess: an endpoint carries no address when it
// is created, none when it is attached to a NIC, and none while the compute system runs without
// a guest OS in it (#43, 2026-08-09). The address can only come from the guest's own DHCP
// client, so a consumer that wants one has to wait, and doing that by polling `vm inspect` in a
// shell loop is worse than doing it here.
//
// It waits, deliberately, rather than answering once. `vm start` returning means the firmware is
// running -- the guest has not booted, let alone leased -- so a single-shot read would answer
// "none" for every caller who did the obvious thing.
func ip(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--timeout", "--store"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}

	timeout := 60 * time.Second
	if s := a.Option("--timeout"); s != "" {
		d, perr := time.ParseDuration(s)
		if perr != nil || d <= 0 {
			return cli.Usage, cli.Usagef("--timeout must be a positive duration, e.g. 60s")
		}
		timeout = d
	}

	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Failed, fmt.Errorf("no vm %s in the store", id)
		}
		return cli.Failed, err
	}
	if record.EndpointID == "" {
		return cli.Failed, fmt.Errorf("vm %s has no network endpoint -- it was created without --network", id)
	}

	began := time.Now()
	deadline := began.Add(timeout)
	for {
		addrs, aerr := addressesOf(record.EndpointID)
		if aerr != nil {
			return cli.Failed, fmt.Errorf("reading endpoint %s: %w", record.EndpointID, aerr)
		}
		if len(addrs) > 0 {
			waited := time.Since(began).Milliseconds()
			e.Result(ipResult{OK: true, Command: "vm ip", ID: id, EndpointID: record.EndpointID,
				Addresses: addrs, WaitedMS: waited}, func() {
				fmt.Printf("%s\n", strings.Join(addrs, "\n"))
			})
			return cli.OK, nil
		}
		if time.Now().After(deadline) {
			// Named as the guest's failure, because that is what it is: the endpoint is fine
			// and HNS is fine, and nothing on the host can produce an address on its own.
			return cli.Failed, fmt.Errorf(
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
	ID       string `json:"id"`
	State    string `json:"state"`
	DiskPath string `json:"diskPath"`
	CPUs     uint64 `json:"cpus"`
	MemoryMB uint64 `json:"memoryMb"`
	Created  string `json:"createdUtc"`
}

type listResult struct {
	OK      bool        `json:"ok"`
	Command string      `json:"command"`
	VMs     []listEntry `json:"vms"`
}

func list(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--store"); err != nil {
		return cli.Usage, err
	}
	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	entries, err := os.ReadDir(vmsDir(st))
	if err != nil && !os.IsNotExist(err) {
		return cli.Failed, err
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
		})
	}
	sort.Slice(res.VMs, func(i, j int) bool { return res.VMs[i].Created < res.VMs[j].Created })

	e.Result(res, func() {
		if len(res.VMs) == 0 {
			fmt.Println("no vms")
			return
		}
		fmt.Printf("%-38s %-10s %-6s %-8s %s\n", "ID", "STATE", "CPUS", "MEMORY", "DISK")
		for _, v := range res.VMs {
			fmt.Printf("%-38s %-10s %-6d %-8d %s\n", v.ID, v.State, v.CPUs, v.MemoryMB, v.DiskPath)
		}
	})
	return cli.OK, nil
}

// hcsState asks HCS what it thinks, so ls reports the live state rather than what this tool
// last wrote. "stopped" is a store-side reading, not an HCS one: HCS has no stopped state,
// it destroys the compute system when it exits, so what is measured is its absence.
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
	if json.Unmarshal([]byte(props), &p) != nil || p.State == "" {
		return "unknown"
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

func inspect(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--store"); err != nil {
		return cli.Usage, err
	}
	id, err := requireID(a)
	if err != nil {
		return cli.Usage, err
	}
	st, err := openStore(a)
	if err != nil {
		return cli.Failed, err
	}
	record, err := readState(st, id)
	if err != nil {
		if os.IsNotExist(err) {
			return cli.Failed, fmt.Errorf("no vm %s in the store", id)
		}
		return cli.Failed, err
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
		if res.HCSError != "" {
			fmt.Printf("  hcs      %s\n", res.HCSError)
		}
	})
	return cli.OK, nil
}
