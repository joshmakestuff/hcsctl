//go:build windows

// Package container is the `hcsctl container` verb group: running a Hyper-V-isolated (xenon)
// Windows container on a materialized image chain.
//
// A xenon is built differently from a process-isolated (argon) container, and the difference is
// the whole reason this package does not reuse `hcsctl layer`:
//
//	argon  -- the host stacks the layers itself. ActivateLayer, PrepareLayer, GetLayerMountPath,
//	          and the resulting \\?\Volume{...} goes into ContainerConfig.VolumePath. PrepareLayer
//	          needs an enabled BUILTIN\Administrators SID at every container start.
//	xenon  -- the host stacks nothing. The scratch VHD and the read-only layer directories are
//	          handed to a utility VM, which does the stacking inside the guest. Only
//	          CreateScratchLayer runs on the host; there is no Activate/Prepare and no volume path.
//
// So the config is: LayerFolderPath = the scratch directory, Layers = the read-only chain
// (topmost first, each with a GUID derived from its directory name), HvPartition = true, and
// HvRuntime.ImagePath = the UtilityVM directory of the uppermost layer that has one -- which for
// a normal Windows image is the base layer.
//
// hcsshim's v1 CreateContainer is the route. internal/uvm is not importable, and the v2 path
// (uvm.CreateWCOW then hcsoci.CreateContainer) lives entirely behind internal/, so v1 is not a
// fallback here, it is the only public door.
//
// ELEVATED.
package container

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"golang.org/x/sys/windows"
)

// defaultCmd is chosen to prove the guest actually booted and is the OS we think it is, while
// exiting on its own so `run` does not need a timeout to make progress.
const defaultCmd = `cmd /c ver`

// startTimeout bounds the utility VM boot. A cold xenon on a slow disk is tens of seconds; well
// past that and something is wrong rather than slow.
const startTimeout = 5 * time.Minute

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "run":
		return run(a, e)
	case "create":
		return create(a, e)
	case "start":
		return start(a, e)
	case "exec":
		return exec(a, e)
	case "kill":
		return kill(a, e)
	case "stop":
		return stop(a, e)
	case "rm":
		return remove(a, e)
	case "ls":
		return list(a, e)
	case "stats":
		return stats(a, e)
	case "ps":
		return ps(a, e)
	case "inspect":
		return inspect(a, e)
	case "pause":
		return pauseResume(a, e, "pause")
	case "resume":
		return pauseResume(a, e, "resume")
	case "logs":
		return logsCmd(a, e)
	case "":
		return cli.Usage, cli.Usagef("container needs a subcommand: run, create, start, exec, kill, logs, stop, rm, ls, stats, ps, inspect, pause, resume")
	default:
		return cli.Usage, cli.Usagef("unknown container subcommand %q (expected run, create, start, exec, kill, logs, stop, rm, ls, stats, ps, inspect, pause, resume)", a.Word(1))
	}
}

// -- on-disk state -----------------------------------------------------------------------

// state is what `rm` and `ls` need after the creating process has exited. The compute system
// itself is host-global and reopenable by id, so this holds only what HCS does not: where the
// scratch lives and what it was built from.
type state struct {
	ID      string   `json:"id"`
	Ref     string   `json:"ref"`
	Scratch string   `json:"scratch"`
	UVM     string   `json:"utilityVM"`
	Chain   []string `json:"chain"`
	// Endpoint is here because endpoints are host-global and outlive the creating process:
	// `rm` after a crash must delete an endpoint it did not create.
	Endpoint  string   `json:"endpoint,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// Primary is the container's main workload (#33), recorded by `create --cmd` so a fresh
	// invocation can say what a running container is running, follow its retained output,
	// and report its exit after the starting invocation is gone.
	Primary *primaryState `json:"primary,omitempty"`
	// Labels are stored and reported, never interpreted (#31): ownership and run identity
	// are the consumer's policy, and the consumer is the only place that knows whether a
	// pid is alive. Scavenging by proof needs an owner recorded; this is where it lives.
	Labels map[string]string `json:"labels,omitempty"`
}

// primaryState survives the invocation that starts the process. Pipes cannot: whoever creates
// a guest process owns them, unrecoverably -- so `start` tees output to primary.log and this
// records who was pumping (PumpPid, a host pid) and how it ended. ExitCode is a pointer
// because 0 is an exit code and "never exited" must stay distinguishable.
type primaryState struct {
	Cmd        string `json:"cmd"`
	Pid        int    `json:"pid,omitempty"`
	PumpPid    int    `json:"pumpPid,omitempty"`
	StartedUTC string `json:"startedUtc,omitempty"`
	ExitCode   *int   `json:"exitCode,omitempty"`
	EndedUTC   string `json:"endedUtc,omitempty"`
}

func primaryLogPath(st *store.Store, id string) string {
	return filepath.Join(containerDir(st, id), "primary.log")
}

func containersRoot(st *store.Store) string { return filepath.Join(st.Root, "containers") }

func containerDir(st *store.Store, id string) string { return filepath.Join(containersRoot(st), id) }

// scratchDir is a subdirectory rather than the container directory itself, because DestroyLayer
// wants a layer directory and state.json is not part of a layer.
func scratchDir(st *store.Store, id string) string {
	return filepath.Join(containerDir(st, id), "scratch")
}

func statePath(st *store.Store, id string) string {
	return filepath.Join(containerDir(st, id), "state.json")
}

func writeState(st *store.Store, s state) error {
	// Failpoint (#19): the only way to reach a real state-write failure is after a real
	// acquisition -- scratch, endpoint, compute system -- which no hosted runner can do. The
	// env var makes the branch reachable from the elevated smoke path, so the cleanup below
	// it is proven by a run rather than trusted on inspection.
	if os.Getenv("HCSCTL_TEST_FAIL_WRITESTATE") != "" {
		return fmt.Errorf("injected failure: HCSCTL_TEST_FAIL_WRITESTATE is set")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(st, s.ID), b, 0o644)
}

func readState(st *store.Store, id string) (state, error) {
	var s state
	b, err := os.ReadFile(statePath(st, id))
	if err != nil {
		if os.IsNotExist(err) {
			return s, cli.Usagef("no container named %q in %s", id, containersRoot(st))
		}
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// idFor turns a reference into a usable id so --id can be optional. HCS ids are opaque strings,
// so the only requirement is that it also works as a directory name.
func idFor(ref string) string {
	return strings.NewReplacer("/", "_", ":", "_", "@", "_", "\\", "_").Replace(ref)
}

// newID is the only way create and run obtain an id; resolve is its counterpart for verbs
// acting on an existing container. Validation lives in these two functions rather than at
// call sites, so a future verb cannot forget it -- ids reach DestroyLayer and os.RemoveAll,
// commonly elevated.
func newID(a *cli.Args, ref string) (string, error) {
	id := a.Option("--id")
	if id == "" {
		id = idFor(ref)
	}
	if err := cli.ValidateID(id); err != nil {
		return "", err
	}
	return id, nil
}

// -- layer chain -------------------------------------------------------------------------

// chainFor resolves a reference to its materialized layer directories, topmost first, which is
// the order every wclayer call and ContainerConfig.Layers wants.
func chainFor(st *store.Store, ref string) ([]string, error) {
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cli.Usagef("no record for %s -- pull and import it first", ref)
		}
		return nil, err
	}
	// Structural soundness (non-empty, matched arrays, digest syntax) is ReadRecord's
	// guarantee -- one boundary, not a twin check here (#22).
	var chain []string
	for _, d := range rec.DiffIDs {
		p := st.LayerPath(d)
		if _, err := os.Stat(filepath.Join(p, "Files")); err != nil {
			return nil, cli.Usagef("layer %s is not materialized -- run image import", filepath.Base(p))
		}
		chain = append([]string{p}, chain...)
	}
	return chain, nil
}

// locateUVM finds the uppermost layer carrying a UtilityVM directory. This mirrors what
// hcsshim's internal uvmfolder.LocateUVMFolder does; it is six lines, and reimplementing it is
// cheaper than needing internal/.
func locateUVM(chain []string) (string, error) {
	for _, l := range chain {
		p := filepath.Join(l, "UtilityVM")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("no layer in the chain carries a UtilityVM directory -- this image cannot boot Hyper-V isolated (a Nano/Server Core base normally has one; a --platform-mismatched pull will not)")
}

// layersFor builds ContainerConfig.Layers. The GUID comes from the directory's base name, not
// its full path -- that is what hcsshim's own callers do, and HCS matches on it.
func layersFor(chain []string) ([]hcsshim.Layer, error) {
	var out []hcsshim.Layer
	for _, l := range chain {
		g, err := hcsshim.NameToGuid(filepath.Base(l))
		if err != nil {
			return nil, fmt.Errorf("NameToGuid(%s): %w", filepath.Base(l), err)
		}
		out = append(out, hcsshim.Layer{ID: g.ToString(), Path: l})
	}
	return out, nil
}

// -- network endpoint --------------------------------------------------------------------

// resolveNetwork accepts a name or an id, matching `network endpoints --network`. Reuse of an
// existing network is the whole posture: creating one is risky (one NAT network per host, and
// Docker usually owns it) and deliberately lives elsewhere -- see issue #15.
func resolveNetwork(want string) (*hcn.HostComputeNetwork, error) {
	nets, err := hcn.ListNetworks()
	if err != nil {
		return nil, fmt.Errorf("ListNetworks: %w", err)
	}
	for i := range nets {
		if strings.EqualFold(nets[i].Name, want) || strings.EqualFold(nets[i].Id, want) {
			return &nets[i], nil
		}
	}
	return nil, cli.Usagef("no network named or with id %q -- try `hcsctl network ls`", want)
}

// createEndpoint puts a new endpoint on the network. The returned document carries the
// address HNS allocated, which is the thing the caller wants reported.
func createEndpoint(netw *hcn.HostComputeNetwork, name string) (*hcn.HostComputeEndpoint, error) {
	ep := &hcn.HostComputeEndpoint{
		Name:               name,
		HostComputeNetwork: netw.Id,
		SchemaVersion:      hcn.V2SchemaVersion(),
	}
	created, err := ep.Create()
	if err != nil {
		return nil, fmt.Errorf("endpoint Create on %s: %w", netw.Name, err)
	}
	return created, nil
}

// deleteEndpoint removes an endpoint and verifies it is gone. Endpoints are host-global, so a
// silently failed delete is a leak that outlives every process -- the post-condition matters
// more than the return value, same as destroyScratch.
func deleteEndpoint(id string) error {
	ep, err := hcn.GetEndpointByID(id)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("GetEndpointByID(%s): %w", id, err)
	}
	if err := ep.Delete(); err != nil {
		return fmt.Errorf("endpoint Delete(%s): %w", id, err)
	}
	if _, err := hcn.GetEndpointByID(id); err == nil {
		return fmt.Errorf("endpoint %s still present after Delete", id)
	} else if !hcn.IsNotFoundError(err) {
		return fmt.Errorf("endpoint %s after Delete: %w", id, err)
	}
	return nil
}

// -- mounts ------------------------------------------------------------------------------

// mountRe wants both sides drive-letter absolute, which sidesteps the ambiguity a plain
// colon split has with Windows paths. `:ro` is the only suffix; read-write is the default
// and not a spelling.
var mountRe = regexp.MustCompile(`^([A-Za-z]:\\[^:]*):([A-Za-z]:\\[^:]*?)(:ro)?$`)

// parseMounts turns repeated --mount HOST:CONTAINER[:ro] into MappedDirectories. For a xenon
// these go over VSMB, not a bind mount -- different performance, different semantics, and the
// help text describes what it does rather than promising Docker parity.
func parseMounts(a *cli.Args) ([]hcsshim.MappedDir, error) {
	vals := a.Options("--mount")
	if len(vals) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]hcsshim.MappedDir, 0, len(vals))
	for _, v := range vals {
		m := mountRe.FindStringSubmatch(v)
		if m == nil {
			return nil, cli.Usagef("--mount wants HOST:CONTAINER[:ro] with both paths drive-letter absolute, got %q", v)
		}
		host, ctr := m[1], m[2]
		fi, err := os.Stat(host)
		if err != nil {
			return nil, cli.Usagef("--mount host path %s: %v", host, err)
		}
		if !fi.IsDir() {
			return nil, cli.Usagef("--mount host path %s is not a directory", host)
		}
		key := strings.ToLower(strings.TrimRight(ctr, `\`))
		if seen[key] {
			return nil, cli.Usagef("--mount container path %s given more than once", ctr)
		}
		seen[key] = true
		out = append(out, hcsshim.MappedDir{HostPath: host, ContainerPath: ctr, ReadOnly: m[3] != ""})
	}
	return out, nil
}

// reservedLabelKeys are what a consumer sees when it flattens state.json (or the inspect
// document) -- a label may not shadow one. Grown alongside the state struct's json tags.
var reservedLabelKeys = map[string]bool{
	"id": true, "ref": true, "scratch": true, "utilityVM": true, "chain": true,
	"endpoint": true, "addresses": true, "primary": true, "labels": true,
	"ok": true, "command": true, "state": true, "hcs": true,
}

// parseLabels is cli.ParseLabels with this package's reserved key set.
func parseLabels(a *cli.Args) (map[string]string, error) {
	return cli.ParseLabels(a, reservedLabelKeys)
}

// -- create ------------------------------------------------------------------------------

var createOptions = []string{"--ref", "--id", "--store", "--cpus", "--memory-mb", "--hostname",
	"--network", "--dns-search", "--mount", "--scratch-size", "--cmd", "--label"}

// buildConfig assembles the compute system document. Split out from create() because `run`
// needs the same document and the same failure messages.
func buildConfig(a *cli.Args, e cli.Emit, st *store.Store, id, ref string) (*hcsshim.ContainerConfig, state, error) {
	var s state

	// Every argument is validated before anything touches the disk, because exit 64 promises
	// nothing was attempted -- and because from CreateScratchLayer on, an early return has an
	// increasing amount to clean up.
	if a.Option("--dns-search") != "" && a.Option("--network") == "" {
		return nil, s, cli.Usagef("--dns-search only means something with --network")
	}
	var cpus, memoryMB uint64
	var err error
	if v := a.Option("--cpus"); v != "" {
		// ProcessorCount is a uint32 in the config document.
		if cpus, err = cli.ParseUint(v, math.MaxUint32); err != nil {
			return nil, s, cli.Usagef("--cpus %v", err)
		}
	}
	if v := a.Option("--memory-mb"); v != "" {
		// MemoryMaximumInMB is an int64 in the config document.
		if memoryMB, err = cli.ParseUint(v, math.MaxInt64); err != nil {
			return nil, s, cli.Usagef("--memory-mb %v", err)
		}
	}
	mounts, err := parseMounts(a)
	if err != nil {
		return nil, s, err
	}
	labels, err := parseLabels(a)
	if err != nil {
		return nil, s, err
	}
	var scratchSize uint64
	if v := a.Option("--scratch-size"); v != "" {
		if scratchSize, err = cli.ParseSize(v); err != nil {
			return nil, s, err
		}
	}

	chain, err := chainFor(st, ref)
	if err != nil {
		return nil, s, err
	}
	uvm, err := locateUVM(chain)
	if err != nil {
		return nil, s, err
	}
	layers, err := layersFor(chain)
	if err != nil {
		return nil, s, err
	}

	// Resolved before anything touches the disk, so a bad name is exit 64 with nothing to
	// clean up.
	var netw *hcn.HostComputeNetwork
	if want := a.Option("--network"); want != "" {
		if netw, err = resolveNetwork(want); err != nil {
			return nil, s, err
		}
	}

	sd := scratchDir(st, id)
	if _, err := os.Stat(containerDir(st, id)); err == nil {
		return nil, s, cli.Usagef("a container named %q already exists at %s -- rm it first", id, containerDir(st, id))
	}
	if err := os.MkdirAll(sd, 0o755); err != nil {
		return nil, s, err
	}

	e.Progress("chain:     %d layer(s), topmost %s", len(chain), filepath.Base(chain[0]))
	e.Progress("utilityVM: %s", uvm)
	e.Progress("scratch:   %s", sd)

	// The only host-side storage step a xenon needs. No ActivateLayer, no PrepareLayer: the
	// utility VM does the stacking, which is also why a xenon does not hit the
	// BUILTIN\Administrators SID check that PrepareLayer imposes on every argon start.
	if err := hcsshim.CreateScratchLayer(hcsshim.DriverInfo{}, sd, "", chain); err != nil {
		os.RemoveAll(containerDir(st, id))
		return nil, s, fmt.Errorf("CreateScratchLayer (rerun elevated?): %w", err)
	}
	e.Progress("CreateScratchLayer ok")

	if scratchSize != 0 {
		if err := hcsshim.ExpandScratchSize(hcsshim.DriverInfo{}, sd, scratchSize); err != nil {
			destroyScratch(st, id)
			return nil, s, fmt.Errorf("ExpandScratchSize: %w", err)
		}
		e.Progress("ExpandScratchSize to %d bytes ok", scratchSize)
	}

	var ep *hcn.HostComputeEndpoint
	var addrs []string
	if netw != nil {
		if ep, err = createEndpoint(netw, id+"-ep"); err != nil {
			destroyScratch(st, id)
			return nil, s, err
		}
		for _, ip := range ep.IpConfigurations {
			addrs = append(addrs, fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength))
		}
		e.Progress("endpoint:  %s on %s (%s)", ep.Id, netw.Name, strings.Join(addrs, ","))
	}

	cfg := &hcsshim.ContainerConfig{
		SystemType:      "Container",
		Name:            id,
		Owner:           "hcsctl",
		LayerFolderPath: sd,
		Layers:          layers,
		HvPartition:     true,
		HvRuntime:       &hcsshim.HvRuntime{ImagePath: uvm},
		// Without this a terminated container can outlive the process that made it and hold
		// the scratch open, which turns a failed run into a manual cleanup.
		TerminateOnLastHandleClosed: false,
	}
	if h := a.Option("--hostname"); h != "" {
		cfg.HostName = h
	}
	if cpus != 0 {
		cfg.ProcessorCount = uint32(cpus)
	}
	if memoryMB != 0 {
		cfg.MemoryMaximumInMB = int64(memoryMB)
	}
	cfg.MappedDirectories = mounts
	if ep != nil {
		cfg.EndpointList = []string{ep.Id}
		// Unqualified lookups are what a developer's `ping example.com` is, so this defaults
		// on rather than being a switch nobody remembers.
		cfg.AllowUnqualifiedDNSQuery = true
		cfg.DNSSearchList = a.Option("--dns-search")
	}

	s = state{ID: id, Ref: ref, Scratch: sd, UVM: uvm, Chain: chain, Labels: labels}
	if ep != nil {
		s.Endpoint = ep.Id
		s.Addresses = addrs
	}
	return cfg, s, nil
}

func create(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown(createOptions...); err != nil {
		return cli.Usage, err
	}
	ref, err := a.Require("--ref")
	if err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	id, err := newID(a, ref)
	if err != nil {
		return cli.Usage, err
	}

	cfg, s, err := buildConfig(a, e, st, id, ref)
	if err != nil {
		return exitFor(err), err
	}
	// The primary process (#33) is recorded, not started: `start` launches it. The cmd
	// should be the target directly, not a `cmd /c` wrapper -- Kill terminates one process,
	// not a tree (findings.md), and a wrapper's children would survive a later kill.
	if cmd := a.Option("--cmd"); cmd != "" {
		s.Primary = &primaryState{Cmd: cmd}
	}

	c, err := hcsshim.CreateContainer(id, cfg)
	if err != nil {
		destroy(st, s)
		return cli.Failed, fmt.Errorf("CreateContainer: %w", err)
	}

	// State is part of the creation transaction (#19): without state.json, `rm` can never
	// find any of this again, so a failed write tears down the compute system -- while the
	// handle is still open -- then the endpoint and scratch. The write error stays the
	// reported one; cleanup failures are progress, not the verdict.
	if err := writeState(st, s); err != nil {
		if terr := shutdown(c, e, true); terr != nil {
			e.Progress("cleanup after failed state write: %v", terr)
		}
		c.Close()
		if derr := destroy(st, s); derr != nil {
			e.Progress("cleanup after failed state write: %v", derr)
		}
		return cli.Failed, fmt.Errorf("writing state: %w", err)
	}
	// The handle is dropped here on purpose: the compute system outlives this process and is
	// reopened by id. state.json records what HCS does not.
	c.Close()
	e.Result(map[string]any{
		"ok": true, "command": "container create", "id": id, "ref": ref,
		"utilityVM": s.UVM, "scratch": s.Scratch, "chain": s.Chain,
		"endpoint": s.Endpoint, "addresses": s.Addresses,
	}, func() {
		fmt.Printf("created %s\n  id:      %s\n  scratch: %s\n", ref, id, s.Scratch)
		if s.Endpoint != "" {
			fmt.Printf("  address: %s\n", strings.Join(s.Addresses, ","))
		}
	})
	return cli.OK, nil
}

// -- start / stop ------------------------------------------------------------------------

func start(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	s, err := readState(st, id)
	if err != nil {
		return exitFor(err), err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	defer c.Close()

	e.Progress("starting utility VM...")
	if err := c.Start(); err != nil {
		return cli.Failed, fmt.Errorf("Start: %w", err)
	}

	if s.Primary == nil {
		e.Result(map[string]any{"ok": true, "command": "container start", "id": id}, func() {
			fmt.Printf("started %s\n", id)
		})
		return cli.OK, nil
	}

	// A primary process is recorded (#33): launch it and stay attached as its pump. This
	// invocation owns the pipes -- HCS gives them out once, to the creator, unrecoverably --
	// so it tees everything to primary.log, where `container logs` can follow from any fresh
	// invocation, and records the exit in state.json when the process ends. If this pump
	// dies with its caller, the workload keeps running; the log truncates at that moment and
	// `logs` reports the pump's death rather than pretending the file is complete.
	logFile, err := os.Create(primaryLogPath(st, id))
	if err != nil {
		return cli.Failed, fmt.Errorf("primary.log: %w", err)
	}
	defer logFile.Close()
	e.Progress("primary: %s", s.Primary.Cmd)

	out := &captured{json: e.JSON}
	outSink, errSink, closeFraming := guestSinks(e, out)
	lw := &lockedWriter{w: logFile}
	outSink, errSink = io.MultiWriter(lw, outSink), io.MultiWriter(lw, errSink)

	onStart := func(pid int) {
		s.Primary.Pid = pid
		s.Primary.PumpPid = os.Getpid()
		s.Primary.StartedUTC = time.Now().UTC().Format(time.RFC3339)
		if werr := writeState(st, s); werr != nil {
			// Bookkeeping must not kill a started workload; `logs` degrades honestly.
			e.Progress("recording primary pid: %v", werr)
		}
	}
	res, execErr := execIn(c, e, s.Primary.Cmd, "", "", nil, 0, outSink, errSink, onStart)
	closeFraming()

	s.Primary.PumpPid = 0
	s.Primary.EndedUTC = time.Now().UTC().Format(time.RFC3339)
	if execErr == nil {
		s.Primary.ExitCode = &res.ExitCode
	}
	if werr := writeState(st, s); werr != nil {
		e.Progress("recording primary exit: %v", werr)
	}
	if execErr != nil {
		return cli.Failed, execErr
	}
	e.Result(map[string]any{
		"ok": true, "command": "container start", "id": id,
		"primary": map[string]any{"cmd": s.Primary.Cmd, "pid": res.Pid, "exitCode": res.ExitCode},
	}, func() {
		fmt.Printf("started %s; primary pid %d exited %d\n", id, res.Pid, res.ExitCode)
	})
	return cli.OK, nil
}

// lockedWriter serializes two concurrent guest streams into one log file, so lines from
// stdout and stderr cannot interleave mid-chunk.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func stop(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store", "--force"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	if _, err := readState(st, id); err != nil {
		return exitFor(err), err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	defer c.Close()

	if err := shutdown(c, e, a.Flag("--force")); err != nil {
		return cli.Failed, err
	}
	e.Result(map[string]any{"ok": true, "command": "container stop", "id": id}, func() {
		fmt.Printf("stopped %s\n", id)
	})
	return cli.OK, nil
}

// shutdown asks politely, then insists. Both Shutdown and Terminate report
// ErrVmcomputeOperationPending on success -- the operation is asynchronous and Wait is what
// actually confirms it -- so a pending error here is not an error.
func shutdown(c hcsshim.Container, e cli.Emit, force bool) error {
	if !force {
		err := c.Shutdown()
		if err == nil || hcsshim.IsPending(err) {
			if werr := c.WaitTimeout(30 * time.Second); werr == nil {
				e.Progress("shutdown ok")
				return nil
			}
			e.Progress("shutdown did not complete in 30s, terminating")
		} else if hcsshim.IsAlreadyStopped(err) {
			return nil
		} else {
			e.Progress("shutdown: %v -- terminating", err)
		}
	}
	err := c.Terminate()
	if err != nil && !hcsshim.IsPending(err) && !hcsshim.IsAlreadyStopped(err) {
		return fmt.Errorf("Terminate: %w", err)
	}
	if err := c.WaitTimeout(60 * time.Second); err != nil && !hcsshim.IsAlreadyStopped(err) {
		return fmt.Errorf("wait after Terminate: %w", err)
	}
	e.Progress("terminate ok")
	return nil
}

// -- exec --------------------------------------------------------------------------------

// parseEnv turns repeated --env NAME=value into ProcessConfig.Environment. The value keeps
// everything after the first '='. An empty value is an error rather than a pass-through:
// hcsshim sends {"NAME":""} over the wire intact, but the variable never appears in the guest
// (measured against servercore:ltsc2022 -- Win32 treats empty as deleted), and a silent drop
// is worse than a loud one. There is no inherited environment here, so "unset" is expressed
// by omitting the variable.
func parseEnv(a *cli.Args) (map[string]string, error) {
	vals := a.Options("--env")
	if len(vals) == 0 {
		return nil, nil
	}
	env := make(map[string]string, len(vals))
	for _, v := range vals {
		name, value, found := strings.Cut(v, "=")
		if !found || name == "" {
			return nil, cli.Usagef("--env wants NAME=value, got %q", v)
		}
		if value == "" {
			return nil, cli.Usagef("--env %s= has an empty value, which HCS drops before the guest sees it -- omit the variable instead", name)
		}
		env[name] = value
	}
	return env, nil
}

// parseTimeout reads --timeout as a Go duration. Zero means absent, which means wait
// forever -- the default an integration's log-following exec depends on, so the bound is
// strictly opt-in.
func parseTimeout(a *cli.Args) (time.Duration, error) {
	v := a.Option("--timeout")
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, cli.Usagef("--timeout wants a positive duration like 30s or 2m, got %q", v)
	}
	return d, nil
}

// killWait bounds the wait for a Kill to take effect. A process that survives its kill this
// long is a failure to report, not a thing to wait harder on.
const killWait = 10 * time.Second

// execResult is what execIn measured. ExitCode is meaningful only when TimedOut is false: a
// killed process's code is an invention of the kill, not something the guest produced.
type execResult struct {
	ExitCode int
	Pid      int
	TimedOut bool
}

// execIn launches a process, streams its output, and returns its exit code. Stdin is closed
// immediately: nothing here is interactive, and a process blocked on a stdin that never closes
// looks exactly like a hung container. A non-zero timeout kills the process on expiry.
// onStart, when non-nil, runs with the guest pid as soon as the process exists -- the
// primary-process path records it in state.json while the process is still running (#33).
func execIn(c hcsshim.Container, e cli.Emit, cmdline, cwd, user string, env map[string]string, timeout time.Duration, outSink, errSink io.Writer, onStart func(pid int)) (execResult, error) {
	var res execResult
	res.ExitCode = -1
	pc := &hcsshim.ProcessConfig{
		CommandLine:      cmdline,
		WorkingDirectory: cwd,
		User:             user,
		Environment:      env,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	}
	p, err := c.CreateProcess(pc)
	if err != nil {
		return res, fmt.Errorf("CreateProcess(%q): %w", cmdline, err)
	}
	defer p.Close()
	res.Pid = p.Pid()
	if onStart != nil {
		onStart(res.Pid)
	}

	stdin, stdout, stderr, err := p.Stdio()
	if err != nil {
		return res, fmt.Errorf("Stdio: %w", err)
	}
	if stdin != nil {
		stdin.Close()
	}
	_ = p.CloseStdin()

	// Both streams are drained concurrently. Draining them in sequence deadlocks as soon as the
	// guest fills the pipe this side is not reading. The sinks are separate so --stream-json
	// can attribute guest stdout and stderr individually (#28); without it both are the same
	// merged writer, exactly as before.
	var wg sync.WaitGroup
	for _, s := range []struct {
		r    io.ReadCloser
		sink io.Writer
	}{{stdout, outSink}, {stderr, errSink}} {
		if s.r == nil {
			continue
		}
		wg.Add(1)
		go func(r io.ReadCloser, sink io.Writer) {
			defer wg.Done()
			defer r.Close()
			io.Copy(sink, r)
		}(s.r, s.sink)
	}

	if timeout > 0 {
		if err := p.WaitTimeout(timeout); err != nil {
			if !hcsshim.IsTimeout(err) {
				wg.Wait()
				return res, fmt.Errorf("process WaitTimeout: %w", err)
			}
			// Expired: kill, then confirm the kill landed rather than trusting it. "We gave
			// up on it" and "it exited" must stay distinguishable, so the exit code is not
			// collected -- it would be the kill's invention, not the guest's.
			res.TimedOut = true
			e.Progress("timeout %s expired, killing pid %d", timeout, res.Pid)
			if err := p.Kill(); err != nil {
				wg.Wait()
				return res, fmt.Errorf("Kill after %s timeout: %w", timeout, err)
			}
			if err := p.WaitTimeout(killWait); err != nil {
				wg.Wait()
				return res, fmt.Errorf("pid %d still running %s after Kill: %w", res.Pid, killWait, err)
			}
			wg.Wait()
			return res, nil
		}
	} else if err := p.Wait(); err != nil {
		wg.Wait()
		return res, fmt.Errorf("process Wait: %w", err)
	}
	wg.Wait()

	code, err := p.ExitCode()
	if err != nil {
		return res, fmt.Errorf("ExitCode: %w", err)
	}
	res.ExitCode = code
	return res, nil
}

func exec(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store", "--cmd", "--cwd", "--user", "--env", "--timeout"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	cmdline, err := a.Require("--cmd")
	if err != nil {
		return cli.Usage, err
	}
	env, err := parseEnv(a)
	if err != nil {
		return cli.Usage, err
	}
	timeout, err := parseTimeout(a)
	if err != nil {
		return cli.Usage, err
	}
	if _, err := readState(st, id); err != nil {
		return exitFor(err), err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	defer c.Close()

	out := &captured{json: e.JSON}
	outSink, errSink, closeFraming := guestSinks(e, out)
	res, err := execIn(c, e, cmdline, a.Option("--cwd"), a.Option("--user"), env, timeout, outSink, errSink, nil)
	closeFraming()
	if err != nil {
		return cli.Failed, err
	}
	e.Result(execDoc("container exec", id, cmdline, res, out), func() {
		printExec(res)
	})
	return cli.OK, nil
}

// guestSinks wires guest output for one exec (#28). Default: both guest streams merge into
// the captured buffer, which tees live -- exactly the pre-#28 behaviour. Under --stream-json
// (with --json), each stream additionally flows through its own NDJSON line framer, the tee
// goes quiet (the framers own stderr now), and the buffer keeps serving the final document's
// merged output field unchanged.
func guestSinks(e cli.Emit, out *captured) (outSink, errSink io.Writer, closeFraming func()) {
	if !e.JSON || !e.StreamJSON {
		return out, out, func() {}
	}
	out.quiet = true
	so := cli.NewStreamWriter(e, "stdout")
	se := cli.NewStreamWriter(e, "stderr")
	return io.MultiWriter(out, so), io.MultiWriter(out, se), func() {
		so.Close()
		se.Close()
	}
}

// execDoc is the shared shape of an exec-like result. A timed-out process gets exitCode null
// -- the guest never produced one, and inventing it would make "gave up" look like "exited".
func execDoc(command, id, cmdline string, res execResult, out *captured) map[string]any {
	doc := map[string]any{
		"ok": true, "command": command, "id": id,
		"cmd": cmdline, "pid": res.Pid, "timedOut": res.TimedOut,
		"output": out.String(),
	}
	if res.TimedOut {
		doc["exitCode"] = nil
	} else {
		doc["exitCode"] = res.ExitCode
	}
	return doc
}

func printExec(res execResult) {
	if res.TimedOut {
		fmt.Printf("timed out, killed pid %d\n", res.Pid)
		return
	}
	fmt.Printf("exit code: %d\n", res.ExitCode)
}

// captured tees guest output. In JSON mode it must not reach stdout -- stdout carries exactly
// one document -- so it goes to stderr live and into the document at the end.
type captured struct {
	json bool
	// quiet suppresses the live tee: under --stream-json the framing writers own stderr,
	// and this buffer serves only the final document's output field (#28).
	quiet bool
	mu    sync.Mutex
	buf   strings.Builder
}

func (c *captured) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	if c.quiet {
		return len(p), nil
	}
	if c.json {
		return os.Stderr.Write(p)
	}
	return os.Stdout.Write(p)
}

func (c *captured) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// -- run ---------------------------------------------------------------------------------

// run is create + start + exec + stop + rm in one call: the shape you want for a smoke test and
// for one-shot work, and the shape that leaves nothing behind when a step fails.
func run(a *cli.Args, e cli.Emit) (int, error) {
	known := append([]string{"--cmd", "--cwd", "--user", "--env", "--timeout", "--keep"}, createOptions...)
	if err := a.RejectUnknown(known...); err != nil {
		return cli.Usage, err
	}
	ref, err := a.Require("--ref")
	if err != nil {
		return cli.Usage, err
	}
	env, err := parseEnv(a)
	if err != nil {
		return cli.Usage, err
	}
	timeout, err := parseTimeout(a)
	if err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	id, err := newID(a, ref)
	if err != nil {
		return cli.Usage, err
	}
	cmdline := a.Option("--cmd")
	if cmdline == "" {
		cmdline = defaultCmd
	}

	cfg, s, err := buildConfig(a, e, st, id, ref)
	if err != nil {
		return exitFor(err), err
	}
	// Same transaction rule as create (#19): buildConfig has acquired the scratch and any
	// endpoint by now, and without state.json nothing can ever find them to clean them up.
	if err := writeState(st, s); err != nil {
		if derr := destroy(st, s); derr != nil {
			e.Progress("cleanup after failed state write: %v", derr)
		}
		return cli.Failed, fmt.Errorf("writing state: %w", err)
	}

	c, err := hcsshim.CreateContainer(id, cfg)
	if err != nil {
		destroy(st, s)
		return cli.Failed, fmt.Errorf("CreateContainer: %w", err)
	}
	e.Progress("CreateContainer ok")

	// From here the container exists in HCS and must be torn down on every path out.
	cleanup := func() {
		if a.Flag("--keep") {
			e.Progress("--keep: leaving %s in place", id)
			c.Close()
			return
		}
		if err := shutdown(c, e, false); err != nil {
			e.Progress("teardown: %v", err)
		}
		c.Close()
		if err := destroy(st, s); err != nil {
			e.Progress("teardown: %v", err)
		}
	}

	e.Progress("starting utility VM...")
	started := make(chan error, 1)
	go func() { started <- c.Start() }()
	select {
	case err := <-started:
		if err != nil {
			cleanup()
			return cli.Failed, fmt.Errorf("Start: %w", err)
		}
	case <-time.After(startTimeout):
		cleanup()
		return cli.Failed, fmt.Errorf("utility VM did not start within %s", startTimeout)
	}
	e.Progress("started")

	out := &captured{json: e.JSON}
	outSink, errSink, closeFraming := guestSinks(e, out)
	res, execErr := execIn(c, e, cmdline, a.Option("--cwd"), a.Option("--user"), env, timeout, outSink, errSink, nil)
	closeFraming()
	cleanup()
	if execErr != nil {
		return cli.Failed, execErr
	}

	// The CLI's own exit code stays on contract -- 0 means hcsctl ran the thing -- and the
	// guest's exit code is reported in the document rather than conflated with it.
	doc := execDoc("container run", id, cmdline, res, out)
	doc["ref"] = ref
	doc["utilityVM"] = s.UVM
	doc["kept"] = a.Flag("--keep")
	doc["endpoint"] = s.Endpoint
	doc["addresses"] = s.Addresses
	e.Result(doc, func() {
		printExec(res)
	})
	return cli.OK, nil
}

// kill terminates one guest process by pid. It exists because an exec that hcsctl no longer
// owns -- a crashed caller, an abandoned long-running app -- leaves a process nothing can
// reach: HCS pipes belong to whoever created them, but Kill needs only the pid.
func kill(a *cli.Args, e cli.Emit) (int, error) {
	// The whole command line is judged before any container lookup, so a bad --pid is exit 64
	// even when the container does not exist either.
	if err := a.RejectUnknown("--id", "--ref", "--store", "--pid"); err != nil {
		return cli.Usage, err
	}
	v, err := a.Require("--pid")
	if err != nil {
		return cli.Usage, err
	}
	// OpenProcess takes an int and a Windows pid is a DWORD; MaxInt32 satisfies both sinks,
	// and no real pid approaches it.
	pid, err := cli.ParseUint(v, math.MaxInt32)
	if err != nil {
		return cli.Usage, cli.Usagef("--pid %v", err)
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	if _, err := readState(st, id); err != nil {
		return exitFor(err), err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	defer c.Close()

	// A pid that is not there is a runtime fact, not a bad command line: the process may have
	// exited a moment ago, and exit 1 with the message is the honest report.
	p, err := c.OpenProcess(int(pid))
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer p.Close()

	if err := p.Kill(); err != nil {
		return cli.Failed, fmt.Errorf("Kill(%d): %w", pid, err)
	}
	// The post-condition, not the return value: Kill signals, WaitTimeout is what confirms.
	if err := p.WaitTimeout(killWait); err != nil {
		return cli.Failed, fmt.Errorf("pid %d still running %s after Kill: %w", pid, killWait, err)
	}

	e.Result(map[string]any{
		"ok": true, "command": "container kill", "id": id, "pid": pid, "killed": true,
	}, func() {
		fmt.Printf("killed pid %d in %s\n", pid, id)
	})
	return cli.OK, nil
}

// -- rm / ls -----------------------------------------------------------------------------

// destroyScratch removes the scratch layer and the container directory. DestroyLayer rather than
// os.RemoveAll: layer directories carry restored security descriptors that defeat ordinary file
// deletion, which shows up as a wall of access-denied rather than a clean failure.
func destroyScratch(st *store.Store, id string) error {
	sd := scratchDir(st, id)
	if _, err := os.Stat(sd); err == nil {
		if err := hcsshim.DestroyLayer(hcsshim.DriverInfo{}, sd); err != nil {
			return fmt.Errorf("DestroyLayer(%s): %w", sd, err)
		}
		// The post-condition, not the return value: DestroyLayer can report success and leave
		// the tree behind.
		if _, err := os.Stat(sd); err == nil {
			return fmt.Errorf("scratch still present after DestroyLayer: %s", sd)
		}
	}
	return os.RemoveAll(containerDir(st, id))
}

// destroy tears down everything a container owns outside HCS: its endpoint, then its scratch.
// Every step is attempted regardless of earlier failures -- a half-torn-down container should
// lose as much as possible -- and the first error is what gets reported.
func destroy(st *store.Store, s state) error {
	var first error
	if s.Endpoint != "" {
		first = deleteEndpoint(s.Endpoint)
	}
	if err := destroyScratch(st, s.ID); err != nil && first == nil {
		first = err
	}
	return first
}

func remove(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store", "--force"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	s, err := readState(st, id)
	if err != nil {
		return exitFor(err), err
	}

	// A container that is gone from HCS but still on disk is the normal state after a crash, so
	// a failure to open is not fatal here -- the scratch and endpoint still need removing.
	if c, err := hcsshim.OpenContainer(id); err == nil {
		if err := shutdown(c, e, a.Flag("--force")); err != nil {
			e.Progress("stop: %v", err)
		}
		c.Close()
	} else if !hcsshim.IsNotExist(err) {
		e.Progress("OpenContainer: %v -- removing on-disk state anyway", err)
	}

	if err := destroy(st, s); err != nil {
		return cli.Failed, err
	}
	e.Result(map[string]any{"ok": true, "command": "container rm", "id": id}, func() {
		fmt.Printf("removed %s\n", id)
	})
	return cli.OK, nil
}

func list(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--store"); err != nil {
		return cli.Usage, err
	}
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return cli.Failed, err
	}
	entries, err := os.ReadDir(containersRoot(st))
	if err != nil && !os.IsNotExist(err) {
		return cli.Failed, err
	}

	// HCS is the authority on whether a container is running; the store is the authority on
	// what it was made from. Neither alone gives a useful listing.
	running := map[string]string{}
	if props, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{}); err == nil {
		for _, p := range props {
			running[p.ID] = p.State
		}
	} else {
		e.Progress("GetContainers: %v -- state column will be unknown", err)
	}

	type row struct {
		ID     string            `json:"id"`
		Ref    string            `json:"ref"`
		State  string            `json:"state"`
		Labels map[string]string `json:"labels,omitempty"`
	}
	var rows []row
	for _, en := range entries {
		if !en.IsDir() {
			continue
		}
		s, err := readState(st, en.Name())
		if err != nil {
			continue
		}
		// Three distinct situations, and the empty one is the interesting one: HCS reports a
		// created-but-never-started compute system with a blank State, which is not the same as
		// having no compute system at all.
		hcsState, ok := running[en.Name()]
		switch {
		case !ok:
			hcsState = "absent"
		case hcsState == "":
			hcsState = "created"
		}
		rows = append(rows, row{ID: s.ID, Ref: s.Ref, State: hcsState, Labels: s.Labels})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	e.Result(map[string]any{"ok": true, "command": "container ls", "containers": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no containers")
			return
		}
		for _, r := range rows {
			fmt.Printf("%-40s %-12s %s\n", r.ID, r.State, r.Ref)
		}
	})
	return cli.OK, nil
}

// -- introspection -----------------------------------------------------------------------

// open is the common preamble for every verb that inspects a live container: resolve the id,
// confirm we know about it, and get a handle.
func open(a *cli.Args, known ...string) (hcsshim.Container, string, error) {
	if err := a.RejectUnknown(append([]string{"--id", "--ref", "--store"}, known...)...); err != nil {
		return nil, "", err
	}
	st, id, err := resolve(a)
	if err != nil {
		return nil, "", err
	}
	if _, err := readState(st, id); err != nil {
		return nil, id, err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return nil, id, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	return c, id, nil
}

func stats(a *cli.Args, e cli.Emit) (int, error) {
	c, id, err := open(a)
	if err != nil {
		return exitFor(err), err
	}
	defer c.Close()

	s, err := c.Statistics()
	if err != nil {
		return cli.Failed, fmt.Errorf("Statistics: %w", err)
	}
	e.Result(map[string]any{
		"ok": true, "command": "container stats", "id": id, "statistics": s,
	}, func() {
		// 100ns ticks are what HCS reports; seconds are what a person wants.
		fmt.Printf("uptime            %s\n", time.Duration(s.Uptime100ns*100))
		fmt.Printf("started           %s\n", s.ContainerStartTime.Format(time.RFC3339))
		fmt.Printf("memory commit     %s\n", bytes(s.Memory.UsageCommitBytes))
		fmt.Printf("memory peak       %s\n", bytes(s.Memory.UsageCommitPeakBytes))
		fmt.Printf("working set priv  %s\n", bytes(s.Memory.UsagePrivateWorkingSetBytes))
		fmt.Printf("cpu total         %s\n", time.Duration(s.Processor.TotalRuntime100ns*100))
		fmt.Printf("cpu user/kernel   %s / %s\n",
			time.Duration(s.Processor.RuntimeUser100ns*100),
			time.Duration(s.Processor.RuntimeKernel100ns*100))
		fmt.Printf("storage r/w       %d / %d ops\n",
			s.Storage.ReadCountNormalized, s.Storage.WriteCountNormalized)
		for i, n := range s.Network {
			fmt.Printf("net[%d] rx/tx      %s / %s\n", i, bytes(n.BytesReceived), bytes(n.BytesSent))
		}
	})
	return cli.OK, nil
}

func ps(a *cli.Args, e cli.Emit) (int, error) {
	c, id, err := open(a)
	if err != nil {
		return exitFor(err), err
	}
	defer c.Close()

	procs, err := c.ProcessList()
	if err != nil {
		return cli.Failed, fmt.Errorf("ProcessList: %w", err)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].ProcessId < procs[j].ProcessId })

	e.Result(map[string]any{
		"ok": true, "command": "container ps", "id": id, "processes": procs,
	}, func() {
		if len(procs) == 0 {
			fmt.Println("no processes")
			return
		}
		fmt.Printf("%8s  %-32s %12s %12s\n", "PID", "IMAGE", "COMMIT", "CPU")
		for _, p := range procs {
			fmt.Printf("%8d  %-32s %12s %12s\n",
				p.ProcessId, trunc(p.ImageName, 32), bytes(p.MemoryCommitBytes),
				time.Duration((p.KernelTime100ns+p.UserTime100ns)*100).Round(time.Millisecond))
		}
	})
	return cli.OK, nil
}

// inspect reports what HCS itself knows, which is a different and larger set than state.json.
func inspect(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	s, err := readState(st, id)
	if err != nil {
		return exitFor(err), err
	}

	// GetContainers rather than OpenContainer().Properties(): it answers for a container that
	// exists but was never started, where an open handle tells you very little.
	props, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{IDs: []string{id}})
	if err != nil {
		return cli.Failed, fmt.Errorf("GetContainers: %w", err)
	}

	doc := map[string]any{"ok": true, "command": "container inspect", "id": id, "state": s}
	if len(props) > 0 {
		doc["hcs"] = props[0]
	} else {
		doc["hcs"] = nil
	}
	e.Result(doc, func() {
		fmt.Printf("id         %s\nref        %s\nscratch    %s\nutilityVM  %s\n",
			s.ID, s.Ref, s.Scratch, s.UVM)
		fmt.Printf("chain      %d layer(s)\n", len(s.Chain))
		for _, l := range s.Chain {
			fmt.Printf("           %s\n", l)
		}
		if len(props) == 0 {
			fmt.Println("hcs        absent (not created, or already torn down)")
			return
		}
		p := props[0]
		fmt.Printf("hcs state  %s\n", orDash(p.State))
		fmt.Printf("owner      %s\n", orDash(p.Owner))
		fmt.Printf("systemType %s\n", orDash(p.SystemType))
		if p.RuntimeImagePath != "" {
			fmt.Printf("runtimeImg %s\n", p.RuntimeImagePath)
		}
		if p.Stopped {
			fmt.Printf("stopped    true (exitType %s)\n", orDash(p.ExitType))
		}
	})
	return cli.OK, nil
}

// pauseResume covers both because they are the same verb with a different call and a different
// past participle, and splitting them duplicates the whole preamble.
func pauseResume(a *cli.Args, e cli.Emit, verb string) (int, error) {
	c, id, err := open(a)
	if err != nil {
		return exitFor(err), err
	}
	defer c.Close()

	call, done, api := c.Pause, "paused", "Pause"
	if verb == "resume" {
		call, done, api = c.Resume, "resumed", "Resume"
	}
	if err := call(); err != nil {
		return cli.Failed, fmt.Errorf("%s: %w", api, err)
	}
	e.Result(map[string]any{
		"ok": true, "command": "container " + verb, "id": id,
	}, func() { fmt.Printf("%s %s\n", done, id) })
	return cli.OK, nil
}

func bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

// -- logs --------------------------------------------------------------------------------

// logsCmd reads a primary process's retained output from a fresh invocation (#33). It reads
// the file the pump wrote, never the pipes -- those died with their creator. Status comes
// from state.json and is reported honestly: running (pump alive), exited (code recorded), or
// pump dead (the log may be truncated and the exit unrecorded).
func logsCmd(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store", "--follow"); err != nil {
		return cli.Usage, err
	}
	st, id, err := resolve(a)
	if err != nil {
		return cli.Usage, err
	}
	s, err := readState(st, id)
	if err != nil {
		return exitFor(err), err
	}
	if s.Primary == nil {
		return cli.Usage, cli.Usagef("no primary process recorded for %q -- `container create --cmd` records one", id)
	}

	lp := primaryLogPath(st, id)
	status := func(s state) string {
		switch {
		case s.Primary.ExitCode != nil:
			return "exited"
		case s.Primary.PumpPid != 0 && pidAlive(s.Primary.PumpPid):
			return "running"
		case s.Primary.Pid == 0:
			return "never started"
		default:
			return "pump dead -- output may be truncated, exit unrecorded"
		}
	}

	if !a.Flag("--follow") {
		b, err := os.ReadFile(lp)
		if err != nil && !os.IsNotExist(err) {
			return cli.Failed, err
		}
		e.Result(map[string]any{
			"ok": true, "command": "container logs", "id": id,
			"primary": s.Primary, "status": status(s), "log": string(b),
		}, func() {
			fmt.Print(string(b))
		})
		return cli.OK, nil
	}

	// Follow: emit the file as it grows, re-reading state each pass to notice the exit (or
	// the pump's death). Lines go to stderr in JSON mode -- stdout still carries exactly one
	// document, at the end -- and are framed under --stream-json as {"stream":"log"}: the
	// file merges guest stdout and stderr, so per-stream attribution is gone by design here.
	f, err := os.Open(lp)
	if err != nil && !os.IsNotExist(err) {
		return cli.Failed, err
	}
	emit := func(chunk []byte) {
		if len(chunk) == 0 {
			return
		}
		if e.JSON {
			if e.StreamJSON {
				for _, line := range strings.Split(strings.TrimRight(string(chunk), "\r\n"), "\n") {
					e.StreamLogLine(strings.TrimSuffix(line, "\r"))
				}
			} else {
				os.Stderr.Write(chunk)
			}
			return
		}
		os.Stdout.Write(chunk)
	}
	buf := make([]byte, 64*1024)
	for {
		if f == nil {
			f, _ = os.Open(lp)
		}
		drained := false
		for f != nil {
			n, rerr := f.Read(buf)
			emit(buf[:n])
			if rerr != nil {
				drained = true
				break
			}
		}
		if drained || f == nil {
			cur, rerr := readState(st, id)
			if rerr != nil || cur.Primary == nil {
				return cli.Failed, fmt.Errorf("state disappeared while following: %v", rerr)
			}
			if st := status(cur); st != "running" {
				if f != nil {
					f.Close()
				}
				e.Result(map[string]any{
					"ok": true, "command": "container logs", "id": id,
					"primary": cur.Primary, "status": st, "followed": true,
				}, func() {
					fmt.Fprintf(os.Stderr, "-- %s\n", st)
				})
				return cli.OK, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// pidAlive asks whether a host pid is still running. Pid reuse can, in principle, make a
// recycled pid look like a live pump; the window is small and the failure mode is a follow
// that waits instead of finishing -- annoying, not wrong.
func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// -- shared ------------------------------------------------------------------------------

// resolve accepts --id or --ref for every verb that acts on an existing container, so a caller
// that created one by reference never has to know how the id was derived. Together with newID
// it is the only producer of ids, which is why validation lives here.
func resolve(a *cli.Args) (*store.Store, string, error) {
	st, err := store.New(a.Option("--store"))
	if err != nil {
		return nil, "", err
	}
	id := a.Option("--id")
	if id == "" {
		if ref := a.Option("--ref"); ref != "" {
			id = idFor(ref)
		} else {
			return nil, "", cli.Usagef("--id or --ref is required")
		}
	}
	if err := cli.ValidateID(id); err != nil {
		return nil, "", err
	}
	return st, id, nil
}

func exitFor(err error) int {
	if _, ok := err.(*cli.UsageError); ok {
		return cli.Usage
	}
	return cli.Failed
}
