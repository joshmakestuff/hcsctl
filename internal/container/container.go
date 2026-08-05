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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
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
	case "stop":
		return stop(a, e)
	case "rm":
		return remove(a, e)
	case "ls":
		return list(a, e)
	case "":
		return cli.Usage, cli.Usagef("container needs a subcommand: run, create, start, exec, stop, rm, ls")
	default:
		return cli.Usage, cli.Usagef("unknown container subcommand %q (expected run, create, start, exec, stop, rm, ls)", a.Word(1))
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
}

func containersRoot(st *store.Store) string { return filepath.Join(st.Root, "containers") }

func containerDir(st *store.Store, id string) string { return filepath.Join(containersRoot(st), id) }

// scratchDir is a subdirectory rather than the container directory itself, because DestroyLayer
// wants a layer directory and state.json is not part of a layer.
func scratchDir(st *store.Store, id string) string { return filepath.Join(containerDir(st, id), "scratch") }

func statePath(st *store.Store, id string) string { return filepath.Join(containerDir(st, id), "state.json") }

func writeState(st *store.Store, s state) error {
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
	if len(rec.DiffIDs) == 0 {
		return nil, fmt.Errorf("record for %s lists no layers", ref)
	}
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

// -- create ------------------------------------------------------------------------------

var createOptions = []string{"--ref", "--id", "--store", "--cpus", "--memory-mb", "--hostname"}

// buildConfig assembles the compute system document. Split out from create() because `run`
// needs the same document and the same failure messages.
func buildConfig(a *cli.Args, e cli.Emit, st *store.Store, id, ref string) (*hcsshim.ContainerConfig, state, error) {
	var s state

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
	if v := a.Option("--cpus"); v != "" {
		n, err := parseUint(v)
		if err != nil {
			return nil, s, cli.Usagef("--cpus must be a positive integer, got %q", v)
		}
		cfg.ProcessorCount = uint32(n)
	}
	if v := a.Option("--memory-mb"); v != "" {
		n, err := parseUint(v)
		if err != nil {
			return nil, s, cli.Usagef("--memory-mb must be a positive integer, got %q", v)
		}
		cfg.MemoryMaximumInMB = int64(n)
	}

	s = state{ID: id, Ref: ref, Scratch: sd, UVM: uvm, Chain: chain}
	return cfg, s, nil
}

func parseUint(s string) (uint64, error) {
	var n uint64
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + uint64(c-'0')
	}
	if n == 0 {
		return 0, fmt.Errorf("zero")
	}
	return n, nil
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
	id := a.Option("--id")
	if id == "" {
		id = idFor(ref)
	}

	cfg, s, err := buildConfig(a, e, st, id, ref)
	if err != nil {
		return exitFor(err), err
	}

	c, err := hcsshim.CreateContainer(id, cfg)
	if err != nil {
		destroyScratch(st, id)
		return cli.Failed, fmt.Errorf("CreateContainer: %w", err)
	}
	// The handle is dropped here on purpose: the compute system outlives this process and is
	// reopened by id. state.json records what HCS does not.
	c.Close()

	if err := writeState(st, s); err != nil {
		return cli.Failed, err
	}
	e.Result(map[string]any{
		"ok": true, "command": "container create", "id": id, "ref": ref,
		"utilityVM": s.UVM, "scratch": s.Scratch, "chain": s.Chain,
	}, func() {
		fmt.Printf("created %s\n  id:      %s\n  scratch: %s\n", ref, id, s.Scratch)
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
	if _, err := readState(st, id); err != nil {
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
	e.Result(map[string]any{"ok": true, "command": "container start", "id": id}, func() {
		fmt.Printf("started %s\n", id)
	})
	return cli.OK, nil
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

// execIn launches a process, streams its output, and returns its exit code. Stdin is closed
// immediately: nothing here is interactive, and a process blocked on a stdin that never closes
// looks exactly like a hung container.
func execIn(c hcsshim.Container, e cli.Emit, cmdline, cwd, user string, sink io.Writer) (int, error) {
	pc := &hcsshim.ProcessConfig{
		CommandLine:      cmdline,
		WorkingDirectory: cwd,
		User:             user,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	}
	p, err := c.CreateProcess(pc)
	if err != nil {
		return -1, fmt.Errorf("CreateProcess(%q): %w", cmdline, err)
	}
	defer p.Close()

	stdin, stdout, stderr, err := p.Stdio()
	if err != nil {
		return -1, fmt.Errorf("Stdio: %w", err)
	}
	if stdin != nil {
		stdin.Close()
	}
	_ = p.CloseStdin()

	// Both streams are drained concurrently. Draining them in sequence deadlocks as soon as the
	// guest fills the pipe this side is not reading.
	var wg sync.WaitGroup
	for _, r := range []io.ReadCloser{stdout, stderr} {
		if r == nil {
			continue
		}
		wg.Add(1)
		go func(r io.ReadCloser) {
			defer wg.Done()
			defer r.Close()
			io.Copy(sink, r)
		}(r)
	}

	if err := p.Wait(); err != nil {
		wg.Wait()
		return -1, fmt.Errorf("process Wait: %w", err)
	}
	wg.Wait()

	code, err := p.ExitCode()
	if err != nil {
		return -1, fmt.Errorf("ExitCode: %w", err)
	}
	return code, nil
}

func exec(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--ref", "--store", "--cmd", "--cwd", "--user"); err != nil {
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
	if _, err := readState(st, id); err != nil {
		return exitFor(err), err
	}
	c, err := hcsshim.OpenContainer(id)
	if err != nil {
		return cli.Failed, fmt.Errorf("OpenContainer(%s): %w", id, err)
	}
	defer c.Close()

	out := &captured{json: e.JSON}
	code, err := execIn(c, e, cmdline, a.Option("--cwd"), a.Option("--user"), out)
	if err != nil {
		return cli.Failed, err
	}
	e.Result(map[string]any{
		"ok": true, "command": "container exec", "id": id,
		"cmd": cmdline, "exitCode": code, "output": out.String(),
	}, func() {
		fmt.Printf("exit code: %d\n", code)
	})
	return cli.OK, nil
}

// captured tees guest output. In JSON mode it must not reach stdout -- stdout carries exactly
// one document -- so it goes to stderr live and into the document at the end.
type captured struct {
	json bool
	mu   sync.Mutex
	buf  strings.Builder
}

func (c *captured) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
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
	known := append([]string{"--cmd", "--cwd", "--user", "--keep"}, createOptions...)
	if err := a.RejectUnknown(known...); err != nil {
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
	id := a.Option("--id")
	if id == "" {
		id = idFor(ref)
	}
	cmdline := a.Option("--cmd")
	if cmdline == "" {
		cmdline = defaultCmd
	}

	cfg, s, err := buildConfig(a, e, st, id, ref)
	if err != nil {
		return exitFor(err), err
	}
	if err := writeState(st, s); err != nil {
		return cli.Failed, err
	}

	c, err := hcsshim.CreateContainer(id, cfg)
	if err != nil {
		destroyScratch(st, id)
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
		if err := destroyScratch(st, id); err != nil {
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
	code, execErr := execIn(c, e, cmdline, a.Option("--cwd"), a.Option("--user"), out)
	cleanup()
	if execErr != nil {
		return cli.Failed, execErr
	}

	// The CLI's own exit code stays on contract -- 0 means hcsctl ran the thing -- and the
	// guest's exit code is reported in the document rather than conflated with it.
	e.Result(map[string]any{
		"ok": true, "command": "container run", "id": id, "ref": ref,
		"cmd": cmdline, "exitCode": code, "output": out.String(),
		"utilityVM": s.UVM, "kept": a.Flag("--keep"),
	}, func() {
		fmt.Printf("exit code: %d\n", code)
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

func remove(a *cli.Args, e cli.Emit) (int, error) {
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

	// A container that is gone from HCS but still on disk is the normal state after a crash, so
	// a failure to open is not fatal here -- the scratch still needs removing.
	if c, err := hcsshim.OpenContainer(id); err == nil {
		if err := shutdown(c, e, a.Flag("--force")); err != nil {
			e.Progress("stop: %v", err)
		}
		c.Close()
	} else if !hcsshim.IsNotExist(err) {
		e.Progress("OpenContainer: %v -- removing on-disk state anyway", err)
	}

	if err := destroyScratch(st, id); err != nil {
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
		ID    string `json:"id"`
		Ref   string `json:"ref"`
		State string `json:"state"`
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
		rows = append(rows, row{ID: s.ID, Ref: s.Ref, State: hcsState})
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

// -- shared ------------------------------------------------------------------------------

// resolve accepts --id or --ref for every verb that acts on an existing container, so a caller
// that created one by reference never has to know how the id was derived.
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
	return st, id, nil
}

func exitFor(err error) int {
	if _, ok := err.(*cli.UsageError); ok {
		return cli.Usage
	}
	return cli.Failed
}
