//go:build windows

// Package container is the `hcsctl container` verb group: running a Windows
// container on a materialized image chain, entirely over computecore.dll.
//
// The two isolations differ in storage presentation and document schema:
//
//	argon  -- the scratch VHD stays attached with the layer storage filter on
//	          its volume, and a schema-2.1 document consumes that volume in
//	          Container.Storage.Path (the layers stack under the filter; no
//	          wclayer Activate/Prepare, no per-start admin-SID gate).
//	xenon  -- the scratch is a detached VHD in a directory a SCHEMA-1 document
//	          consumes (LayerFolderPath + HvRuntime.ImagePath); the utility VM
//	          stacks the layers in-guest. The document shape is legacy because
//	          no self-contained v2 xenon document exists; every
//	          call carrying it is computecore.
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/computecore"
	"github.com/joshmakestuff/hcsctl/internal/layerid"
	"github.com/joshmakestuff/hcsctl/internal/scratch"
	"github.com/joshmakestuff/hcsctl/internal/store"
	"github.com/joshmakestuff/hcsctl/internal/sysinfo"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"golang.org/x/sys/windows"
)

// defaultCmd proves the guest booted and is the expected OS, and exits on its own so `run`
// needs no timeout to make progress.
const defaultCmd = `cmd /c ver`

// startTimeout bounds the container start. A cold xenon on a slow disk is tens of seconds; well
// past that and something is wrong rather than slow.

const startTimeout = 5 * time.Minute

// The remaining operation bounds. Create includes a xenon's UVM template
// work; process creation and property reads are fast or wrong.
const (
	createTimeout     = 3 * time.Minute
	shutdownWait      = 30 * time.Second
	terminateWait     = 60 * time.Second
	procCreateTimeout = 60 * time.Second
	propsTimeout      = 30 * time.Second
)

// Command is `hcsctl container`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("container", "run a Windows container on a materialized image chain",
		runCmd(e), createCmd(e), startCmd(e), execCmd(e), killCmd(e), logsCmd(e),
		stopCmd(e), rmCmd(e), lsCmd(e), statsCmd(e), psCmd(e), inspectCmd(e),
		pauseCmd(e), resumeCmd(e))
}

// createOptions is the option set create and run share: everything buildConfig consumes.
// Numeric and size options stay strings here and are parsed in buildConfig, so their error
// messages keep naming the option and its sink's range.
type createOptions struct {
	ref, id, storeDir   string
	cpus, memoryMB      string
	hostname, isolation string
	network, dnsSearch  string
	scratchSize, cmd    string
	publish, acl, mount []string
	label               []string
}

// addCreateFlags declares the shared create/run option set once, --cmd excepted: both verbs
// take it, but it means "record the primary" to create and "run this now" to run, so each
// declares it with its own usage text.
func addCreateFlags(fs *pflag.FlagSet, o *createOptions) {
	cli.StringOnce(fs, &o.ref, "ref", "image reference, registry/repo:tag")
	cli.StringOnce(fs, &o.id, "id", "container id; defaults to one derived from --ref")
	cli.StringOnce(fs, &o.storeDir, "store", "store directory")
	cli.StringOnce(fs, &o.cpus, "cpus", "processor count")
	cli.StringOnce(fs, &o.memoryMB, "memory-mb", "memory ceiling in MB")
	cli.StringOnce(fs, &o.hostname, "hostname", "guest hostname")
	cli.StringOnce(fs, &o.isolation, "isolation", "hyperv (default) or process. Process isolation stacks layers on the host, needs elevation at every start, and requires an image build inside the host's process-isolation compatibility window (see hcsctl info)")
	cli.StringOnce(fs, &o.network, "network", "attach an endpoint on an existing host compute network (name or id) and report its address")
	cli.StringOnce(fs, &o.dnsSearch, "dns-search", "DNS search list for the endpoint; only means something with --network")
	cli.StringArray(fs, &o.publish, "publish", "HOST_PORT:CONTAINER_PORT/tcp|udp, repeatable. A NAT port mapping created while the endpoint is created; it exposes the requested host port")
	cli.StringArray(fs, &o.acl, "acl", "DIRECTION:ACTION[:tcp|udp], repeatable. A create-time endpoint ACL, added to the endpoint create document like --publish. Enforced on process isolation + NAT and Hyper-V + L2Bridge; refused on every other combination, including Hyper-V + NAT where it would be stored without effect. No runtime mutation")
	cli.StringArray(fs, &o.mount, "mount", "HOST:CONTAINER[:ro], repeatable. Maps a host directory into the guest over VSMB -- not a bind mount, and not Docker semantics; both paths drive-letter absolute")
	cli.StringOnce(fs, &o.scratchSize, "scratch-size", "grow the scratch VHD, e.g. 40GB, so the guest's C: is bigger than the default -- anything writing real data wants this")
	cli.StringArray(fs, &o.label, "label", "key=value, repeatable. Stored in state.json, reported by ls and inspect, never interpreted -- ownership and run identity are the consumer's policy")
}

// targetOptions is the trio every verb acting on an existing container takes.
type targetOptions struct {
	id, ref, storeDir string
}

func addTargetFlags(fs *pflag.FlagSet, o *targetOptions) {
	cli.StringOnce(fs, &o.id, "id", "container id")
	cli.StringOnce(fs, &o.ref, "ref", "image reference the container was created from; derives the id when --id is absent")
	cli.StringOnce(fs, &o.storeDir, "store", "store directory")
}

const envUsage = "NAME=value, repeatable. The value keeps everything after the first '='; an empty value is rejected because HCS drops it before the guest sees it"

// runOptions is create's option set plus run's exec-shaped extras.
type runOptions struct {
	createOptions
	cwd, user string
	timeout   time.Duration
	env       []string
	keep      bool
}

// execOptions is the target trio plus the process to run and how to attach to it.
type execOptions struct {
	targetOptions
	cmd, cwd, user   string
	timeout          time.Duration
	env              []string
	interactive, tty bool
}

func runCmd(e cli.Emit) *cobra.Command {
	var o runOptions
	cmd := &cobra.Command{
		Use:   `run --ref <ref> [--cmd "<cmdline>"] [--id <id>] [--cpus N] [--memory-mb N] [--hostname H] [--cwd D] [--user U] [--env NAME=value]... [--network <name|id>] [--dns-search list] [--publish HOST_PORT:CONTAINER_PORT/tcp|udp]... [--acl DIRECTION:ACTION[:tcp|udp]]... [--mount HOST:CONTAINER[:ro]]... [--scratch-size 40GB] [--isolation hyperv|process] [--timeout <dur>] [--label key=value]... [--store <dir>] [--keep]`,
		Short: "create, boot and run one command in a container, then tear it down. ELEVATED",
		Long: `Create, boot and run one command in a container (hyperv by default), then tear
it down. --cmd defaults to "cmd /c ver". --network attaches an endpoint on an
existing host compute network and reports its address. --publish creates a NAT
endpoint mapping while the endpoint is created; it exposes the requested host
port. --mount maps a host directory into the guest over VSMB -- not a bind
mount, and not Docker semantics; both paths drive-letter absolute. ELEVATED.
--isolation hyperv (default) or process. Process isolation stacks layers on
the host, needs elevation at every start, and requires an image build inside
the host's process-isolation compatibility window (see hcsctl info).
--acl DIRECTION:ACTION[:tcp|udp], repeatable. A create-time endpoint ACL,
added to the endpoint create document like --publish. Enforced on process
isolation + NAT and Hyper-V + L2Bridge; refused on every other combination,
including Hyper-V + NAT where it would be stored without effect. No runtime
mutation. --timeout bounds the primary command; absent means wait forever.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return run(&o, e)
		},
	}
	addCreateFlags(cmd.Flags(), &o.createOptions)
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &o.cmd, "cmd", `command to run; defaults to "cmd /c ver"`)
	cli.StringOnce(cmd.Flags(), &o.cwd, "cwd", "guest working directory")
	cli.StringOnce(cmd.Flags(), &o.user, "user", "guest user")
	cli.StringArray(cmd.Flags(), &o.env, "env", envUsage)
	cli.Duration(cmd.Flags(), &o.timeout, "timeout", 0, 0, "bound the primary command, e.g. 30s or 2m; absent means wait forever")
	cmd.Flags().BoolVar(&o.keep, "keep", false, "leave the container in place instead of tearing it down")
	return cmd
}

func createCmd(e cli.Emit) *cobra.Command {
	var o createOptions
	cmd := &cobra.Command{
		Use:   `create --ref <ref> [--id <id>] [--cmd "<cmdline>"] [--cpus N] [--memory-mb N] [--hostname H] [--network <name|id>] [--dns-search list] [--publish HOST_PORT:CONTAINER_PORT/tcp|udp]... [--acl DIRECTION:ACTION[:tcp|udp]]... [--mount HOST:CONTAINER[:ro]]... [--scratch-size 40GB] [--isolation hyperv|process] [--label key=value]... [--store <dir>]`,
		Short: "create a container without starting it. ELEVATED",
		Long: `Create a container without starting it. --label stores opaque key=value pairs
in state.json, reported by ls and inspect and never interpreted -- ownership
and run identity are the consumer's policy (record an owner pid; scavenge only
on proof it is dead). --scratch-size grows the scratch VHD so the guest's C:
is bigger than the default -- anything writing real data wants this. --cmd
records the primary process; start launches it. Exec the target directly, not
via cmd /c -- a kill terminates one process, not a tree, and a wrapper's
children survive. --isolation hyperv (default) or process; process needs
elevation at every start and a host-compatible image build. Recorded in
state.json and reported by inspect. --acl DIRECTION:ACTION[:tcp|udp],
repeatable. Create-time endpoint ACL; enforced on process isolation + NAT and
Hyper-V + L2Bridge, refused elsewhere. Recorded in state.json.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			return create(&o, e)
		},
	}
	addCreateFlags(cmd.Flags(), &o)
	cli.Required(cmd, "ref")
	cli.StringOnce(cmd.Flags(), &o.cmd, "cmd", "record the primary process; start launches it. Exec the target directly, not via cmd /c -- a kill terminates one process, not a tree, and a wrapper's children survive")
	return cmd
}

func startCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "start --id <id> | --ref <ref> [--store <dir>]",
		Short: "start a container; launch and pump its recorded primary process",
		Long: `With a recorded primary process, start launches it and stays attached as its
pump, teeing output to primary.log and recording the exit in state.json. The
pump owns the pipes -- if it dies with its caller, the workload keeps running
and logs reports the truncation honestly.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error { return start(o, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

func execCmd(e cli.Emit) *cobra.Command {
	var o execOptions
	cmd := &cobra.Command{
		Use:   `exec --id <id> --cmd "<cmdline>" [--cwd D] [--user U] [--env NAME=value]... [--timeout 30s] [--interactive [--tty]] [--ref <ref>] [--store <dir>]`,
		Short: "run a command in a running container",
		Long: `Run a command in a running container. Default stdin closes immediately.
--interactive forwards this process's stdin and closes the guest side on EOF;
--tty adds an emulated console. Neither can be used with --json or
--stream-json. Ctrl-C kills only the exec process.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error { return exec(&o, e) },
	}
	addTargetFlags(cmd.Flags(), &o.targetOptions)
	cli.StringOnce(cmd.Flags(), &o.cmd, "cmd", "command to run in the guest")
	cli.Required(cmd, "cmd")
	cli.StringOnce(cmd.Flags(), &o.cwd, "cwd", "guest working directory")
	cli.StringOnce(cmd.Flags(), &o.user, "user", "guest user")
	cli.StringArray(cmd.Flags(), &o.env, "env", envUsage)
	cli.Duration(cmd.Flags(), &o.timeout, "timeout", 0, 0, "bound the command, e.g. 30s or 2m; absent means wait forever")
	cmd.Flags().BoolVar(&o.interactive, "interactive", false, "forward this process's stdin; close the guest side on EOF")
	cmd.Flags().BoolVar(&o.tty, "tty", false, "with --interactive: an emulated guest console with the host terminal in raw mode")
	return cmd
}

func killCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	var pid string
	cmd := &cobra.Command{
		Use:   "kill --id <id> --pid <pid> [--ref <ref>] [--store <dir>]",
		Short: "kill one guest process by pid and confirm it is gone",
		Long: `Kill one guest process and confirm it is gone. PIDs come from container ps or
the exec result. Kill (and --timeout) terminates that process only: a cmd /c
wrapper's children survive it, so exec the target directly when a kill must be
total.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			// The whole command line is judged before any container lookup, so a bad --pid is
			// exit 64 even when the container does not exist either.
			// OpenProcess takes an int and a Windows pid is a DWORD; MaxInt32 satisfies both
			// sinks, and no real pid approaches it.
			n, err := cli.ParseUint(pid, math.MaxInt32)
			if err != nil {
				return cli.Usagef("--pid %v", err)
			}
			return kill(o, n, e)
		},
	}
	addTargetFlags(cmd.Flags(), &o)
	cli.StringOnce(cmd.Flags(), &pid, "pid", "guest pid, from container ps or an exec result")
	cli.Required(cmd, "pid")
	return cmd
}

func logsCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs --id <id> [--follow] [--ref <ref>] [--store <dir>]",
		Short: "a primary process's retained output, from any invocation",
		Long: `A primary process's retained output, from any invocation -- the file the pump
wrote, plus status: running, exited (with code), or pump dead. --follow tails
until the primary exits or the pump dies. Under --stream-json, followed lines
are framed {"stream":"log"} (the file merges guest stdout and stderr).`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error { return logs(o, follow, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	cmd.Flags().BoolVar(&follow, "follow", false, "tail until the primary exits or the pump dies")
	return cmd
}

func stopCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	var force bool
	cmd := &cobra.Command{
		Use:   "stop --id <id> [--force] [--ref <ref>] [--store <dir>]",
		Short: "shut a container down, politely then forcibly",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return stop(o, force, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	cmd.Flags().BoolVar(&force, "force", false, "terminate without asking the guest to shut down")
	return cmd
}

func rmCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	var force bool
	cmd := &cobra.Command{
		Use:   "rm --id <id> [--force] [--ref <ref>] [--store <dir>]",
		Short: "stop a container and remove its scratch, endpoint and state. ELEVATED",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return remove(o, force, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	cmd.Flags().BoolVar(&force, "force", false, "terminate without asking the guest to shut down")
	return cmd
}

func lsCmd(e cli.Emit) *cobra.Command {
	var storeDir string
	cmd := &cobra.Command{
		Use:   "ls [--store <dir>]",
		Short: "containers and their HCS state",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return list(storeDir, e) },
	}
	cli.StringOnce(cmd.Flags(), &storeDir, "store", "store directory")
	return cmd
}

func statsCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "stats --id <id> [--ref <ref>] [--store <dir>]",
		Short: "uptime, memory, CPU, storage and network",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return stats(o, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

func psCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "ps --id <id> [--ref <ref>] [--store <dir>]",
		Short: "processes running in the guest",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return ps(o, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

func inspectCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "inspect --id <id> [--ref <ref>] [--store <dir>]",
		Short: "what the store and HCS each know",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return inspect(o, e) },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

func pauseCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "pause --id <id> [--ref <ref>] [--store <dir>]",
		Short: "pause a running container",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return pauseResume(o, e, "pause") },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

func resumeCmd(e cli.Emit) *cobra.Command {
	var o targetOptions
	cmd := &cobra.Command{
		Use:   "resume --id <id> [--ref <ref>] [--store <dir>]",
		Short: "resume a paused container",
		Args:  cli.NoExtraArgs,
		RunE:  func(*cobra.Command, []string) error { return pauseResume(o, e, "resume") },
	}
	addTargetFlags(cmd.Flags(), &o)
	return cmd
}

// -- on-disk state -----------------------------------------------------------------------

// state is what `rm` and `ls` need after the creating process has exited. The compute system
// itself is host-global and reopenable by id, so this holds only what HCS does not: where the
// scratch lives and what it was built from.
type state struct {
	ID        string   `json:"id"`
	Ref       string   `json:"ref"`
	Scratch   string   `json:"scratch"`
	UVM       string   `json:"utilityVM"`
	Isolation string   `json:"isolation,omitempty"`
	Chain     []string `json:"chain"`
	// Volume is an argon's filter-attached scratch volume -- what the v2
	// document consumed, and what a later invocation's teardown detaches.
	Volume string `json:"volume,omitempty"`
	// Namespace is the HNS namespace an argon's endpoint was added to. Like
	// the endpoint it is host-global: `rm` after a crash must delete it.
	Namespace string `json:"namespace,omitempty"`
	// Endpoint is here because endpoints are host-global and outlive the creating process:
	// `rm` after a crash must delete an endpoint it did not create.
	Endpoint  string   `json:"endpoint,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// Published records the NAT port mappings supplied when this endpoint was created. HCN
	// owns their effective lifetime; this is the requested creation contract reported again by
	// inspect after the creating invocation is gone.
	Published []publishedPort `json:"published,omitempty"`
	// ACLs records the create-time endpoint ACL policies supplied for this container. HCN owns
	// their effective lifetime; this is the requested contract reported again by inspect.
	ACLs []aclRule `json:"acls,omitempty"`
	// Primary is the container's main workload, recorded by `create --cmd` so a fresh
	// invocation can say what a running container is running, follow its retained output,
	// and report its exit after the starting invocation is gone.
	Primary *primaryState `json:"primary,omitempty"`
	// Labels are stored and reported, never interpreted: ownership and run identity
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
	// Failpoint: HCSCTL_TEST_FAIL_WRITESTATE forces a state-write failure without a real
	// acquisition.
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
func newID(id, ref string) (string, error) {
	if id == "" {
		id = idFor(ref)
	}
	if err := cli.ValidateID(id); err != nil {
		return "", err
	}
	return id, nil
}

// -- layer chain -------------------------------------------------------------------------

// chainFor resolves a reference to its materialized layer directories, topmost
// first -- store.Chain with this package's usage-error shape.
func chainFor(st *store.Store, ref string) ([]string, error) {
	rec, err := st.ReadRecord(ref)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cli.Usagef("no record for %s -- pull and import it first", ref)
		}
		return nil, err
	}
	chain, err := st.Chain(rec)
	if err != nil {
		return nil, cli.Usagef("%v", err)
	}
	return chain, nil
}

// locateUVM finds the uppermost layer whose UtilityVM is PREPARED -- it
// carries the SystemTemplate.vhdx SetupUtilityVMBaseLayer produced. A diff
// layer's tar can carry a UtilityVM delta too, but the modern import prepares
// only the base's, and a document naming an unprepared UVM fails create with
// 0x80070002. The utility VM therefore runs
// the BASE build; the container's own filesystem still stacks the full chain.
func locateUVM(chain []string) (string, error) {
	for _, l := range chain {
		p := filepath.Join(l, "UtilityVM")
		if _, err := os.Stat(filepath.Join(p, "SystemTemplate.vhdx")); err == nil {
			return p, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("no layer in the chain carries a prepared UtilityVM -- this image cannot boot Hyper-V isolated (a Nano/Server Core base normally has one; a --platform-mismatched pull will not, and a pre-format-2 import needs re-importing)")
}

// layersFor builds the document's layer list: ids from layerid (matching what
// import and scratch derived), topmost first.
func layersFor(chain []string) ([]layerRef, error) {
	var out []layerRef
	for _, l := range chain {
		id, err := layerid.ForPath(l)
		if err != nil {
			return nil, err
		}
		out = append(out, layerRef{Id: id, Path: l})
	}
	return out, nil
}

// -- network endpoint --------------------------------------------------------------------

// resolveNetwork accepts a name or an id, matching `network endpoints --network`. It reuses an
// existing network; nothing here creates one.
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
func createEndpoint(netw *hcn.HostComputeNetwork, name, isolation string, published []publishedPort, acls []aclRule) (*hcn.HostComputeEndpoint, error) {
	ep := &hcn.HostComputeEndpoint{
		Name:               name,
		HostComputeNetwork: netw.Id,
		SchemaVersion:      hcn.V2SchemaVersion(),
	}
	if len(acls) > 0 {
		if reason := aclEnforcementReason(isolation, netw); reason != "" {
			return nil, fmt.Errorf("endpoint ACLs on %s: %s", netw.Name, reason)
		}
	}
	for _, p := range published {
		settings, err := json.Marshal(hcn.PortMappingPolicySetting{
			Protocol: p.protocolNumber(), InternalPort: p.ContainerPort, ExternalPort: p.HostPort,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal port mapping %s: %w", p, err)
		}
		ep.Policies = append(ep.Policies, hcn.EndpointPolicy{Type: hcn.PortMapping, Settings: settings})
	}
	for _, a := range acls {
		policy, err := a.policy()
		if err != nil {
			return nil, fmt.Errorf("marshal ACL %s: %w", a, err)
		}
		ep.Policies = append(ep.Policies, policy)
	}
	// Port mappings take effect only when present in the endpoint's create document: HNS
	// allocates the forwarding dataplane at create time. A policy added later with
	// ApplyPolicy is accepted and reported but does not establish forwarding.
	created, err := netw.CreateEndpoint(ep)
	if err != nil {
		return nil, fmt.Errorf("endpoint Create on %s: %w", netw.Name, err)
	}
	return created, nil
}

// publishedPort maps a host port to a guest port while the endpoint is created. HCN accepts a
// port mapping added later, but that does not establish a forwarding dataplane.
type publishedPort struct {
	Protocol      string `json:"protocol"`
	HostPort      uint16 `json:"hostPort"`
	ContainerPort uint16 `json:"containerPort"`
}

func (p publishedPort) String() string {
	return fmt.Sprintf("%d:%d/%s", p.HostPort, p.ContainerPort, p.Protocol)
}

func (p publishedPort) protocolNumber() uint32 {
	if p.Protocol == "udp" {
		return 17
	}
	return 6
}

// parsePublishedPorts parses repeated --publish HOST_PORT:CONTAINER_PORT/PROTOCOL values.
// Keeping it separate from endpoint creation makes every rejected value an exit-64 path before
// the scratch, endpoint, and compute system transactions begin.
func parsePublishedPorts(vals []string) ([]publishedPort, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]publishedPort, 0, len(vals))
	for _, v := range vals {
		parts := strings.Split(v, "/")
		if len(parts) != 2 || (parts[1] != "tcp" && parts[1] != "udp") {
			return nil, cli.Usagef("--publish wants HOST_PORT:CONTAINER_PORT/tcp|udp, got %q", v)
		}
		ports := strings.Split(parts[0], ":")
		if len(ports) != 2 {
			return nil, cli.Usagef("--publish wants HOST_PORT:CONTAINER_PORT/tcp|udp, got %q", v)
		}
		host, err := parsePublishedPort(ports[0])
		if err != nil {
			return nil, cli.Usagef("--publish host port in %q: %v", v, err)
		}
		guest, err := parsePublishedPort(ports[1])
		if err != nil {
			return nil, cli.Usagef("--publish container port in %q: %v", v, err)
		}
		p := publishedPort{Protocol: parts[1], HostPort: host, ContainerPort: guest}
		key := p.Protocol + ":" + strconv.FormatUint(uint64(p.HostPort), 10)
		if seen[key] {
			return nil, cli.Usagef("--publish host port %d/%s is given more than once", p.HostPort, p.Protocol)
		}
		seen[key] = true
		out = append(out, p)
	}
	return out, nil
}

func parsePublishedPort(v string) (uint16, error) {
	if v == "" {
		return 0, fmt.Errorf("is required")
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("must be a decimal integer from 1 through 65535")
	}
	return uint16(n), nil
}

func validatePublishNetwork(published []publishedPort, netw *hcn.HostComputeNetwork) error {
	if len(published) == 0 {
		return nil
	}
	if netw == nil {
		return cli.Usagef("--publish requires --network naming an HCN NAT network")
	}
	if netw.Type != hcn.NAT {
		return cli.Usagef("--publish requires an HCN NAT network; %q is %s", netw.Name, netw.Type)
	}
	return nil
}

// aclRule is the ACL surface: a direction, an action, and an optional protocol (empty = all).
// It materializes as an hcn.ACL endpoint policy at create time. RuleType is not
// user-selectable: Host and Switch both enforce on the argon + NAT topology, and the surface
// fixes Switch. Enforcement is topology-dependent (argon + NAT and xenon + L2Bridge enforce;
// xenon + NAT stores without dataplane effect) and create-time only: runtime ApplyPolicy is
// inert.
type aclRule struct {
	Direction hcn.DirectionType `json:"direction"`
	Action    hcn.ActionType    `json:"action"`
	Protocol  string            `json:"protocol,omitempty"` // "tcp" or "udp"; empty = all
}

func (a aclRule) String() string {
	p := a.Protocol
	if p == "" {
		p = "*"
	}
	return fmt.Sprintf("%s:%s:%s", strings.ToLower(string(a.Direction)), strings.ToLower(string(a.Action)), p)
}

func (a aclRule) protocolNumber() string {
	switch a.Protocol {
	case "udp":
		return "17"
	case "tcp":
		return "6"
	default:
		return ""
	}
}

func (a aclRule) policy() (hcn.EndpointPolicy, error) {
	s, err := json.Marshal(hcn.AclPolicySetting{
		Protocols: a.protocolNumber(),
		Action:    a.Action,
		Direction: a.Direction,
		RuleType:  hcn.RuleTypeSwitch,
		Priority:  200,
	})
	if err != nil {
		return hcn.EndpointPolicy{}, err
	}
	return hcn.EndpointPolicy{Type: hcn.ACL, Settings: s}, nil
}

// parseACLs parses repeated --acl DIRECTION:ACTION[:tcp|udp] values. Like parsePublishedPorts,
// it runs before any disk or endpoint transaction so every rejected value is exit 64.
func parseACLs(vals []string) ([]aclRule, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]aclRule, 0, len(vals))
	for _, v := range vals {
		r, err := parseACL(v)
		if err != nil {
			return nil, err
		}
		if seen[r.String()] {
			return nil, cli.Usagef("--acl %q is given more than once", r)
		}
		seen[r.String()] = true
		out = append(out, r)
	}
	return out, nil
}

func parseACL(v string) (aclRule, error) {
	parts := strings.Split(v, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return aclRule{}, cli.Usagef("--acl wants DIRECTION:ACTION[:tcp|udp], got %q", v)
	}
	var r aclRule
	switch strings.ToLower(parts[0]) {
	case "in":
		r.Direction = hcn.DirectionTypeIn
	case "out":
		r.Direction = hcn.DirectionTypeOut
	default:
		return aclRule{}, cli.Usagef("--acl direction must be in or out, got %q", parts[0])
	}
	switch strings.ToLower(parts[1]) {
	case "allow":
		r.Action = hcn.ActionTypeAllow
	case "block":
		r.Action = hcn.ActionTypeBlock
	default:
		return aclRule{}, cli.Usagef("--acl action must be allow or block, got %q", parts[1])
	}
	if len(parts) == 3 {
		switch strings.ToLower(parts[2]) {
		case "tcp":
			r.Protocol = "tcp"
		case "udp":
			r.Protocol = "udp"
		default:
			return aclRule{}, cli.Usagef("--acl protocol must be tcp or udp, got %q", parts[2])
		}
	}
	return r, nil
}

// aclEnforcementReason reports whether ACLs on this isolation/network combination are known to
// enforce on the dataplane. Empty means they do; any other value is why they must not be
// applied. The matrix: process (argon) + NAT and hyperv (xenon) + L2Bridge enforce.
// hyperv + NAT is a no-op (HNS stores the policy, the dataplane is unchanged), and every
// other combination fails closed.
func aclEnforcementReason(isolation string, netw *hcn.HostComputeNetwork) string {
	if netw == nil {
		return "no HCN network"
	}
	switch isolation {
	case isolationProcess:
		if netw.Type == hcn.NAT {
			return ""
		}
		return fmt.Sprintf("process isolation supports ACLs only on NAT; %s is unsupported", netw.Type)
	case isolationHyperV:
		if netw.Type == hcn.L2Bridge {
			return ""
		}
		if netw.Type == hcn.NAT {
			return "hyperv isolation + NAT stores the ACL without enforcing it"
		}
		return fmt.Sprintf("hyperv isolation supports ACLs only on L2Bridge; %s is unsupported", netw.Type)
	default:
		return fmt.Sprintf("unknown isolation %q", isolation)
	}
}

// validateACLNetwork fails closed for ACLs on an isolation/network combination whose
// enforcement is inert or unverified. It runs before any disk or endpoint transaction so a
// refused combination is exit 64 with nothing attempted; createEndpoint guards the same matrix
// so a future call site cannot bypass it.
func validateACLNetwork(acls []aclRule, isolation string, netw *hcn.HostComputeNetwork) error {
	if len(acls) == 0 {
		return nil
	}
	if netw == nil {
		return cli.Usagef("--acl requires --network naming an HCN network")
	}
	if reason := aclEnforcementReason(isolation, netw); reason != "" {
		return cli.Usagef("--acl is not enforced here: %s", reason)
	}
	return nil
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
// these go over VSMB, not a bind mount -- different performance, different semantics.
func parseMounts(vals []string) ([]mappedDir, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]mappedDir, 0, len(vals))
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
		out = append(out, mappedDir{HostPath: host, ContainerPath: ctr, ReadOnly: m[3] != ""})
	}
	return out, nil
}

// reservedLabelKeys are what a consumer sees when it flattens state.json (or the inspect
// document) -- a label may not shadow one. Kept in sync with the state struct's json tags.
var reservedLabelKeys = map[string]bool{
	"id": true, "ref": true, "scratch": true, "utilityVM": true, "isolation": true,
	"chain": true, "volume": true, "namespace": true,
	"endpoint": true, "addresses": true, "published": true, "acls": true,
	"primary": true, "labels": true,
	"ok": true, "command": true, "state": true, "hcs": true,
}

// parseLabels is cli.ParseLabels with this package's reserved key set.
func parseLabels(vals []string) (map[string]string, error) {
	return cli.ParseLabels(vals, reservedLabelKeys)
}

// -- isolation ---------------------------------------------------------------------------

// Isolation modes. Process (argon) stacks layers on the host and is elevated at every start;
// hyperv (xenon) hands the layers to a utility VM. The flag defaults to hyperv.
const (
	isolationHyperV  = "hyperv"
	isolationProcess = "process"
)

func parseIsolation(v string) (string, error) {
	switch v {
	case "", isolationHyperV:
		return isolationHyperV, nil
	case isolationProcess:
		return isolationProcess, nil
	default:
		return "", cli.Usagef("--isolation wants %q or %q, got %q", isolationHyperV, isolationProcess, v)
	}
}

// -- create ------------------------------------------------------------------------------

// buildConfig assembles the compute system document. Split out from create() because `run`
// needs the same document and the same failure messages.
func buildConfig(o *createOptions, e cli.Emit, st *store.Store, id string) (string, state, error) {
	var s state

	// Every argument is validated before anything touches the disk, because exit 64 promises
	// nothing was attempted -- and because from the scratch on, an early return has an
	// increasing amount to clean up.
	if o.dnsSearch != "" && o.network == "" {
		return "", s, cli.Usagef("--dns-search only means something with --network")
	}
	isolation, err := parseIsolation(o.isolation)
	if err != nil {
		return "", s, err
	}
	published, err := parsePublishedPorts(o.publish)
	if err != nil {
		return "", s, err
	}
	acls, err := parseACLs(o.acl)
	if err != nil {
		return "", s, err
	}
	var cpus, memoryMB uint64
	if o.cpus != "" {
		// ProcessorCount is a uint32 in both documents.
		if cpus, err = cli.ParseUint(o.cpus, math.MaxUint32); err != nil {
			return "", s, cli.Usagef("--cpus %v", err)
		}
	}
	if o.memoryMB != "" {
		if memoryMB, err = cli.ParseUint(o.memoryMB, math.MaxInt64); err != nil {
			return "", s, cli.Usagef("--memory-mb %v", err)
		}
	}
	mounts, err := parseMounts(o.mount)
	if err != nil {
		return "", s, err
	}
	labels, err := parseLabels(o.label)
	if err != nil {
		return "", s, err
	}
	var scratchSize uint64
	if o.scratchSize != "" {
		if scratchSize, err = cli.ParseSize(o.scratchSize); err != nil {
			return "", s, err
		}
		// Rejected here, before any disk work, so a missing grant is exit 64 with a named
		// reason instead of an attach failure after the scratch was created.
		if err := sysinfo.ExpandScratchReady(); err != nil {
			return "", s, err
		}
	}

	chain, err := chainFor(st, o.ref)
	if err != nil {
		return "", s, err
	}
	layers, err := layersFor(chain)
	if err != nil {
		return "", s, err
	}

	// Process isolation runs on the host, gated by the host/image build
	// compatibility window. Xenon needs a utility VM instead.
	var uvm string
	if isolation == isolationProcess {
		rec, err := st.ReadRecord(o.ref)
		if err != nil {
			return "", s, err
		}
		if err := sysinfo.ProcessIsolationReady(rec.OSVersion); err != nil {
			return "", s, err
		}
	} else {
		uvm, err = locateUVM(chain)
		if err != nil {
			return "", s, err
		}
	}

	// Resolved before anything touches the disk, so a bad name is exit 64 with nothing to
	// clean up.
	var netw *hcn.HostComputeNetwork
	if o.network != "" {
		if netw, err = resolveNetwork(o.network); err != nil {
			return "", s, err
		}
	}
	if err := validatePublishNetwork(published, netw); err != nil {
		return "", s, err
	}
	if err := validateACLNetwork(acls, isolation, netw); err != nil {
		return "", s, err
	}

	sd := scratchDir(st, id)
	if _, err := os.Stat(containerDir(st, id)); err == nil {
		return "", s, cli.Usagef("a container named %q already exists at %s -- rm it first", id, containerDir(st, id))
	}
	if err := os.MkdirAll(sd, 0o755); err != nil {
		return "", s, err
	}

	e.Progress("chain:     %d layer(s), topmost %s", len(chain), filepath.Base(chain[0]))
	e.Progress("isolation: %s", isolation)
	if isolation == isolationHyperV {
		e.Progress("utilityVM: %s", uvm)
	}
	e.Progress("scratch:   %s", sd)

	// One scratch shape; isolation decides presentation. Argon: attached with
	// the storage filter, the volume goes into the document. Xenon: detached
	// dir the schema-1 document consumes.
	sc, err := scratch.Prepare(sd, chain, scratchSize, isolation == isolationProcess)
	if err != nil {
		os.RemoveAll(containerDir(st, id))
		return "", s, fmt.Errorf("scratch: %w", err)
	}
	if sc.Volume != "" {
		e.Progress("volume:    %s", sc.Volume)
	}

	var ep *hcn.HostComputeEndpoint
	var addrs []string
	var namespace string
	if netw != nil {
		if ep, err = createEndpoint(netw, id+"-ep", isolation, published, acls); err != nil {
			destroyScratchFor(st, id, isolation)
			return "", s, err
		}
		for _, ip := range ep.IpConfigurations {
			addrs = append(addrs, fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength))
		}
		e.Progress("endpoint:  %s on %s (%s)", ep.Id, netw.Name, strings.Join(addrs, ","))
		// The v2 document names an HNS namespace, not an endpoint list: make
		// one and add the endpoint. The xenon's schema-1 document keeps
		// EndpointList and needs no namespace.
		if isolation == isolationProcess {
			if namespace, err = createNamespace(ep.Id); err != nil {
				_ = deleteEndpoint(ep.Id)
				destroyScratchFor(st, id, isolation)
				return "", s, err
			}
			e.Progress("namespace: %s", namespace)
		}
	}

	in := docInputs{
		Layers:     layers,
		Hostname:   o.hostname,
		CPUs:       cpus,
		MemoryMB:   memoryMB,
		Mounts:     mounts,
		Volume:     sc.Volume,
		Namespace:  namespace,
		ScratchDir: sd,
		UVM:        uvm,
	}
	if ep != nil {
		in.Endpoint = ep.Id
		// Enable unqualified DNS lookups whenever an endpoint is attached.
		in.AllowDNS = true
		in.DNSSearch = o.dnsSearch
	}
	var doc string
	if isolation == isolationProcess {
		doc, err = buildArgonDoc(in)
	} else {
		doc, err = buildXenonDoc(id, in)
	}
	if err != nil {
		if namespace != "" {
			_ = deleteNamespace(namespace)
		}
		if ep != nil {
			_ = deleteEndpoint(ep.Id)
		}
		destroyScratchFor(st, id, isolation)
		return "", s, err
	}

	s = state{ID: id, Ref: o.ref, Scratch: sd, UVM: uvm, Isolation: isolation, Chain: chain,
		Volume: sc.Volume, Namespace: namespace, Labels: labels, Published: published, ACLs: acls}
	if ep != nil {
		s.Endpoint = ep.Id
		s.Addresses = addrs
	}
	return doc, s, nil
}

// createNamespace makes a fresh HNS namespace and adds the endpoint to it --
// the attach shape a v2 document's Networking.Namespace consumes.
func createNamespace(endpointID string) (string, error) {
	// The empty namespace type is what hcsshim's own container path creates
	// (hcn.NewNamespace("")); a typed namespace fails the document's Construct
	// with 0x80070057.
	ns, err := hcn.NewNamespace("").Create()
	if err != nil {
		return "", fmt.Errorf("namespace Create: %w", err)
	}
	if err := hcn.AddNamespaceEndpoint(ns.Id, endpointID); err != nil {
		_ = ns.Delete()
		return "", fmt.Errorf("AddNamespaceEndpoint: %w", err)
	}
	return ns.Id, nil
}

// deleteNamespace removes a namespace; absence is success.
func deleteNamespace(id string) error {
	ns, err := hcn.GetNamespaceByID(id)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("GetNamespaceByID(%s): %w", id, err)
	}
	if err := ns.Delete(); err != nil {
		return fmt.Errorf("namespace Delete(%s): %w", id, err)
	}
	return nil
}

func create(o *createOptions, e cli.Emit) error {
	st, err := store.New(o.storeDir)
	if err != nil {
		return err
	}
	id, err := newID(o.id, o.ref)
	if err != nil {
		return err
	}

	doc, s, err := buildConfig(o, e, st, id)
	if err != nil {
		return err
	}
	// The primary process is recorded, not started: `start` launches it. The cmd
	// should be the target directly, not a `cmd /c` wrapper -- Kill terminates one process,
	// not a tree, and a wrapper's children would survive a later kill.
	if o.cmd != "" {
		s.Primary = &primaryState{Cmd: o.cmd}
	}

	c, err := computecore.Create(id, doc, createTimeout)
	if err != nil {
		destroy(st, s)
		return fmt.Errorf("create: %w", err)
	}

	// State is part of the creation transaction: without state.json, `rm` can never
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
		return fmt.Errorf("writing state: %w", err)
	}
	// The handle is dropped here: the compute system outlives this process and is reopened by
	// id. state.json records what HCS does not.
	c.Close()
	e.Result(map[string]any{
		"ok": true, "command": "container create", "id": id, "ref": o.ref,
		"utilityVM": s.UVM, "isolation": s.Isolation, "scratch": s.Scratch, "chain": s.Chain,
		"endpoint": s.Endpoint, "addresses": s.Addresses, "published": s.Published, "acls": s.ACLs,
	}, func() {
		fmt.Printf("created %s\n  id:      %s\n  scratch: %s\n", o.ref, id, s.Scratch)
		if s.Endpoint != "" {
			fmt.Printf("  address: %s\n", strings.Join(s.Addresses, ","))
		}
		for _, p := range s.Published {
			fmt.Printf("  publish: %s\n", p)
		}
		for _, a := range s.ACLs {
			fmt.Printf("  acl:     %s\n", a)
		}
	})
	return nil
}

// -- start / stop ------------------------------------------------------------------------

func start(o targetOptions, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	s, err := readState(st, id)
	if err != nil {
		return err
	}
	c, err := computecore.Open(id)
	if err != nil {
		return fmt.Errorf("open %s: %w", id, err)
	}
	defer c.Close()

	e.Progress("starting container...")

	if err := c.Start(startTimeout); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	if s.Primary == nil {
		e.Result(map[string]any{"ok": true, "command": "container start", "id": id}, func() {
			fmt.Printf("started %s\n", id)
		})
		return nil
	}

	// A primary process is recorded: launch it and stay attached as its pump. This
	// invocation owns the pipes -- HCS gives them out once, to the creator, unrecoverably --
	// so it tees everything to primary.log, where `container logs` can follow from any fresh
	// invocation, and records the exit in state.json when the process ends. If this pump
	// dies with its caller, the workload keeps running; the log truncates at that moment and
	// `logs` reports the pump's death rather than pretending the file is complete.
	logFile, err := os.Create(primaryLogPath(st, id))
	if err != nil {
		return fmt.Errorf("primary.log: %w", err)
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
			// Bookkeeping must not kill a started workload; `logs` reports the gap.
			e.Progress("recording primary pid: %v", werr)
		}
	}
	res, execErr := execIn(c, e, s.Primary.Cmd, "", "", nil, 0, outSink, errSink, onStart, execMode{})
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
		return execErr
	}
	e.Result(map[string]any{
		"ok": true, "command": "container start", "id": id,
		"primary": map[string]any{"cmd": s.Primary.Cmd, "pid": res.Pid, "exitCode": res.ExitCode},
	}, func() {
		fmt.Printf("started %s; primary pid %d exited %d\n", id, res.Pid, res.ExitCode)
	})
	return nil
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

func stop(o targetOptions, force bool, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	if _, err := readState(st, id); err != nil {
		return err
	}
	c, err := computecore.Open(id)
	if err != nil {
		return fmt.Errorf("open %s: %w", id, err)
	}
	defer c.Close()

	if err := shutdown(c, e, force); err != nil {
		return err
	}
	e.Result(map[string]any{"ok": true, "command": "container stop", "id": id}, func() {
		fmt.Printf("stopped %s\n", id)
	})
	return nil
}

// shutdown asks politely, then insists. A container's HcsShutDownComputeSystem
// takes NULL options (unlike the VM's). The operation completing is
// the request landing; Stopped:true in the properties is the exit -- a
// handle-holding process keeps a stopped system queryable, so absence is not
// the signal.
func shutdown(c *computecore.System, e cli.Emit, force bool) error {
	if !force {
		err := c.Shutdown("", shutdownWait)
		if err == nil {
			if werr := waitStopped(c, shutdownWait); werr == nil {
				e.Progress("shutdown ok")
				return nil
			}
			e.Progress("shutdown did not complete in %s, terminating", shutdownWait)
		} else if computecore.IsAlreadyStopped(err) || computecore.IsNotFound(err) {
			return nil
		} else {
			e.Progress("shutdown: %v -- terminating", err)
		}
	}
	if err := c.Terminate(terminateWait); err != nil &&
		!computecore.IsAlreadyStopped(err) && !computecore.IsNotFound(err) {
		return fmt.Errorf("terminate: %w", err)
	}
	if err := waitStopped(c, terminateWait); err != nil {
		return fmt.Errorf("wait after terminate: %w", err)
	}
	e.Progress("terminate ok")
	return nil
}

// waitStopped polls the system's properties until they report Stopped.
func waitStopped(c *computecore.System, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		props, err := c.Properties("", propsTimeout)
		if err != nil {
			// Gone entirely (another handle closed): also stopped.
			return nil
		}
		var p struct {
			Stopped bool `json:"Stopped"`
		}
		if json.Unmarshal([]byte(props), &p) == nil && p.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("still running %s after the stop request", timeout)
		}
		time.Sleep(time.Second)
	}
}

// -- exec --------------------------------------------------------------------------------

// parseEnv turns repeated --env NAME=value into ProcessConfig.Environment. The value keeps
// everything after the first '='. An empty value is an error: hcsshim sends {"NAME":""} over
// the wire intact, but the variable never appears in the guest (Win32 treats empty as
// deleted). There is no inherited environment here, so "unset" is expressed by omitting the
// variable.
func parseEnv(vals []string) (map[string]string, error) {
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

// killWait bounds the wait for a Kill to take effect. A process that survives its kill this
// long is a failure to report, not a thing to wait harder on.
const killWait = 10 * time.Second

// execResult is what execIn reports. ExitCode is meaningful only when neither TimedOut nor
// Interrupted is true: a killed process's code is an invention of the kill, not something the
// guest produced.
type execResult struct {
	ExitCode    int
	Pid         int
	TimedOut    bool
	Interrupted bool
}

// parseExitCode reads the exit code out of a ProcessStatus document
// (HcsWaitForProcessExit's answer -- the code is real on this route, no
// pre-reap artifact).
func parseExitCode(status string) (int, error) {
	var st computecore.ProcessStatus
	if err := json.Unmarshal([]byte(status), &st); err != nil {
		return -1, fmt.Errorf("parse ProcessStatus %q: %w", status, err)
	}
	if !st.Exited {
		return -1, fmt.Errorf("wait returned but Exited is false: %s", status)
	}
	return int(st.ExitCode), nil
}

// killConfirmed terminates a guest process and confirms the kill landed --
// the post-condition, not the return value.
func killConfirmed(p *computecore.Process, pid int) error {
	if err := p.Terminate(killWait); err != nil && !computecore.IsAlreadyStopped(err) {
		return fmt.Errorf("kill pid %d: %w", pid, err)
	}
	if _, err := p.WaitExit(killWait); err != nil {
		return fmt.Errorf("pid %d still running %s after kill: %w", pid, killWait, err)
	}
	return nil
}

// execIn launches a process, streams its output, and returns its exit code. The default closes
// stdin immediately; only explicit interactive mode forwards host input. A non-zero timeout
// kills the process on expiry. onStart, when non-nil, runs with the guest pid as soon as the
// process exists -- the primary-process path records it in state.json while it is still running.
func execIn(c *computecore.System, e cli.Emit, cmdline, cwd, user string, env map[string]string, timeout time.Duration, outSink, errSink io.Writer, onStart func(pid int), mode execMode) (execResult, error) {
	var res execResult
	res.ExitCode = -1
	doc, err := buildProcessDoc(cmdline, cwd, user, env, mode.tty, mode.consoleSize)
	if err != nil {
		return res, err
	}
	p, err := c.CreateProcess(doc, procCreateTimeout)
	if err != nil {
		return res, fmt.Errorf("create process (%q): %w", cmdline, err)
	}
	defer p.Close()
	res.Pid = int(p.Pid)
	if onStart != nil {
		onStart(res.Pid)
	}

	var closeStdinOnce sync.Once
	closeStdin := func() {
		closeStdinOnce.Do(func() {
			if p.Stdin != nil {
				_ = p.Stdin.Close()
			}
			_ = p.CloseStdin(propsTimeout)
		})
	}

	// Both streams are drained concurrently. Draining them in sequence deadlocks as soon as the
	// guest fills the pipe this side is not reading. The sinks are separate so --stream-json
	// can attribute guest stdout and stderr individually, while interactive mode sends both
	// streams directly to the terminal.
	var wg sync.WaitGroup
	for _, s := range []struct {
		r    *os.File
		sink io.Writer
	}{{p.Stdout, outSink}, {p.Stderr, errSink}} {
		if s.r == nil {
			continue
		}
		wg.Add(1)
		go func(r *os.File, sink io.Writer) {
			defer wg.Done()
			defer r.Close()
			_, _ = io.Copy(sink, r)
		}(s.r, s.sink)
	}

	if mode.interactive {
		if p.Stdin == nil {
			return res, fmt.Errorf("interactive process has no stdin pipe")
		}
		interrupt, stopInterrupt := interruptContext()
		defer stopInterrupt()
		forwardStdin(os.Stdin, p.Stdin, closeStdin, mode.tty, stopInterrupt)

		status, timedOut, interrupted, waitErr := waitInteractive(p, e, timeout, interrupt.Done(), closeStdin, res.Pid)
		res.TimedOut = timedOut
		res.Interrupted = interrupted
		wg.Wait()
		if waitErr != nil {
			return res, waitErr
		}
		if res.TimedOut || res.Interrupted {
			return res, nil
		}
		code, err := parseExitCode(status)
		if err != nil {
			return res, err
		}
		res.ExitCode = code
		return res, nil
	}

	closeStdin()
	status, err := p.WaitExit(timeout) // timeout 0 = wait forever
	if err != nil {
		if timeout > 0 && computecore.IsTimeout(err) {
			// Expired: kill, then confirm the kill landed rather than trusting it. A timeout
			// and a guest exit must stay distinguishable, so the exit code is not collected --
			// it would be the kill's invention, not the guest's.
			res.TimedOut = true
			e.Progress("timeout %s expired, killing pid %d", timeout, res.Pid)
			kerr := killConfirmed(p, res.Pid)
			wg.Wait()
			return res, kerr
		}
		wg.Wait()
		return res, fmt.Errorf("process wait: %w", err)
	}
	wg.Wait()
	code, err := parseExitCode(status)
	if err != nil {
		return res, err
	}
	res.ExitCode = code
	return res, nil
}

// waitProc is what waitInteractive needs from a process -- narrowed so the
// interrupt path is testable without HCS.
type waitProc interface {
	WaitExit(time.Duration) (string, error)
	Terminate(time.Duration) error
}

// waitInteractive blocks on the process exit, the interrupt, or the deadline,
// whichever lands first. status is meaningful only when none of timedOut,
// interrupted, or err is set.
func waitInteractive(p waitProc, e cli.Emit, timeout time.Duration, interrupted <-chan struct{}, closeStdin func(), pid int) (status string, timedOut, wasInterrupted bool, err error) {
	type exitMsg struct {
		status string
		err    error
	}
	exited := make(chan exitMsg, 1)
	go func() {
		s, werr := p.WaitExit(0)
		exited <- exitMsg{s, werr}
	}()

	var deadline <-chan time.Time
	var timer *time.Timer
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}

	killAndReap := func() error {
		if err := p.Terminate(killWait); err != nil && !computecore.IsAlreadyStopped(err) {
			return fmt.Errorf("kill pid %d: %w", pid, err)
		}
		select {
		case <-exited:
			return nil
		case <-time.After(killWait):
			return fmt.Errorf("pid %d still running %s after kill", pid, killWait)
		}
	}

	select {
	case m := <-exited:
		if m.err != nil {
			return "", false, false, fmt.Errorf("process wait: %w", m.err)
		}
		return m.status, false, false, nil
	case <-interrupted:
		closeStdin()
		e.Progress("interrupt received, killing pid %d", pid)
		return "", false, true, killAndReap()
	case <-deadline:
		closeStdin()
		e.Progress("timeout %s expired, killing pid %d", timeout, pid)
		return "", true, false, killAndReap()
	}
}

func exec(o *execOptions, e cli.Emit) error {
	if o.tty && !o.interactive {
		return cli.Usagef("--tty requires --interactive")
	}
	if o.interactive && (e.JSON || e.StreamJSON) {
		return cli.Usagef("--interactive cannot be used with --json or --stream-json")
	}
	st, id, err := resolve(o.targetOptions)
	if err != nil {
		return err
	}
	env, err := parseEnv(o.env)
	if err != nil {
		return err
	}
	timeout := o.timeout
	if _, err := readState(st, id); err != nil {
		return err
	}
	c, err := computecore.Open(id)
	if err != nil {
		return fmt.Errorf("open %s: %w", id, err)
	}
	defer c.Close()

	mode := execMode{interactive: o.interactive, tty: o.tty}
	restoreTerminal := func() {}
	if mode.tty {
		restore, consoleSize, terr := prepareTerminal()
		if terr != nil {
			return fmt.Errorf("--tty requires attached stdin and stdout terminals: %w", terr)
		}
		var restoreOnce sync.Once
		restoreTerminal = func() { restoreOnce.Do(restore) }
		defer restoreTerminal()
		mode.consoleSize = consoleSize
	}
	if mode.interactive {
		res, err := execIn(c, e, o.cmd, o.cwd, o.user, env, timeout, os.Stdout, os.Stderr, nil, mode)
		if err != nil {
			return err
		}
		restoreTerminal()
		printExec(res)
		if res.Interrupted {
			// printExec already reported the interruption; ErrReported keeps the exit-1
			// verdict without a second voice on stderr.
			return cli.ErrReported
		}
		return nil
	}

	out := &captured{json: e.JSON}
	outSink, errSink, closeFraming := guestSinks(e, out)
	res, err := execIn(c, e, o.cmd, o.cwd, o.user, env, timeout, outSink, errSink, e.StreamExecStarted, mode)
	closeFraming()
	if err != nil {
		return err
	}
	e.Result(execDoc("container exec", id, o.cmd, res, out), func() {
		printExec(res)
	})
	return nil
}

// guestSinks wires guest output for one exec. Default: both guest streams merge into the
// captured buffer, which tees live. Under --stream-json (with --json), each stream additionally
// flows through its own NDJSON line framer, the tee goes quiet (the framers own stderr), and
// the buffer keeps serving the final document's merged output field.
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
	if res.Interrupted {
		fmt.Printf("interrupted, killed pid %d\n", res.Pid)
		return
	}
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
	// and this buffer serves only the final document's output field.
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
func run(o *runOptions, e cli.Emit) error {
	env, err := parseEnv(o.env)
	if err != nil {
		return err
	}
	timeout := o.timeout
	st, err := store.New(o.storeDir)
	if err != nil {
		return err
	}
	id, err := newID(o.id, o.ref)
	if err != nil {
		return err
	}
	cmdline := o.cmd
	if cmdline == "" {
		cmdline = defaultCmd
	}

	doc, s, err := buildConfig(&o.createOptions, e, st, id)
	if err != nil {
		return err
	}
	// Same transaction rule as create: buildConfig has acquired the scratch and any
	// endpoint by now, and without state.json nothing can ever find them to clean them up.
	if err := writeState(st, s); err != nil {
		if derr := destroy(st, s); derr != nil {
			e.Progress("cleanup after failed state write: %v", derr)
		}
		return fmt.Errorf("writing state: %w", err)
	}

	c, err := computecore.Create(id, doc, createTimeout)
	if err != nil {
		destroy(st, s)
		return fmt.Errorf("create: %w", err)
	}
	e.Progress("create ok (computecore)")

	// From here the container exists in HCS and must be torn down on every path out.
	cleanup := func() {
		if o.keep {
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

	e.Progress("starting container...")

	if err := c.Start(startTimeout); err != nil {
		cleanup()
		return fmt.Errorf("start: %w", err)
	}
	e.Progress("started")

	out := &captured{json: e.JSON}
	outSink, errSink, closeFraming := guestSinks(e, out)
	res, execErr := execIn(c, e, cmdline, o.cwd, o.user, env, timeout, outSink, errSink, e.StreamExecStarted, execMode{})
	closeFraming()
	cleanup()
	if execErr != nil {
		return execErr
	}

	// The CLI's own exit code stays on contract -- 0 means hcsctl ran the thing -- and the
	// guest's exit code is reported in the document rather than conflated with it.
	resDoc := execDoc("container run", id, cmdline, res, out)
	resDoc["ref"] = o.ref
	resDoc["utilityVM"] = s.UVM
	resDoc["isolation"] = s.Isolation
	resDoc["kept"] = o.keep
	resDoc["endpoint"] = s.Endpoint
	resDoc["addresses"] = s.Addresses
	resDoc["published"] = s.Published
	resDoc["acls"] = s.ACLs
	e.Result(resDoc, func() {
		printExec(res)
	})
	return nil
}

// kill terminates one guest process by pid. It exists because an exec that hcsctl no longer
// owns -- a crashed caller, an abandoned long-running app -- leaves a process nothing can
// reach: HCS pipes belong to whoever created them, but Kill needs only the pid.
// --pid was required and parsed by killCmd before any container lookup.
func kill(o targetOptions, pid uint64, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	if _, err := readState(st, id); err != nil {
		return err
	}
	c, err := computecore.Open(id)
	if err != nil {
		return fmt.Errorf("open %s: %w", id, err)
	}
	defer c.Close()

	// A pid that is not there is a runtime fact, not a bad command line: the process may have
	// exited a moment ago, so it is exit 1 with the message.
	p, err := c.OpenProcess(uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer p.Close()

	if err := killConfirmed(p, int(pid)); err != nil {
		return err
	}

	e.Result(map[string]any{
		"ok": true, "command": "container kill", "id": id, "pid": pid, "killed": true,
	}, func() {
		fmt.Printf("killed pid %d in %s\n", pid, id)
	})
	return nil
}

// -- rm / ls -----------------------------------------------------------------------------

// destroyScratchFor removes a scratch in its final state for the recorded
// isolation: an argon's scratch may still be filter-attached, so Teardown
// detaches first; a xenon's is a detached VHD in a directory.
func destroyScratchFor(st *store.Store, id, isolation string) error {
	if err := scratch.Teardown(scratchDir(st, id), isolation == isolationProcess); err != nil {
		return err
	}
	return os.RemoveAll(containerDir(st, id))
}

// destroy tears down everything a container owns outside HCS: its namespace,
// its endpoint, then its scratch. Every step is attempted regardless of
// earlier failures -- a half-torn-down container should lose as much as
// possible -- and the first error is what gets reported.
func destroy(st *store.Store, s state) error {
	var first error
	if s.Namespace != "" {
		first = deleteNamespace(s.Namespace)
	}
	if s.Endpoint != "" {
		if err := deleteEndpoint(s.Endpoint); err != nil && first == nil {
			first = err
		}
	}
	if err := destroyScratchFor(st, s.ID, s.Isolation); err != nil && first == nil {
		first = err
	}
	return first
}

func remove(o targetOptions, force bool, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	s, err := readState(st, id)
	if err != nil {
		// A create that died before writeState leaves a directory with no
		// state.json -- a scratch (possibly with a still-attached sandbox)
		// and nothing else. rm is the only thing that can ever clean it, so
		// it proceeds with an empty record; Teardown detaches defensively.
		if _, serr := os.Stat(containerDir(st, id)); serr == nil {
			e.Progress("no state.json -- removing the orphaned directory (interrupted create)")
			s = state{ID: id, Isolation: isolationProcess}
		} else {
			return err
		}
	}

	// A container that is gone from HCS but still on disk is the normal state after a crash, so
	// a failure to open is not fatal here -- the scratch and endpoint still need removing.
	if c, err := computecore.Open(id); err == nil {
		if err := shutdown(c, e, force); err != nil {
			e.Progress("stop: %v", err)
		}
		c.Close()
	} else if !computecore.IsNotFound(err) {
		e.Progress("open: %v -- removing on-disk state anyway", err)
	}

	if err := destroy(st, s); err != nil {
		return err
	}
	e.Result(map[string]any{"ok": true, "command": "container rm", "id": id}, func() {
		fmt.Printf("removed %s\n", id)
	})
	return nil
}

func list(storeDir string, e cli.Emit) error {
	st, err := store.New(storeDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(containersRoot(st))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// HCS is the authority on whether a container is running; the store is the authority on
	// what it was made from. Neither alone gives a useful listing.
	running := map[string]string{}
	if doc, err := computecore.Enumerate("", propsTimeout); err == nil {
		var systems []struct {
			ID    string `json:"Id"`
			State string `json:"State"`
		}
		if jerr := json.Unmarshal([]byte(doc), &systems); jerr == nil {
			for _, p := range systems {
				running[p.ID] = p.State
			}
		}
	} else {
		e.Progress("enumerate: %v -- state column will be unknown", err)
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
	return nil
}

// -- introspection -----------------------------------------------------------------------

// open is the common preamble for every verb that inspects a live container: resolve the id,
// confirm we know about it, and get a handle.
func open(o targetOptions) (*computecore.System, string, error) {
	st, id, err := resolve(o)
	if err != nil {
		return nil, "", err
	}
	if _, err := readState(st, id); err != nil {
		return nil, id, err
	}
	c, err := computecore.Open(id)
	if err != nil {
		return nil, id, fmt.Errorf("open %s: %w", id, err)
	}
	return c, id, nil
}

// v2Statistics is the shape of the Statistics property. There
// is NO network section in v2 -- the schema-1 one is gone.
type v2Statistics struct {
	Statistics struct {
		ContainerStartTime time.Time `json:"ContainerStartTime"`
		Uptime100ns        uint64    `json:"Uptime100ns"`
		Processor          struct {
			TotalRuntime100ns  uint64 `json:"TotalRuntime100ns"`
			RuntimeUser100ns   uint64 `json:"RuntimeUser100ns"`
			RuntimeKernel100ns uint64 `json:"RuntimeKernel100ns"`
		} `json:"Processor"`
		Memory struct {
			MemoryUsageCommitBytes            uint64 `json:"MemoryUsageCommitBytes"`
			MemoryUsageCommitPeakBytes        uint64 `json:"MemoryUsageCommitPeakBytes"`
			MemoryUsagePrivateWorkingSetBytes uint64 `json:"MemoryUsagePrivateWorkingSetBytes"`
		} `json:"Memory"`
		Storage struct {
			ReadCountNormalized  uint64 `json:"ReadCountNormalized"`
			WriteCountNormalized uint64 `json:"WriteCountNormalized"`
		} `json:"Storage"`
	} `json:"Statistics"`
}

func stats(o targetOptions, e cli.Emit) error {
	c, id, err := open(o)
	if err != nil {
		return err
	}
	defer c.Close()

	doc, err := c.Properties(`{"PropertyTypes":["Statistics"]}`, propsTimeout)
	if err != nil {
		return fmt.Errorf("statistics: %w", err)
	}
	var s v2Statistics
	if err := json.Unmarshal([]byte(doc), &s); err != nil {
		return fmt.Errorf("parse statistics %q: %w", doc, err)
	}
	e.Result(map[string]any{
		// The raw v2 property document, passed through -- contract 3.
		"ok": true, "command": "container stats", "id": id, "statistics": json.RawMessage(doc),
	}, func() {
		st := s.Statistics
		// 100ns ticks are what HCS reports; seconds are what a person wants.
		fmt.Printf("uptime            %s\n", time.Duration(st.Uptime100ns*100))
		fmt.Printf("started           %s\n", st.ContainerStartTime.Format(time.RFC3339))
		fmt.Printf("memory commit     %s\n", bytes(st.Memory.MemoryUsageCommitBytes))
		fmt.Printf("memory peak       %s\n", bytes(st.Memory.MemoryUsageCommitPeakBytes))
		fmt.Printf("working set priv  %s\n", bytes(st.Memory.MemoryUsagePrivateWorkingSetBytes))
		fmt.Printf("cpu total         %s\n", time.Duration(st.Processor.TotalRuntime100ns*100))
		fmt.Printf("cpu user/kernel   %s / %s\n",
			time.Duration(st.Processor.RuntimeUser100ns*100),
			time.Duration(st.Processor.RuntimeKernel100ns*100))
		fmt.Printf("storage r/w       %d / %d ops\n",
			st.Storage.ReadCountNormalized, st.Storage.WriteCountNormalized)
	})
	return nil
}

// v2ProcessEntry is one ProcessList row.
type v2ProcessEntry struct {
	ProcessId         uint32 `json:"ProcessId"`
	ImageName         string `json:"ImageName"`
	UserTime100ns     uint64 `json:"UserTime100ns"`
	KernelTime100ns   uint64 `json:"KernelTime100ns"`
	MemoryCommitBytes uint64 `json:"MemoryCommitBytes"`
}

func ps(o targetOptions, e cli.Emit) error {
	c, id, err := open(o)
	if err != nil {
		return err
	}
	defer c.Close()

	doc, err := c.Properties(`{"PropertyTypes":["ProcessList"]}`, propsTimeout)
	if err != nil {
		return fmt.Errorf("process list: %w", err)
	}
	var pl struct {
		ProcessList []v2ProcessEntry `json:"ProcessList"`
	}
	if err := json.Unmarshal([]byte(doc), &pl); err != nil {
		return fmt.Errorf("parse process list %q: %w", doc, err)
	}
	procs := pl.ProcessList
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
	return nil
}

// inspect reports what HCS itself knows, which is a different and larger set than state.json.
func inspect(o targetOptions, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	s, err := readState(st, id)
	if err != nil {
		return err
	}

	// The raw v2 property document, passed through (contract 3) -- the verb
	// for finding out what HCS actually holds. Absent from HCS is hcs: null.
	var hcsDoc any
	var parsed struct {
		State      string `json:"State"`
		Owner      string `json:"Owner"`
		SystemType string `json:"SystemType"`
		Stopped    bool   `json:"Stopped"`
		ExitType   string `json:"ExitType"`
	}
	present := false
	if c, err := computecore.Open(id); err == nil {
		props, perr := c.Properties("", propsTimeout)
		c.Close()
		if perr != nil {
			return fmt.Errorf("properties: %w", perr)
		}
		hcsDoc = json.RawMessage(props)
		present = true
		_ = json.Unmarshal([]byte(props), &parsed)
	} else if !computecore.IsNotFound(err) {
		return fmt.Errorf("open %s: %w", id, err)
	}

	doc := map[string]any{"ok": true, "command": "container inspect", "id": id, "state": s, "hcs": hcsDoc}
	e.Result(doc, func() {
		fmt.Printf("id         %s\nref        %s\nscratch    %s\nutilityVM  %s\n",
			s.ID, s.Ref, s.Scratch, s.UVM)
		fmt.Printf("chain      %d layer(s)\n", len(s.Chain))
		for _, l := range s.Chain {
			fmt.Printf("           %s\n", l)
		}
		if !present {
			fmt.Println("hcs        absent (not created, or already torn down)")
			return
		}
		fmt.Printf("hcs state  %s\n", orDash(parsed.State))
		fmt.Printf("owner      %s\n", orDash(parsed.Owner))
		fmt.Printf("systemType %s\n", orDash(parsed.SystemType))
		if parsed.Stopped {
			fmt.Printf("stopped    true (exitType %s)\n", orDash(parsed.ExitType))
		}
	})
	return nil
}

// pauseResume covers both: the same verb with a different call and a different past participle.
// The platform refuses Pause for process-isolated containers (0x80070032); the refusal is the
// report.
func pauseResume(o targetOptions, e cli.Emit, verb string) error {
	c, id, err := open(o)
	if err != nil {
		return err
	}
	defer c.Close()

	call, done, api := c.Pause, "paused", "pause"
	if verb == "resume" {
		call, done, api = c.Resume, "resumed", "resume"
	}
	if err := call(propsTimeout); err != nil {
		return fmt.Errorf("%s: %w", api, err)
	}
	e.Result(map[string]any{
		"ok": true, "command": "container " + verb, "id": id,
	}, func() { fmt.Printf("%s %s\n", done, id) })
	return nil
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

// logs reads a primary process's retained output from a fresh invocation. It reads the
// file the pump wrote, never the pipes -- those died with their creator. Status comes from
// state.json: running (pump alive), exited (code recorded), or pump dead (the log may be
// truncated and the exit unrecorded).
func logs(o targetOptions, follow bool, e cli.Emit) error {
	st, id, err := resolve(o)
	if err != nil {
		return err
	}
	s, err := readState(st, id)
	if err != nil {
		return err
	}
	if s.Primary == nil {
		return cli.Usagef("no primary process recorded for %q -- `container create --cmd` records one", id)
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

	if !follow {
		b, err := os.ReadFile(lp)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		e.Result(map[string]any{
			"ok": true, "command": "container logs", "id": id,
			"primary": s.Primary, "status": status(s), "log": string(b),
		}, func() {
			fmt.Print(string(b))
		})
		return nil
	}

	// Follow: emit the file as it grows, re-reading state each pass to notice the exit (or
	// the pump's death). Lines go to stderr in JSON mode -- stdout still carries exactly one
	// document, at the end -- and are framed under --stream-json as {"stream":"log"}: the
	// file merges guest stdout and stderr, so there is no per-stream attribution.
	f, err := os.Open(lp)
	if err != nil && !os.IsNotExist(err) {
		return err
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
				return fmt.Errorf("state disappeared while following: %v", rerr)
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
				return nil
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
func resolve(o targetOptions) (*store.Store, string, error) {
	st, err := store.New(o.storeDir)
	if err != nil {
		// Exit 64, as the pre-cobra dispatch classified every resolve failure: the command
		// line (with its environment) names a store that cannot be resolved, and nothing
		// was attempted.
		return nil, "", cli.Usagef("store: %v", err)
	}
	id := o.id
	if id == "" {
		if o.ref != "" {
			id = idFor(o.ref)
		} else {
			return nil, "", cli.Usagef("--id or --ref is required")
		}
	}
	if err := cli.ValidateID(id); err != nil {
		return nil, "", err
	}
	return st, id, nil
}
