//go:build windows

package container

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"

	"github.com/joshmakestuff/hcsctl/internal/vmcompute"
)

// Container routes. v1 is the schema-1 route (hcsshim.CreateContainer): the
// historically measured surface, and the only route for a self-contained hyperv
// (xenon) container -- the v2 Container schema has no HvRuntime field, and
// hcsoci's v2 xenon is a different architecture (a container hosted inside a
// pre-built utility VM). v2 is the ComputeSystem-document route
// (HcsCreateComputeSystem with Container.Storage), measured working for the
// argon on a computestorage VHD scratch, full flag matrix and the
// create-close-reopen lifecycle (hcsctl#86, argonprobe v2-route cell). The
// default argon route is v2; --storage wclayer keeps the v1 argon route.
const (
	routeV1 = "v1"
	routeV2 = "v2"
)

// shutdownBound bounds the v2 system's synchronous Shutdown/Terminate waits.
const shutdownBound = 60 * time.Second

// createTimeout bounds the v2 create's completion wait. A cold create of an
// argon is seconds; the v1 call has no external bound (hcsshim's own timeout).
const createTimeout = 2 * time.Minute

// routeFor maps an isolation/storage combination to its container route.
func routeFor(isolation, storage string) string {
	if isolation == isolationProcess && storage != storageWclayer {
		return routeV2
	}
	return routeV1
}

// processIface is the process surface the container verbs use. Both routes
// implement it: the v1 route is hcsshim.Process, the v2 route is vmcompute.Process
// adapted here.
type processIface interface {
	Pid() int
	Kill() error
	Wait() error
	WaitTimeout(time.Duration) error
	ExitCode() (int, error)
	Stdio() (io.WriteCloser, io.ReadCloser, io.ReadCloser, error)
	CloseStdin() error
	Close() error
}

// containerIface is the live-container surface the container verbs use. Both
// routes implement it: the v1 route is hcsshim.Container, the v2 route is
// vmcompute.System adapted here.
type containerIface interface {
	Start() error
	Shutdown() error
	Terminate() error
	WaitTimeout(time.Duration) error
	Pause() error
	Resume() error
	Statistics() (hcsshim.Statistics, error)
	ProcessList() ([]hcsshim.ProcessListItem, error)
	CreateProcess(*hcsshim.ProcessConfig) (processIface, error)
	OpenProcess(int) (processIface, error)
	Close() error
}

// -- v1 adapter --------------------------------------------------------------------------

// v1Container adapts hcsshim.Container to containerIface. The embedded methods
// already match every verb's shape except CreateProcess/OpenProcess, whose
// return types are narrowed to processIface.
type v1Container struct {
	hcsshim.Container
}

func (c *v1Container) CreateProcess(pc *hcsshim.ProcessConfig) (processIface, error) {
	p, err := c.Container.CreateProcess(pc)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (c *v1Container) OpenProcess(pid int) (processIface, error) {
	p, err := c.Container.OpenProcess(pid)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// -- v2 document -------------------------------------------------------------------------

// The v2 ComputeSystem document, the subset hcsctl's surface needs. Field names
// are HCS PascalCase; the mapping is hcsoci's v2 argon shape
// (hcsshim/internal/hcsoci/hcsdoc_wcow.go), with the storage cell, full flag
// matrix and the close/reopen lifecycle measured end-to-end by the argonprobe
// v2-route cell (hcsctl#86).

type v2ComputeSystem struct {
	Owner                             string          `json:"Owner,omitempty"`
	SchemaVersion                     *v2Version      `json:"SchemaVersion,omitempty"`
	Container                         *v2ContainerDoc `json:"Container,omitempty"`
	ShouldTerminateOnLastHandleClosed bool            `json:"ShouldTerminateOnLastHandleClosed,omitempty"`
}

type v2Version struct {
	Major int32 `json:"Major"`
	Minor int32 `json:"Minor"`
}

type v2ContainerDoc struct {
	GuestOs           *v2GuestOs    `json:"GuestOs,omitempty"`
	Processor         *v2Processor  `json:"Processor,omitempty"`
	Memory            *v2Memory     `json:"Memory,omitempty"`
	Storage           *v2Storage    `json:"Storage,omitempty"`
	MappedDirectories []v2MappedDir `json:"MappedDirectories,omitempty"`
	Networking        *v2Networking `json:"Networking,omitempty"`
}

type v2GuestOs struct {
	HostName string `json:"HostName,omitempty"`
}

type v2Processor struct {
	Count   int32 `json:"Count,omitempty"`
	Maximum int32 `json:"Maximum,omitempty"`
	Weight  int32 `json:"Weight,omitempty"`
}

type v2Memory struct {
	SizeInMB uint64 `json:"SizeInMB,omitempty"`
}

type v2Storage struct {
	Layers []v2Layer `json:"Layers,omitempty"`
	Path   string    `json:"Path,omitempty"`
}

type v2Layer struct {
	Id   string `json:"Id,omitempty"`
	Path string `json:"Path,omitempty"`
}

type v2MappedDir struct {
	HostPath      string `json:"HostPath,omitempty"`
	ContainerPath string `json:"ContainerPath,omitempty"`
	ReadOnly      bool   `json:"ReadOnly,omitempty"`
}

type v2Networking struct {
	AllowUnqualifiedDnsQuery bool   `json:"AllowUnqualifiedDnsQuery,omitempty"`
	DnsSearchList            string `json:"DnsSearchList,omitempty"`
	Namespace                string `json:"Namespace,omitempty"`
}

// v2ProcessParams is the v2 ProcessParameters document, the subset the surface
// maps from hcsshim.ProcessConfig (the schema-2 shape the probe measured).
type v2ProcessParams struct {
	CommandLine      string            `json:"CommandLine,omitempty"`
	User             string            `json:"User,omitempty"`
	WorkingDirectory string            `json:"WorkingDirectory,omitempty"`
	Environment      map[string]string `json:"Environment,omitempty"`
	EmulateConsole   bool              `json:"EmulateConsole,omitempty"`
	CreateStdInPipe  bool              `json:"CreateStdInPipe,omitempty"`
	CreateStdOutPipe bool              `json:"CreateStdOutPipe,omitempty"`
	CreateStdErrPipe bool              `json:"CreateStdErrPipe,omitempty"`
	ConsoleSize      []int32           `json:"ConsoleSize,omitempty"`
}

func v2ParamsFrom(pc *hcsshim.ProcessConfig) v2ProcessParams {
	out := v2ProcessParams{
		CommandLine:      pc.CommandLine,
		User:             pc.User,
		WorkingDirectory: pc.WorkingDirectory,
		Environment:      pc.Environment,
		EmulateConsole:   pc.EmulateConsole,
		CreateStdInPipe:  pc.CreateStdInPipe,
		CreateStdOutPipe: pc.CreateStdOutPipe,
		CreateStdErrPipe: pc.CreateStdErrPipe,
	}
	if pc.ConsoleSize != [2]uint{} {
		// hcsshim's ProcessConfig orders ConsoleSize height-then-width; the v2
		// schema documents height-then-width in the ConsoleSize slice the same
		// way, so pass the pair through in order.
		out.ConsoleSize = []int32{int32(pc.ConsoleSize[0]), int32(pc.ConsoleSize[1])}
	}
	return out
}

// v2LayersFor maps the materialized chain to the document's Storage.Layers:
// Id is the wclayer NameToGuid of the directory name (the same id the v1 route
// and the probe use), Path is the layer directory. A NameToGuid failure is an
// error, not a skipped layer: an empty or shortened Storage.Layers is the
// document shape that fast-failed vmcompute in #86.
func v2LayersFor(chain []string) ([]v2Layer, error) {
	out := make([]v2Layer, 0, len(chain))
	for _, l := range chain {
		g, err := hcsshim.NameToGuid(filepath.Base(l))
		if err != nil {
			return nil, fmt.Errorf("NameToGuid(%s): %w", filepath.Base(l), err)
		}
		out = append(out, v2Layer{Id: g.ToString(), Path: l})
	}
	return out, nil
}

// v2MountsFor maps the v1 MappedDirectories onto the v2 document shape.
func v2MountsFor(mounts []hcsshim.MappedDir) []v2MappedDir {
	if len(mounts) == 0 {
		return nil
	}
	out := make([]v2MappedDir, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, v2MappedDir{HostPath: m.HostPath, ContainerPath: m.ContainerPath, ReadOnly: m.ReadOnly})
	}
	return out
}

// v2StorageFor assembles Container.Storage: the stacked volume path plus the
// layer chain, each layer Id being the wclayer NameToGuid of its directory.
func v2StorageFor(chain []string, volume string) (*v2Storage, error) {
	layers, err := v2LayersFor(chain)
	if err != nil {
		return nil, err
	}
	return &v2Storage{Path: volume, Layers: layers}, nil
}

// -- v2 adapter --------------------------------------------------------------------------

// v2Container adapts vmcompute.System to containerIface.
type v2Container struct {
	sys *vmcompute.System
}

func (c *v2Container) Start() error { return c.sys.Start(startTimeout) }

func (c *v2Container) Shutdown() error { return c.sys.Shutdown(shutdownBound) }

func (c *v2Container) Terminate() error { return c.sys.Terminate(shutdownBound) }

// WaitTimeout is a no-op: unlike the v1 route, Shutdown/Terminate on the v2
// route are synchronous and have already waited for the exit notification.
func (c *v2Container) WaitTimeout(time.Duration) error { return nil }

func (c *v2Container) Pause() error  { return c.sys.Pause(shutdownBound) }
func (c *v2Container) Resume() error { return c.sys.Resume(shutdownBound) }

// Statistics converts the v2 property document into the v1 shape the verb
// prints. The v2 Statistics carries no Network section (v1 did); the verb's
// network line simply has nothing to print.
func (c *v2Container) Statistics() (hcsshim.Statistics, error) {
	doc, err := c.sys.Properties(`{"PropertyTypes":["Statistics"]}`)
	if err != nil {
		return hcsshim.Statistics{}, err
	}
	var p struct {
		Statistics *struct {
			ContainerStartTime time.Time `json:"ContainerStartTime,omitempty"`
			Uptime100ns        uint64    `json:"Uptime100ns,omitempty"`
			Processor          *struct {
				TotalRuntime100ns  uint64 `json:"TotalRuntime100ns,omitempty"`
				RuntimeUser100ns   uint64 `json:"RuntimeUser100ns,omitempty"`
				RuntimeKernel100ns uint64 `json:"RuntimeKernel100ns,omitempty"`
			} `json:"Processor,omitempty"`
			Memory *struct {
				MemoryUsageCommitBytes            uint64 `json:"MemoryUsageCommitBytes,omitempty"`
				MemoryUsageCommitPeakBytes        uint64 `json:"MemoryUsageCommitPeakBytes,omitempty"`
				MemoryUsagePrivateWorkingSetBytes uint64 `json:"MemoryUsagePrivateWorkingSetBytes,omitempty"`
			} `json:"Memory,omitempty"`
			Storage *struct {
				ReadCountNormalized  uint64 `json:"ReadCountNormalized,omitempty"`
				WriteCountNormalized uint64 `json:"WriteCountNormalized,omitempty"`
			} `json:"Storage,omitempty"`
		} `json:"Statistics,omitempty"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return hcsshim.Statistics{}, fmt.Errorf("parse statistics %q: %w", doc, err)
	}
	if p.Statistics == nil {
		return hcsshim.Statistics{}, fmt.Errorf("no Statistics in %q", doc)
	}
	st := p.Statistics
	out := hcsshim.Statistics{
		ContainerStartTime: st.ContainerStartTime,
		Uptime100ns:        st.Uptime100ns,
	}
	if st.Processor != nil {
		out.Processor = hcsshim.ProcessorStats{
			TotalRuntime100ns:  st.Processor.TotalRuntime100ns,
			RuntimeUser100ns:   st.Processor.RuntimeUser100ns,
			RuntimeKernel100ns: st.Processor.RuntimeKernel100ns,
		}
	}
	if st.Memory != nil {
		out.Memory = hcsshim.MemoryStats{
			UsageCommitBytes:            st.Memory.MemoryUsageCommitBytes,
			UsageCommitPeakBytes:        st.Memory.MemoryUsageCommitPeakBytes,
			UsagePrivateWorkingSetBytes: st.Memory.MemoryUsagePrivateWorkingSetBytes,
		}
	}
	if st.Storage != nil {
		out.Storage = hcsshim.StorageStats{
			ReadCountNormalized:  st.Storage.ReadCountNormalized,
			WriteCountNormalized: st.Storage.WriteCountNormalized,
		}
	}
	return out, nil
}

// ProcessList converts the v2 ProcessDetails document into the v1 shape the
// verb prints.
func (c *v2Container) ProcessList() ([]hcsshim.ProcessListItem, error) {
	doc, err := c.sys.Properties(`{"PropertyTypes":["ProcessList"]}`)
	if err != nil {
		return nil, err
	}
	var p struct {
		ProcessList []struct {
			ProcessId         int32  `json:"ProcessId,omitempty"`
			ImageName         string `json:"ImageName,omitempty"`
			UserTime100ns     int32  `json:"UserTime100ns,omitempty"`
			KernelTime100ns   int32  `json:"KernelTime100ns,omitempty"`
			MemoryCommitBytes int32  `json:"MemoryCommitBytes,omitempty"`
		} `json:"ProcessList,omitempty"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return nil, fmt.Errorf("parse process list %q: %w", doc, err)
	}
	out := make([]hcsshim.ProcessListItem, 0, len(p.ProcessList))
	for _, pd := range p.ProcessList {
		out = append(out, hcsshim.ProcessListItem{
			ProcessId:         uint32(pd.ProcessId),
			ImageName:         pd.ImageName,
			UserTime100ns:     uint64(pd.UserTime100ns),
			KernelTime100ns:   uint64(pd.KernelTime100ns),
			MemoryCommitBytes: uint64(pd.MemoryCommitBytes),
		})
	}
	return out, nil
}

func (c *v2Container) CreateProcess(pc *hcsshim.ProcessConfig) (processIface, error) {
	p, err := c.sys.CreateProcess(v2ParamsFrom(pc))
	if err != nil {
		return nil, err
	}
	return &v2Process{p}, nil
}

func (c *v2Container) OpenProcess(pid int) (processIface, error) {
	p, err := c.sys.OpenProcess(pid)
	if err != nil {
		return nil, err
	}
	return &v2Process{p}, nil
}

func (c *v2Container) Close() error {
	c.sys.Close()
	return nil
}

// v2Process adapts vmcompute.Process to processIface.
type v2Process struct {
	*vmcompute.Process
}

// createContainer makes the compute system through the route's binding. The
// returned handle is closed by the caller; the system survives because both
// routes set terminate-on-last-handle-closed false and are reopened by id.
// createTimeout bounds the v2 create's completion wait; the v1 call is
// synchronous inside hcsshim.
func createContainer(id, route string, cfg any) (containerIface, error) {
	if route == routeV2 {
		sys, err := vmcompute.Create(id, cfg, createTimeout)
		if err != nil {
			return nil, err
		}
		return &v2Container{sys}, nil
	}
	c, err := hcsshim.CreateContainer(id, cfg.(*hcsshim.ContainerConfig))
	if err != nil {
		return nil, fmt.Errorf("CreateContainer: %w", err)
	}
	return &v1Container{c}, nil
}

// openContainer reopens an existing compute system by id through the route
// recorded in state. A state without a route is a pre-v2 container: v1.
func openContainer(s state) (containerIface, error) {
	if s.Route == routeV2 {
		sys, err := vmcompute.Open(s.ID)
		if err != nil {
			return nil, err
		}
		return &v2Container{sys}, nil
	}
	c, err := hcsshim.OpenContainer(s.ID)
	if err != nil {
		return nil, err
	}
	return &v1Container{c}, nil
}

// -- v2 network --------------------------------------------------------------------------

// createNamespace makes an HNS namespace with the endpoint attached -- the v2
// argon attach shape (hcsoci's configureSandboxNetwork). The namespace id goes
// into the document's Networking.Namespace; it is destroyed with the container.
func createNamespace(epID string) (string, error) {
	ns, err := hcn.NewNamespace("").Create()
	if err != nil {
		return "", fmt.Errorf("HNS namespace: %w", err)
	}
	if err := hcn.AddNamespaceEndpoint(ns.Id, epID); err != nil {
		_ = ns.Delete()
		return "", fmt.Errorf("attach endpoint %s to namespace: %w", epID, err)
	}
	return ns.Id, nil
}

func deleteNamespace(id string) error {
	ns, err := hcn.GetNamespaceByID(id)
	if err != nil {
		return fmt.Errorf("GetNamespaceByID(%s): %w", id, err)
	}
	if err := ns.Delete(); err != nil {
		return fmt.Errorf("delete namespace %s: %w", id, err)
	}
	return nil
}
