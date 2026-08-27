//go:build windows

// The two compute-system documents this package produces, both consumed by
// computecore.dll (HcsCreateComputeSystem accepts either).
//
//   - argon: schema 2.1. Storage is the filter-attached scratch volume plus
//     the layer chain; networking is an HNS namespace the endpoint was added
//     to; HostName/Memory/MappedDirectories are in-guest verified.
//   - xenon: schema 1 -- no self-contained v2 xenon document exists (the v2
//     Container schema has no HvRuntime, and the two-system HostedSystem route
//     needs hcsshim's unimportable GCS machinery). The document shape is
//     legacy; every call that carries it is modern.
package container

import (
	"encoding/json"
	"fmt"
)

// layerRef names one read-only layer: the id everything storage-side derived
// via layerid, and the directory path.
type layerRef struct {
	Id   string `json:"Id"`
	Path string `json:"Path"`
}

// mappedDir is a host directory mapped into the guest. Field names are shared
// by the v2 and schema-1 documents.
type mappedDir struct {
	HostPath      string `json:"HostPath"`
	ContainerPath string `json:"ContainerPath"`
	ReadOnly      bool   `json:"ReadOnly"`
}

// docInputs is everything either document builder consumes.
type docInputs struct {
	Layers   []layerRef
	Hostname string
	CPUs     uint64
	MemoryMB uint64
	Mounts   []mappedDir

	// argon
	Volume    string // filter-attached scratch volume, trailing backslash
	Namespace string // HNS namespace the endpoint was added to
	DNSSearch string
	AllowDNS  bool

	// xenon
	ScratchDir string
	UVM        string
	Endpoint   string
	// DNSSearch/AllowDNS apply to the xenon too, via the schema-1 fields.
}

// v2 document types. Only what this tool sets; HCS rejects nothing for
// omission here.
type v2Doc struct {
	SchemaVersion                     v2Version   `json:"SchemaVersion"`
	Owner                             string      `json:"Owner"`
	ShouldTerminateOnLastHandleClosed bool        `json:"ShouldTerminateOnLastHandleClosed"`
	Container                         v2Container `json:"Container"`
}

type v2Version struct {
	Major int `json:"Major"`
	Minor int `json:"Minor"`
}

type v2Container struct {
	GuestOs           *v2GuestOs    `json:"GuestOs,omitempty"`
	Processor         *v2Processor  `json:"Processor,omitempty"`
	Memory            *v2Memory     `json:"Memory,omitempty"`
	Storage           v2Storage     `json:"Storage"`
	MappedDirectories []mappedDir   `json:"MappedDirectories,omitempty"`
	Networking        *v2Networking `json:"Networking,omitempty"`
}

type v2GuestOs struct {
	HostName string `json:"HostName,omitempty"`
}

type v2Processor struct {
	Count uint32 `json:"Count,omitempty"`
}

type v2Memory struct {
	SizeInMB uint64 `json:"SizeInMB,omitempty"`
}

type v2Storage struct {
	Layers []layerRef `json:"Layers"`
	Path   string     `json:"Path"`
}

type v2Networking struct {
	AllowUnqualifiedDnsQuery bool   `json:"AllowUnqualifiedDnsQuery,omitempty"`
	DnsSearchList            string `json:"DnsSearchList,omitempty"`
	Namespace                string `json:"Namespace,omitempty"`
}

// buildArgonDoc assembles the schema-2.1 process-isolated document. The
// volume must be filter-attached with a trailing backslash; the filter attach
// is scratch.Prepare's job -- HCS does not attach it from the document (Start
// fails 0x80070287 without it).
func buildArgonDoc(in docInputs) (string, error) {
	// An empty Layers array crashes the compute service; refuse to marshal one.
	if len(in.Layers) == 0 {
		return "", fmt.Errorf("refusing a document with empty Storage.Layers (crashes the compute service)")
	}
	if in.Volume == "" || in.Volume[len(in.Volume)-1] != '\\' {
		return "", fmt.Errorf("argon Storage.Path %q must be a volume path with a trailing backslash", in.Volume)
	}
	d := v2Doc{
		SchemaVersion: v2Version{Major: 2, Minor: 1},
		Owner:         "hcsctl",
		// False: the container outlives this process and is reopened by id.
		ShouldTerminateOnLastHandleClosed: false,
		Container: v2Container{
			Storage: v2Storage{Layers: in.Layers, Path: in.Volume},
		},
	}
	if in.Hostname != "" {
		d.Container.GuestOs = &v2GuestOs{HostName: in.Hostname}
	}
	if in.CPUs != 0 {
		d.Container.Processor = &v2Processor{Count: uint32(in.CPUs)}
	}
	if in.MemoryMB != 0 {
		d.Container.Memory = &v2Memory{SizeInMB: in.MemoryMB}
	}
	d.Container.MappedDirectories = in.Mounts
	if in.Namespace != "" {
		d.Container.Networking = &v2Networking{
			AllowUnqualifiedDnsQuery: in.AllowDNS,
			DnsSearchList:            in.DNSSearch,
			Namespace:                in.Namespace,
		}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// schema-1 document types, exactly the fields hcsshim's ContainerConfig
// marshals for a xenon. No SchemaVersion field -- its absence is how the
// service tells the schemas apart.
type v1Doc struct {
	SystemType                  string      `json:"SystemType"`
	Name                        string      `json:"Name"`
	Owner                       string      `json:"Owner"`
	LayerFolderPath             string      `json:"LayerFolderPath"`
	Layers                      []v1Layer   `json:"Layers"`
	HvPartition                 bool        `json:"HvPartition"`
	HvRuntime                   v1HvRuntime `json:"HvRuntime"`
	TerminateOnLastHandleClosed bool        `json:"TerminateOnLastHandleClosed"`
	HostName                    string      `json:"HostName,omitempty"`
	ProcessorCount              uint32      `json:"ProcessorCount,omitempty"`
	MemoryMaximumInMB           int64       `json:"MemoryMaximumInMB,omitempty"`
	MappedDirectories           []mappedDir `json:"MappedDirectories,omitempty"`
	EndpointList                []string    `json:"EndpointList,omitempty"`
	AllowUnqualifiedDNSQuery    bool        `json:"AllowUnqualifiedDNSQuery,omitempty"`
	DNSSearchList               string      `json:"DNSSearchList,omitempty"`
}

type v1Layer struct {
	ID   string `json:"ID"`
	Path string `json:"Path"`
}

type v1HvRuntime struct {
	ImagePath string `json:"ImagePath"`
}

// buildXenonDoc assembles the schema-1 hyperv-isolated document: the scratch
// DIRECTORY (the UVM stacks the layers in-guest), the read-only chain, and
// the UtilityVM image path.
func buildXenonDoc(id string, in docInputs) (string, error) {
	if len(in.Layers) == 0 {
		return "", fmt.Errorf("refusing a document with empty Layers (crashes the compute service)")
	}
	layers := make([]v1Layer, len(in.Layers))
	for i, l := range in.Layers {
		layers[i] = v1Layer{ID: l.Id, Path: l.Path}
	}
	d := v1Doc{
		SystemType:      "Container",
		Name:            id,
		Owner:           "hcsctl",
		LayerFolderPath: in.ScratchDir,
		Layers:          layers,
		HvPartition:     true,
		HvRuntime:       v1HvRuntime{ImagePath: in.UVM},
		// False: the container outlives this process and is reopened by id.
		TerminateOnLastHandleClosed: false,
		HostName:                    in.Hostname,
		ProcessorCount:              uint32(in.CPUs),
		MemoryMaximumInMB:           int64(in.MemoryMB),
		MappedDirectories:           in.Mounts,
	}
	if in.Endpoint != "" {
		d.EndpointList = []string{in.Endpoint}
		d.AllowUnqualifiedDNSQuery = in.AllowDNS
		d.DNSSearchList = in.DNSSearch
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// processDoc is the process-parameters document. The field names coincide
// between schema 1 and v2, so one shape serves both isolations.
type processDoc struct {
	CommandLine      string            `json:"CommandLine"`
	WorkingDirectory string            `json:"WorkingDirectory,omitempty"`
	User             string            `json:"User,omitempty"`
	Environment      map[string]string `json:"Environment,omitempty"`
	EmulateConsole   bool              `json:"EmulateConsole,omitempty"`
	ConsoleSize      []uint            `json:"ConsoleSize,omitempty"`
	CreateStdInPipe  bool              `json:"CreateStdInPipe,omitempty"`
	CreateStdOutPipe bool              `json:"CreateStdOutPipe,omitempty"`
	CreateStdErrPipe bool              `json:"CreateStdErrPipe,omitempty"`
}

func buildProcessDoc(cmdline, cwd, user string, env map[string]string, tty bool, consoleSize [2]uint) (string, error) {
	d := processDoc{
		CommandLine:      cmdline,
		WorkingDirectory: cwd,
		User:             user,
		Environment:      env,
		EmulateConsole:   tty,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	}
	if consoleSize != [2]uint{} {
		d.ConsoleSize = []uint{consoleSize[0], consoleSize[1]}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
