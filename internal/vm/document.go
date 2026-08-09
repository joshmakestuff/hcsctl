//go:build windows

package vm

// The HCS v2 schema, subset. Property names are the JSON keys -- HCS documents are PascalCase,
// so nothing is renamed by a policy. Reference: the schema reference on Microsoft Learn, plus
// hcsshim's internal/hcs/schema2, which is not importable.
//
// Schema version 2.5 is deliberate, not "the newest number". Services is NewInVersion 2.5, and
// below that HCS *silently ignores* the section -- the document is accepted and a later
// shutdown then fails ERROR_NOT_SUPPORTED (0x80070032), blaming the shutdown.

type document struct {
	SchemaVersion schemaVersion `json:"SchemaVersion"`
	Owner         string        `json:"Owner,omitempty"`

	// Left false on purpose, unlike a container. hcsctl is a CLI: the process that created the
	// VM exits immediately, and with this true the VM would die with it. A VM outliving the
	// invocation that made it is the whole point of `vm create` being separate from `vm start`.
	ShouldTerminateOnLastHandleClosed bool `json:"ShouldTerminateOnLastHandleClosed"`

	VirtualMachine virtualMachine `json:"VirtualMachine"`
}

type schemaVersion struct {
	Major uint32 `json:"Major"`
	Minor uint32 `json:"Minor"`
}

type virtualMachine struct {
	Chipset         chipset         `json:"Chipset"`
	ComputeTopology computeTopology `json:"ComputeTopology"`
	Devices         devices         `json:"Devices"`
	Services        *services       `json:"Services,omitempty"`
}

type chipset struct {
	Uefi *uefi `json:"Uefi,omitempty"`
}

type uefi struct {
	BootThis *uefiBootEntry `json:"BootThis,omitempty"`
}

type uefiBootEntry struct {
	DevicePath string `json:"DevicePath"`
	DiskNumber uint32 `json:"DiskNumber"`
	DeviceType string `json:"DeviceType"`
}

type computeTopology struct {
	Memory    vmMemory    `json:"Memory"`
	Processor vmProcessor `json:"Processor"`
}

type vmMemory struct {
	Backing  string `json:"Backing"`
	SizeInMB uint64 `json:"SizeInMB"`
}

type vmProcessor struct {
	Count uint64 `json:"Count"`
}

type devices struct {
	Scsi            map[string]scsiController `json:"Scsi,omitempty"`
	ComPorts        map[string]comPort        `json:"ComPorts,omitempty"`
	HvSocket        *hvSocket                 `json:"HvSocket,omitempty"`
	NetworkAdapters map[string]networkAdapter `json:"NetworkAdapters,omitempty"`
}

// networkAdapter names an HCN endpoint that already exists. HCS does not create it and does not
// delete it: the endpoint is host-global, made before the compute system and removed after it.
type networkAdapter struct {
	EndpointId string `json:"EndpointId"`
	MacAddress string `json:"MacAddress"`
}

// networkAdapter0 is the key of the one adapter. Unlike the SCSI controller's key it is not
// referenced from anywhere else in the document, so it is a label and nothing more.
const networkAdapter0 = "ext"

type hvSocket struct {
	HvSocketConfig hvSocketSystemConfig `json:"HvSocketConfig"`
}

type hvSocketSystemConfig struct {
	DefaultBindSecurityDescriptor    string `json:"DefaultBindSecurityDescriptor,omitempty"`
	DefaultConnectSecurityDescriptor string `json:"DefaultConnectSecurityDescriptor,omitempty"`
	// Empty: no per-service entry, so every service falls back to the two defaults above.
	// A service table would be the place to restrict individual service GUIDs, and nothing
	// here wants that yet.
	ServiceTable map[string]struct{} `json:"ServiceTable"`
}

// hvSocketSDDL grants full access to SYSTEM, BUILTIN\Administrators and Hyper-V Administrators
// (S-1-5-32-578).
//
// The Hyper-V Administrators entry is the load-bearing one. hcsctl's whole posture is that an
// unelevated member of that group can drive HCS, and in a filtered token the Administrators
// SID is present but not enabled -- so an SDDL naming only SY and BA locks out exactly the
// caller this tool is built for.
const hvSocketSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-32-578)"

// scsiController0 is the key of the one SCSI controller, and the same string has to appear as
// the UEFI boot entry's DevicePath. It reads like a label because it is one; the key is
// arbitrary, and only the agreement between the two places matters.
const scsiController0 = "Primary disk"

type scsiController struct {
	Attachments map[string]attachment `json:"Attachments"`
}

type attachment struct {
	Type string `json:"Type"`
	Path string `json:"Path"`
}

type comPort struct {
	NamedPipe string `json:"NamedPipe"`
}

type services struct {
	// Serialized as an empty object -- the schema wants the key present, nothing in it.
	Shutdown *struct{} `json:"Shutdown"`
}

// buildDocument assembles the boot document. Every field it sets is one this tool can
// actually drive; nothing is set speculatively.
func buildDocument(spec spec) document {
	d := document{
		SchemaVersion: schemaVersion{Major: 2, Minor: 5},
		Owner:         "hcsctl",
		VirtualMachine: virtualMachine{
			Chipset: chipset{Uefi: &uefi{BootThis: &uefiBootEntry{
				// DevicePath is NOT a file path. It is the key of the SCSI controller in
				// Devices.Scsi below, and DiskNumber is the attachment LUN on it. The two
				// must agree, and nothing checks that they do: a document naming a
				// controller that does not exist -- or an EFI file path, which is the
				// tempting mistake -- is accepted, the VM starts, HCS reports Running, and
				// the firmware boots nothing. No disk writes, no console output, no error
				// anywhere. Measured on both images, #34.
				DevicePath: scsiController0,
				DiskNumber: 0,
				DeviceType: "ScsiDrive",
			}}},
			ComputeTopology: computeTopology{
				Memory:    vmMemory{Backing: "Virtual", SizeInMB: spec.MemoryMB},
				Processor: vmProcessor{Count: spec.CPUs},
			},
			Devices: devices{
				Scsi: map[string]scsiController{
					scsiController0: {Attachments: map[string]attachment{
						"0": {Type: "VirtualDisk", Path: spec.DiskPath},
					}},
				},
				// Without this section the VM has no Hyper-V socket surface at all, and a
				// host-side dial fails WSAEADDRNOTAVAIL (10049) -- the same errno a VM that
				// does not exist produces. Measured, #34 and #37.
				HvSocket: &hvSocket{HvSocketConfig: hvSocketSystemConfig{
					DefaultBindSecurityDescriptor:    hvSocketSDDL,
					DefaultConnectSecurityDescriptor: hvSocketSDDL,
					ServiceTable:                     map[string]struct{}{},
				}},
			},
			Services: &services{Shutdown: &struct{}{}},
		},
	}
	if spec.SerialPipe != "" {
		d.VirtualMachine.Devices.ComPorts = map[string]comPort{"0": {NamedPipe: spec.SerialPipe}}
	}
	if spec.EndpointID != "" {
		d.VirtualMachine.Devices.NetworkAdapters = map[string]networkAdapter{
			networkAdapter0: {EndpointId: spec.EndpointID, MacAddress: spec.MacAddress},
		}
	}
	return d
}
