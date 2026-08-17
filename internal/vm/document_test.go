//go:build windows

package vm

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func testSpec() spec {
	return spec{DiskPath: `E:\vms\x\disk.vhdx`, CPUs: 2, MemoryMB: 2048}
}

// The boot entry points at a SCSI controller by key, not at a file. Nothing validates the
// agreement -- a document naming a controller that does not exist is accepted, the VM starts,
// HCS reports Running, and the firmware boots nothing at all. The failure is invisible in
// every observable except an idle disk.
func TestBootEntryNamesAnAttachedDisk(t *testing.T) {
	d := buildDocument(testSpec())

	boot := d.VirtualMachine.Chipset.Uefi.BootThis
	if boot == nil {
		t.Fatal("no UEFI boot entry")
	}
	controller, ok := d.VirtualMachine.Devices.Scsi[boot.DevicePath]
	if !ok {
		t.Fatalf("BootThis.DevicePath %q names no SCSI controller; controllers are %v",
			boot.DevicePath, keys(d.VirtualMachine.Devices.Scsi))
	}
	lun := strconv.FormatUint(uint64(boot.DiskNumber), 10)
	attached, ok := controller.Attachments[lun]
	if !ok {
		t.Fatalf("BootThis.DiskNumber %s names no attachment on %q", lun, boot.DevicePath)
	}
	if attached.Path != testSpec().DiskPath {
		t.Errorf("boot attachment is %q, want the spec's disk %q", attached.Path, testSpec().DiskPath)
	}
}

// Services is NewInVersion 2.5. Below that HCS ignores the section silently and a later
// shutdown fails ERROR_NOT_SUPPORTED, blaming the shutdown rather than the document.
func TestSchemaVersionSupportsServices(t *testing.T) {
	d := buildDocument(testSpec())
	if d.VirtualMachine.Services == nil {
		t.Fatal("no Services section, so vm stop has nothing to ask")
	}
	v := d.SchemaVersion
	if v.Major < 2 || (v.Major == 2 && v.Minor < 5) {
		t.Errorf("schema %d.%d is below 2.5, where Services is silently ignored", v.Major, v.Minor)
	}
}

// Without an HvSocket section the VM has no Hyper-V socket surface, and a host dial fails
// with the same errno a nonexistent VM produces. The SDDL must name Hyper-V Administrators:
// hcsctl's posture is an unelevated caller, whose Administrators SID is present but disabled.
func TestHvSocketIsConfiguredForAnUnelevatedCaller(t *testing.T) {
	d := buildDocument(testSpec())
	hs := d.VirtualMachine.Devices.HvSocket
	if hs == nil {
		t.Fatal("no HvSocket section, so no guest agent can be reached")
	}
	for name, sddl := range map[string]string{
		"connect": hs.HvSocketConfig.DefaultConnectSecurityDescriptor,
		"bind":    hs.HvSocketConfig.DefaultBindSecurityDescriptor,
	} {
		if !contains(sddl, "S-1-5-32-578") {
			t.Errorf("default %s descriptor %q does not admit Hyper-V Administrators", name, sddl)
		}
	}
}

// Shutdown must serialize as an empty object, not as null: the schema wants the key present
// with nothing in it.
func TestShutdownServiceSerializesAsAnEmptyObject(t *testing.T) {
	b, err := json.Marshal(buildDocument(testSpec()))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"Shutdown":{}`) {
		t.Errorf("Shutdown is not an empty object in:\n%s", b)
	}
}

func keys(m map[string]scsiController) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// A VM with no --network has no NetworkAdapters key at all; the section is omitempty. An empty
// map would be a different document.
func TestNoNetworkAdapterWithoutAnEndpoint(t *testing.T) {
	d := buildDocument(testSpec())
	if d.VirtualMachine.Devices.NetworkAdapters != nil {
		t.Errorf("a VM with no endpoint has NetworkAdapters %v", d.VirtualMachine.Devices.NetworkAdapters)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(b), "NetworkAdapters") {
		t.Errorf("NetworkAdapters is present in a document with no endpoint:\n%s", b)
	}
}

// The adapter names an endpoint that already exists. HCS neither creates nor deletes it, so
// both fields have to reach the document -- a missing MacAddress lets the platform pick its
// own, which moves the DHCP lease off the address the endpoint was made with.
func TestNetworkAdapterCarriesTheEndpointAndMac(t *testing.T) {
	s := testSpec()
	s.EndpointID = "11111111-2222-3333-4444-555555555555"
	s.MacAddress = "02-15-5D-01-02-03"

	adapters := buildDocument(s).VirtualMachine.Devices.NetworkAdapters
	if len(adapters) != 1 {
		t.Fatalf("want exactly one adapter, got %d: %v", len(adapters), adapters)
	}
	nic, ok := adapters[networkAdapter0]
	if !ok {
		t.Fatalf("no adapter under %q; adapters are %v", networkAdapter0, adapters)
	}
	if nic.EndpointId != s.EndpointID {
		t.Errorf("adapter EndpointId is %q, want %q", nic.EndpointId, s.EndpointID)
	}
	if nic.MacAddress != s.MacAddress {
		t.Errorf("adapter MacAddress is %q, want %q", nic.MacAddress, s.MacAddress)
	}
}

// The MAC lives in the store record and is rebuilt into the document on every boot, so a
// stop/start cycle presents the same address to the DHCP server and keeps the same lease.
func TestSpecForCarriesTheEndpointFromTheRecord(t *testing.T) {
	record := state{
		DiskPath: `E:\vms\x\disk.vhdx`, CPUs: 2, MemoryMB: 2048,
		EndpointID: "11111111-2222-3333-4444-555555555555", MacAddress: "02-15-5D-01-02-03",
	}
	s := specFor(record)
	if s.EndpointID != record.EndpointID || s.MacAddress != record.MacAddress {
		t.Errorf("specFor dropped the endpoint: %+v", s)
	}
}
