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
// HCS reports Running, and the firmware boots nothing at all. That failure cost an afternoon
// and is invisible in every observable except an idle disk, so it is asserted here.
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
