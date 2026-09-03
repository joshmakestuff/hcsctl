package files

import (
	"strings"
	"testing"
)

func TestSharePermissionSDDL(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1010"
	if got, want := sharePermissionSDDL(sid, true), "D:(A;;0x1F01FF;;;"+sid+")"; got != want {
		t.Errorf("full = %q, want %q", got, want)
	}
	if got, want := sharePermissionSDDL(sid, false), "D:(A;;0x1200A9;;;"+sid+")"; got != want {
		t.Errorf("read = %q, want %q", got, want)
	}
}

func TestRootDirectorySDDL(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1010"
	got := rootDirectorySDDL(sid)
	for _, want := range []string{
		"D:PAI",
		"(A;OICI;FA;;;SY)",
		"(A;OICI;FA;;;BA)",
		"(A;OICIIO;FA;;;CO)",
		"(A;CI;0x1200AD;;;AU)",
		"(A;OICI;0x1200A9;;;" + sid + ")",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("root DACL %q missing %q", got, want)
		}
	}
}
