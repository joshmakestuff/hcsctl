package main

import (
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func validMount() *guestproto.Mount {
	return &guestproto.Mount{
		UNC:  `\\192.168.77.1\hcsctl-files\vm\data-0`,
		Path: "/mnt/data",
		User: "hcsctl-files",
	}
}

func TestValidateMount(t *testing.T) {
	if err := validateMount(validMount()); err != nil {
		t.Fatalf("valid mount rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*guestproto.Mount)
		want string
	}{
		{"empty unc", func(m *guestproto.Mount) { m.UNC = "" }, "must start with"},
		{"forward slashes", func(m *guestproto.Mount) { m.UNC = "//host/share" }, "must start with"},
		{"host only", func(m *guestproto.Mount) { m.UNC = `\\host` }, "host and a share"},
		{"empty share", func(m *guestproto.Mount) { m.UNC = `\\host\` }, "host and a share"},
		{"empty path", func(m *guestproto.Mount) { m.Path = "" }, "guest path"},
		{"empty user", func(m *guestproto.Mount) { m.User = "" }, "a user"},
		{"comma in password", func(m *guestproto.Mount) { m.Password = "a,b" }, "comma"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validMount()
			tc.mut(m)
			err := validateMount(m)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	t.Run("nil payload", func(t *testing.T) {
		if err := validateMount(nil); err == nil || !strings.Contains(err.Error(), "payload") {
			t.Fatalf("nil payload: %v", err)
		}
	})
}

func TestValidateUnmount(t *testing.T) {
	if err := validateUnmount(&guestproto.Unmount{Path: "/mnt/data"}); err != nil {
		t.Fatalf("valid unmount rejected: %v", err)
	}
	if err := validateUnmount(&guestproto.Unmount{}); err == nil {
		t.Fatal("empty path accepted")
	}
	if err := validateUnmount(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

func TestCifsSource(t *testing.T) {
	got := cifsSource(`\\192.168.77.1\hcsctl-files\vm\data-0`)
	want := "//192.168.77.1/hcsctl-files/vm/data-0"
	if got != want {
		t.Fatalf("cifsSource = %q, want %q", got, want)
	}
}

func TestShareRoot(t *testing.T) {
	got := shareRoot(`\\192.168.77.1\hcsctl-files\vm\data-0`)
	want := `\\192.168.77.1\hcsctl-files`
	if got != want {
		t.Fatalf("shareRoot = %q, want %q", got, want)
	}
	// A UNC that is already just the root is returned unchanged.
	if got := shareRoot(`\\host\share`); got != `\\host\share` {
		t.Fatalf("shareRoot(root) = %q", got)
	}
}

func TestCifsOptions(t *testing.T) {
	// ReadOnly is a mount flag, not an option; it must never appear here.
	m := &guestproto.Mount{User: "u", Password: "p", ReadOnly: true}
	got := cifsOptions(m)
	want := "vers=3.1.1,username=u,password=p,file_mode=0644,dir_mode=0755"
	if got != want {
		t.Fatalf("cifsOptions = %q, want %q", got, want)
	}
	if strings.Contains(got, "ro") && strings.Contains(got, ",ro") {
		t.Fatalf("read-only leaked into options: %q", got)
	}

	// uid/gid appear only when non-zero.
	withIDs := cifsOptions(&guestproto.Mount{User: "u", Password: "p", UID: 1000, GID: 1000})
	if !strings.Contains(withIDs, "uid=1000") || !strings.Contains(withIDs, "gid=1000") {
		t.Fatalf("uid/gid missing: %q", withIDs)
	}
	if strings.Contains(got, "uid=") || strings.Contains(got, "gid=") {
		t.Fatalf("uid/gid present when zero: %q", got)
	}
}
