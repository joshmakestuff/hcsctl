//go:build windows

// Failure paths that isolate without HCS (#24). Everything here is filesystem and parsing;
// nothing opens a compute system. The smoke harness (tools/Run-Smoke.ps1) owns the rest.
package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/store"
)

func TestLocateUVM(t *testing.T) {
	mk := func(t *testing.T, withUVM ...bool) []string {
		var chain []string
		for _, u := range withUVM {
			d := t.TempDir()
			if u {
				if err := os.Mkdir(filepath.Join(d, "UtilityVM"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			chain = append(chain, d)
		}
		return chain
	}

	t.Run("no layer carries a UtilityVM", func(t *testing.T) {
		_, err := locateUVM(mk(t, false, false))
		if err == nil || !strings.Contains(err.Error(), "UtilityVM") {
			t.Fatalf("want an error naming UtilityVM, got %v", err)
		}
	})
	t.Run("uppermost UtilityVM wins", func(t *testing.T) {
		chain := mk(t, true, true) // topmost first; both carry one
		got, err := locateUVM(chain)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(chain[0], "UtilityVM"); got != want {
			t.Fatalf("got %s, want the topmost %s", got, want)
		}
	})
}

func TestChainFor(t *testing.T) {
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	newStore := func(t *testing.T) *store.Store {
		st, err := store.New(filepath.Join(t.TempDir(), "s"))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	materialize := func(t *testing.T, st *store.Store, diffID string) {
		if err := os.MkdirAll(filepath.Join(st.LayerPath(diffID), "Files"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("no record is a usage error", func(t *testing.T) {
		_, err := chainFor(newStore(t), "never/pulled:it")
		if _, ok := err.(*cli.UsageError); !ok || !strings.Contains(err.Error(), "pull") {
			t.Fatalf("want a usage error pointing at pull, got %v", err)
		}
	})
	t.Run("unmaterialized layer is a usage error naming import", func(t *testing.T) {
		st := newStore(t)
		if err := st.WriteRecord("r:x", store.Record{Ref: "r:x", LayerDigests: []string{d1}, DiffIDs: []string{d1}}); err != nil {
			t.Fatal(err)
		}
		_, err := chainFor(st, "r:x")
		if _, ok := err.(*cli.UsageError); !ok || !strings.Contains(err.Error(), "import") {
			t.Fatalf("want a usage error pointing at import, got %v", err)
		}
	})
	t.Run("chain is topmost first (record order reversed)", func(t *testing.T) {
		st := newStore(t)
		// pull writes base first; every wclayer call wants topmost first.
		if err := st.WriteRecord("r:x", store.Record{Ref: "r:x", LayerDigests: []string{d1, d2}, DiffIDs: []string{d1, d2}}); err != nil {
			t.Fatal(err)
		}
		materialize(t, st, d1)
		materialize(t, st, d2)
		chain, err := chainFor(st, "r:x")
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) != 2 || chain[0] != st.LayerPath(d2) || chain[1] != st.LayerPath(d1) {
			t.Fatalf("chain %v is not topmost-first for record order [d1, d2]", chain)
		}
	})
}

func TestParseMounts(t *testing.T) {
	host := t.TempDir() // drive-letter absolute, exists
	parse := func(t *testing.T, specs ...string) ([]string, error) {
		var argv []string
		for _, s := range specs {
			argv = append(argv, "--mount", s)
		}
		a, err := cli.Parse(argv)
		if err != nil {
			t.Fatal(err)
		}
		m, err := parseMounts(a)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, d := range m {
			ro := ""
			if d.ReadOnly {
				ro = ":ro"
			}
			out = append(out, d.HostPath+"->"+d.ContainerPath+ro)
		}
		return out, nil
	}

	t.Run("read-write default and ro suffix", func(t *testing.T) {
		got, err := parse(t, host+`:C:\app`, host+`:C:\cfg:ro`)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != host+`->C:\app` || got[1] != host+`->C:\cfg:ro` {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("relative host is rejected", func(t *testing.T) {
		if _, err := parse(t, `relative\p:C:\app`); err == nil {
			t.Fatal("relative host path accepted")
		}
	})
}

func TestParsePublishedPorts(t *testing.T) {
	parse := func(t *testing.T, specs ...string) ([]publishedPort, error) {
		t.Helper()
		var argv []string
		for _, s := range specs {
			argv = append(argv, "--publish", s)
		}
		a, err := cli.Parse(argv)
		if err != nil {
			t.Fatal(err)
		}
		return parsePublishedPorts(a)
	}

	t.Run("multiple protocols and ports", func(t *testing.T) {
		got, err := parse(t, "39082:8082/tcp", "39083:8082/udp")
		if err != nil {
			t.Fatal(err)
		}
		want := []publishedPort{{Protocol: "tcp", HostPort: 39082, ContainerPort: 8082}, {Protocol: "udp", HostPort: 39083, ContainerPort: 8082}}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	for _, spec := range []string{"39082:8082", "39082:8082/TCP", "0:8082/tcp", "39082:65536/tcp", "x:8082/tcp", "39082:8082/sctp"} {
		t.Run("reject "+spec, func(t *testing.T) {
			if _, err := parse(t, spec); err == nil {
				t.Fatalf("accepted %q", spec)
			}
		})
	}

	t.Run("same protocol and host port is rejected", func(t *testing.T) {
		if _, err := parse(t, "39082:8082/tcp", "39082:8083/tcp"); err == nil {
			t.Fatal("duplicate TCP host port accepted")
		}
	})
	t.Run("same host port across protocols is valid", func(t *testing.T) {
		if _, err := parse(t, "39082:8082/tcp", "39082:8082/udp"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestValidatePublishNetwork(t *testing.T) {
	published := []publishedPort{{Protocol: "tcp", HostPort: 39082, ContainerPort: 8082}}
	if err := validatePublishNetwork(nil, nil); err != nil {
		t.Fatalf("no publish: %v", err)
	}
	if err := validatePublishNetwork(published, nil); err == nil || !strings.Contains(err.Error(), "--network") {
		t.Fatalf("nil network error = %v", err)
	}
	if err := validatePublishNetwork(published, &hcn.HostComputeNetwork{Name: "private", Type: hcn.Private}); err == nil || !strings.Contains(err.Error(), "NAT") {
		t.Fatalf("private network error = %v", err)
	}
	if err := validatePublishNetwork(published, &hcn.HostComputeNetwork{Name: "nat", Type: hcn.NAT}); err != nil {
		t.Fatalf("NAT network: %v", err)
	}
}

func TestParseACL(t *testing.T) {
	parse := func(t *testing.T, specs ...string) ([]aclRule, error) {
		t.Helper()
		var argv []string
		for _, s := range specs {
			argv = append(argv, "--acl", s)
		}
		a, err := cli.Parse(argv)
		if err != nil {
			t.Fatal(err)
		}
		return parseACLs(a)
	}

	t.Run("direction action and protocol", func(t *testing.T) {
		got, err := parse(t, "in:block:tcp", "out:allow:udp")
		if err != nil {
			t.Fatal(err)
		}
		want := []aclRule{
			{Direction: hcn.DirectionTypeIn, Action: hcn.ActionTypeBlock, Protocol: "tcp"},
			{Direction: hcn.DirectionTypeOut, Action: hcn.ActionTypeAllow, Protocol: "udp"},
		}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("empty protocol means all", func(t *testing.T) {
		got, err := parse(t, "in:block")
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Protocol != "" {
			t.Fatalf("protocol = %q, want empty", got[0].Protocol)
		}
	})

	for _, spec := range []string{"in", "in:block:tcp:extra", "sideways:block:tcp", "in:deny:tcp", "in:block:sctp"} {
		t.Run("reject "+spec, func(t *testing.T) {
			if _, err := parse(t, spec); err == nil {
				t.Fatalf("accepted %q", spec)
			}
		})
	}

	t.Run("duplicate is rejected", func(t *testing.T) {
		if _, err := parse(t, "in:block:tcp", "in:block:tcp"); err == nil {
			t.Fatal("duplicate ACL accepted")
		}
	})
}

func TestValidateACLNetwork(t *testing.T) {
	acls := []aclRule{{Direction: hcn.DirectionTypeIn, Action: hcn.ActionTypeBlock, Protocol: "tcp"}}
	if err := validateACLNetwork(nil, nil); err != nil {
		t.Fatalf("no ACL: %v", err)
	}
	if err := validateACLNetwork(acls, nil); err == nil || !strings.Contains(err.Error(), "--network") {
		t.Fatalf("nil network error = %v", err)
	}
	if err := validateACLNetwork(acls, &hcn.HostComputeNetwork{Name: "nat", Type: hcn.NAT}); err != nil {
		t.Fatalf("NAT network: %v", err)
	}
}

func TestParseEnvKeepsValueAfterFirstEquals(t *testing.T) {
	a, err := cli.Parse([]string{"--env", "CONN=Server=x;Db=y"})
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnv(a)
	if err != nil {
		t.Fatal(err)
	}
	if env["CONN"] != "Server=x;Db=y" {
		t.Fatalf("value mangled: %q", env["CONN"])
	}
}
