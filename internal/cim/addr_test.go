//go:build windows

package cim

import (
	"errors"
	"testing"

	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

func TestParseSource(t *testing.T) {
	cases := []struct {
		in        string
		wantPath  string
		wantName  string
		wantType  cimfs.BlockCIMType
		wantUsage bool
	}{
		{in: `E:\cims\layer.bcim`, wantPath: `E:\cims\layer.bcim`, wantName: "layer.cim", wantType: cimfs.BlockCIMTypeSingleFile},
		{in: `E:\cims\layer.bcim::other.cim`, wantPath: `E:\cims\layer.bcim`, wantName: "other.cim", wantType: cimfs.BlockCIMTypeSingleFile},
		{in: `E:\cims\layer`, wantPath: `E:\cims\layer`, wantName: "layer.cim", wantType: cimfs.BlockCIMTypeSingleFile},
		{in: `\\.\PhysicalDrive3::boot.cim`, wantPath: `\\.\PhysicalDrive3`, wantName: "boot.cim", wantType: cimfs.BlockCIMTypeDevice},
		{in: `\\.\PhysicalDrive3`, wantUsage: true},   // device path needs an explicit name
		{in: `E:\cims\layer.bcim::`, wantUsage: true}, // empty name after ::
		{in: `::name.cim`, wantUsage: true},           // empty block path
	}
	for _, c := range cases {
		b, err := parseSource(c.in)
		if c.wantUsage {
			var ue *cli.UsageError
			if !errors.As(err, &ue) {
				t.Errorf("parseSource(%q): want usage error, got %v", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSource(%q): %v", c.in, err)
			continue
		}
		if b.BlockPath != c.wantPath || b.CimName != c.wantName || b.Type != c.wantType {
			t.Errorf("parseSource(%q) = {%q %q %d}, want {%q %q %d}",
				c.in, b.BlockPath, b.CimName, b.Type, c.wantPath, c.wantName, c.wantType)
		}
	}
}

func TestParseRootHash(t *testing.T) {
	if _, err := parseRootHash("abcd"); err == nil {
		t.Error("short hash accepted")
	}
	if _, err := parseRootHash("zz" + string(make([]byte, 62))); err == nil {
		t.Error("non-hex accepted")
	}
	h, err := parseRootHash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil || len(h) != 32 {
		t.Errorf("valid hash rejected: %v (len %d)", err, len(h))
	}
}

func TestMountGUIDDeterministicAndCaseInsensitive(t *testing.T) {
	a, err := mountGUID(`E:\cims\base.cim`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mountGUID(`e:\CIMS\Base.CIM`)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("case variants derive different GUIDs: %s vs %s", a, b)
	}
	c, _ := mountGUID(`E:\cims\other.cim`)
	if a == c {
		t.Error("different CIMs derive the same GUID")
	}
}

func TestParseVolumePath(t *testing.T) {
	vol, g, err := parseVolumePath(`\\?\Volume{c24dc139-e45a-5283-b0fc-e9c736ebf6a0}`)
	if err != nil {
		t.Fatalf("trailing-backslash-less form rejected: %v", err)
	}
	if vol != `\\?\Volume{c24dc139-e45a-5283-b0fc-e9c736ebf6a0}\` {
		t.Errorf("volume not normalized: %q", vol)
	}
	if g.String() != "c24dc139-e45a-5283-b0fc-e9c736ebf6a0" {
		t.Errorf("guid: %s", g)
	}
	for _, bad := range []string{`C:\x`, `\\?\Volume{not-a-guid}\`, `\\.\Volume{c24dc139-e45a-5283-b0fc-e9c736ebf6a0}\`} {
		if _, _, err := parseVolumePath(bad); err == nil {
			t.Errorf("parseVolumePath(%q): accepted", bad)
		}
	}
}

func TestStreamName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: `:s:$DATA`, want: "s", ok: true},
		{in: `:Zone.Identifier:$DATA`, want: "Zone.Identifier", ok: true},
		{in: `::$DATA`, ok: false},                // anonymous stream
		{in: `:idx:$INDEX_ALLOCATION`, ok: false}, // non-$DATA type
		{in: `noleadingcolon`, ok: false},
	}
	for _, c := range cases {
		got, ok := streamName(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("streamName(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
