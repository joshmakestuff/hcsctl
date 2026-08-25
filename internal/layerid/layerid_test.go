//go:build windows

package layerid

import (
	"regexp"
	"testing"
)

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestForIsDeterministicV5(t *testing.T) {
	a, b := For("abc123"), For("abc123")
	if a != b {
		t.Errorf("same key, different ids: %s vs %s", a, b)
	}
	if !guidRe.MatchString(a) {
		t.Errorf("%s is not a lowercase v5 RFC-4122 GUID", a)
	}
}

func TestForCaseFolds(t *testing.T) {
	if For("Layer-ABC") != For("layer-abc") {
		t.Error("NTFS-equal keys forked ids")
	}
}

func TestForDistinctKeysDiffer(t *testing.T) {
	if For("layer-a") == For("layer-b") {
		t.Error("distinct keys collided")
	}
}

func TestForPathKeysOnBaseName(t *testing.T) {
	a, err := ForPath(`C:\store\layers\deadbeef`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ForPath(`E:\elsewhere\deadbeef\`)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("same base name, different ids -- trailing slash or location leaked into the key")
	}
}

func TestForPathVolumeKeepsVolumeGUID(t *testing.T) {
	id, err := ForPath(`\\?\Volume{cec3b983-edb0-4542-bfb5-b814636f313a}\`)
	if err != nil {
		t.Fatal(err)
	}
	if id != "cec3b983-edb0-4542-bfb5-b814636f313a" {
		t.Errorf("volume layer id %s is not the volume GUID", id)
	}
}

func TestDataForIsTopmostFirstSchema21(t *testing.T) {
	data, err := DataFor([]string{`C:\l\top`, `C:\l\base`})
	if err != nil {
		t.Fatal(err)
	}
	if data.SchemaVersion.Major != 2 || data.SchemaVersion.Minor != 1 {
		t.Errorf("schema %d.%d", data.SchemaVersion.Major, data.SchemaVersion.Minor)
	}
	if len(data.Layers) != 2 || data.Layers[0].Path != `C:\l\top` {
		t.Errorf("order not preserved: %+v", data.Layers)
	}
	for _, l := range data.Layers {
		if l.PathType != "AbsolutePath" || l.Id == "" {
			t.Errorf("layer %+v", l)
		}
	}
}

func TestDataForEmptyIsBase(t *testing.T) {
	data, err := DataFor(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Layers) != 0 {
		t.Errorf("base LayerData has layers: %+v", data.Layers)
	}
}
