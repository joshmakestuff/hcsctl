package guestproto

import (
	"encoding/json"
	"testing"
)

func TestShareRequestBootIDWireField(t *testing.T) {
	for _, value := range []any{Share{}, ShareRef{}} {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["bootId"]; !ok {
			t.Fatalf("missing required bootId in %s", b)
		}
	}
}
