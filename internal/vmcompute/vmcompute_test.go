//go:build windows

package vmcompute

import (
	"testing"
)

func TestAwaitNeeded(t *testing.T) {
	cases := []struct {
		name     string
		hr       uintptr
		wantErr  bool
		wantWait bool
	}{
		{"S_OK success does not wait", 0, false, false},
		{"S_FALSE success does not wait", 1, false, false},
		{"pending waits", 0xC0370103, false, true},
		{"failure returns error and no wait", 0x80070005, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err, wait := awaitNeeded(c.hr, "HcsStartComputeSystem", "")
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if wait != c.wantWait {
				t.Fatalf("wait = %v, want %v", wait, c.wantWait)
			}
			if c.wantErr {
				e, ok := err.(*Error)
				if !ok {
					t.Fatalf("expected *Error, got %T", err)
				}
				if e.Code != uint32(c.hr) {
					t.Fatalf("code = %#x, want %#x", e.Code, uint32(c.hr))
				}
			}
		})
	}
}
