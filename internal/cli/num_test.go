package cli

import (
	"math"
	"testing"
)

func TestParseUint(t *testing.T) {
	ok := []struct {
		name string
		s    string
		max  uint64
		want uint64
	}{
		{"one", "1", math.MaxUint64, 1},
		{"uint64 max", "18446744073709551615", math.MaxUint64, math.MaxUint64},
		{"uint32 boundary", "4294967295", math.MaxUint32, math.MaxUint32},
		{"int64 boundary", "9223372036854775807", math.MaxInt64, math.MaxInt64},
		{"int32 boundary", "2147483647", math.MaxInt32, math.MaxInt32},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			n, err := ParseUint(tc.s, tc.max)
			if err != nil || n != tc.want {
				t.Fatalf("ParseUint(%q, %d) = %d, %v; want %d, nil", tc.s, tc.max, n, err, tc.want)
			}
		})
	}

	bad := []struct {
		name string
		s    string
		max  uint64
	}{
		{"uint64 overflow", "18446744073709551616", math.MaxUint64},
		{"uint64 overflow plus one", "18446744073709551617", math.MaxUint64},
		{"above uint32", "4294967296", math.MaxUint32},
		{"above int64", "9223372036854775808", math.MaxInt64},
		{"above int32", "2147483648", math.MaxInt32},
		{"zero", "0", math.MaxUint64},
		{"empty", "", math.MaxUint64},
		{"negative", "-1", math.MaxUint64},
		{"plus sign", "+1", math.MaxUint64},
		{"decimal", "1.5", math.MaxUint64},
		{"not a number", "two", math.MaxUint64},
		{"leading space", " 1", math.MaxUint64},
		{"hex", "0x10", math.MaxUint64},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if n, err := ParseUint(tc.s, tc.max); err == nil {
				t.Fatalf("ParseUint(%q, %d) = %d, nil; want error", tc.s, tc.max, n)
			}
		})
	}
}

func TestParseSizeBounds(t *testing.T) {
	ok := []struct {
		s    string
		want uint64
	}{
		{"65536GB", 64 << 40}, // the VHDX ceiling exactly
		{"67108864MB", 64 << 40},
		{"40GB", 40 << 30},
	}
	for _, tc := range ok {
		n, err := ParseSize(tc.s)
		if err != nil || n != tc.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d, nil", tc.s, n, err, tc.want)
		}
	}

	bad := []string{
		"65537GB",    // one above the ceiling in GB
		"67108865MB", // one above the ceiling in MB
		"18446744073709551616GB",
		"99999999999999999999GB",
	}
	for _, s := range bad {
		if n, err := ParseSize(s); err == nil {
			t.Errorf("ParseSize(%q) = %d, nil; want error", s, n)
		} else if _, isUsage := err.(*UsageError); !isUsage {
			t.Errorf("ParseSize(%q) error is %T, want *UsageError", s, err)
		}
	}
}
