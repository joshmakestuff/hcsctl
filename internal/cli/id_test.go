package cli

import "testing"

func TestValidateID(t *testing.T) {
	valid := []string{
		"a",
		"smoke1",
		"mcr.microsoft.com_windows_servercore_ltsc2022", // what idFor derives
		"x-y_z.1",
		".hidden",
		"CON2",  // not a reserved name
		"COM10", // reserved stops at 9
	}
	for _, id := range valid {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []struct {
		name, id string
	}{
		{"empty", ""},
		{"dot", "."},
		{"dotdot", ".."},
		{"traversal backslash", `..\..\x`},
		{"traversal slash", "../x"},
		{"rooted drive", `C:\evil`},
		{"drive relative", "C:evil"},
		{"unc", `\\host\share`},
		{"backslash separator", `a\b`},
		{"slash separator", "a/b"},
		{"colon stream", "a:stream"},
		{"wildcard star", "a*b"},
		{"wildcard question", "a?b"},
		{"quote", `a"b`},
		{"angle open", "a<b"},
		{"angle close", "a>b"},
		{"pipe", "a|b"},
		{"control char", "a\x00b"},
		{"delete char", "a\x7fb"},
		{"trailing dot", "a."},
		{"trailing space", "a "},
		{"leading space", " a"},
		{"reserved lower", "con"},
		{"reserved upper", "NUL"},
		{"reserved with extension", "Nul.txt"},
		{"reserved com", "COM7"},
		{"reserved lpt", "lpt9"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateID(tc.id)
			if err == nil {
				t.Fatalf("ValidateID(%q) = nil, want error", tc.id)
			}
			if _, ok := err.(*UsageError); !ok {
				t.Fatalf("ValidateID(%q) = %T, want *UsageError", tc.id, err)
			}
		})
	}
}
