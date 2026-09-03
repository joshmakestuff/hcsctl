package files

import "testing"

func TestNewPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := newPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != passwordLength {
			t.Fatalf("length = %d, want %d", len(p), passwordLength)
		}
		if err := validPassword(p); err != nil {
			t.Fatalf("generated password is invalid: %v (%q)", err, p)
		}
		if seen[p] {
			t.Fatalf("duplicate password after %d draws: %q", i, p)
		}
		seen[p] = true
	}
}

func TestValidPassword(t *testing.T) {
	for _, ok := range []string{"abcXYZ012", "aB3", passwordAlphabet} {
		if err := validPassword(ok); err != nil {
			t.Errorf("validPassword(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "a,b", `a"b`, `a\b`, "a;b", "a b", "a\tb", "a\nb"} {
		if err := validPassword(bad); err == nil {
			t.Errorf("validPassword(%q) = nil, want error", bad)
		}
	}
}
