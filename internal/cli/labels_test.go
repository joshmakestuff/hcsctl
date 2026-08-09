package cli

import "testing"

func parse(t *testing.T, argv ...string) *Args {
	t.Helper()
	a, err := Parse(argv)
	if err != nil {
		t.Fatalf("Parse(%v): %v", argv, err)
	}
	return a
}

// Labels are opaque. hcsctl stores what it is given, including an empty value, because a
// consumer's ownership scheme is not this tool's business (#31, #44).
func TestLabelsAreStoredVerbatim(t *testing.T) {
	a := parse(t, "--label", "owner-pid=8123", "--label", "empty=", "--label", "url=a=b=c")
	got, err := ParseLabels(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"owner-pid": "8123", "empty": "", "url": "a=b=c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %q is %q, want %q", k, got[k], v)
		}
	}
}

// No labels is nil rather than an empty map, so the state document omits the key entirely.
func TestNoLabelsIsNil(t *testing.T) {
	got, err := ParseLabels(parse(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// A label that shadows a state-document field would silently win when a consumer flattens the
// document, so it is refused rather than accepted and hidden.
func TestReservedKeyIsRefused(t *testing.T) {
	_, err := ParseLabels(parse(t, "--label", "id=nope"), map[string]bool{"id": true})
	if err == nil {
		t.Fatal("a reserved key was accepted")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("error is %T, want *UsageError so the exit code is 64", err)
	}
}

func TestMalformedLabelsAreUsageErrors(t *testing.T) {
	for _, bad := range []string{"novalue", "=novalue", "bad key=x", "bad/key=x"} {
		if _, err := ParseLabels(parse(t, "--label", bad), nil); err == nil {
			t.Errorf("--label %q was accepted", bad)
		}
	}
}

func TestRepeatedKeyIsRefused(t *testing.T) {
	a := parse(t, "--label", "dup=1", "--label", "dup=2")
	if _, err := ParseLabels(a, nil); err == nil {
		t.Error("a repeated key was accepted; the last one would silently win")
	}
}
