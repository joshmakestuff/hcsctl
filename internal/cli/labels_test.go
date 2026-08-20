package cli

import "testing"

// Labels are opaque. hcsctl stores what it is given, including an empty value.
func TestLabelsAreStoredVerbatim(t *testing.T) {
	got, err := ParseLabels([]string{"owner-pid=8123", "empty=", "url=a=b=c"}, nil)
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
	got, err := ParseLabels(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// A label that shadows a state-document field would win when a consumer flattens the
// document, so it is refused.
func TestReservedKeyIsRefused(t *testing.T) {
	_, err := ParseLabels([]string{"id=nope"}, map[string]bool{"id": true})
	if err == nil {
		t.Fatal("a reserved key was accepted")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("error is %T, want *UsageError so the exit code is 64", err)
	}
}

func TestMalformedLabelsAreUsageErrors(t *testing.T) {
	for _, bad := range []string{"novalue", "=novalue", "bad key=x", "bad/key=x"} {
		if _, err := ParseLabels([]string{bad}, nil); err == nil {
			t.Errorf("--label %q was accepted", bad)
		}
	}
}

func TestRepeatedKeyIsRefused(t *testing.T) {
	if _, err := ParseLabels([]string{"dup=1", "dup=2"}, nil); err == nil {
		t.Error("a repeated key was accepted; the last one would silently win")
	}
}
