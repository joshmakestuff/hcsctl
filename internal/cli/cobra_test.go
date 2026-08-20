package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// plantArgv substitutes the raw command line optionShaped scans, restoring it on cleanup.
func plantArgv(t *testing.T, args ...string) {
	t.Helper()
	old := argv
	argv = func() []string { return args }
	t.Cleanup(func() { argv = old })
}

func TestStringOnceAcceptsEqualsSpelledOptionValue(t *testing.T) {
	plantArgv(t, "guest", "exec", "--cmd=--help")
	var cmd string
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	StringOnce(fs, &cmd, "cmd", "")
	if err := fs.Parse([]string{"--cmd=--help"}); err != nil {
		t.Fatalf("= spelling rejected: %v", err)
	}
	if cmd != "--help" {
		t.Fatalf("value = %q, want --help", cmd)
	}
}

func TestStringOnceRejectsSpaceFormOptionValue(t *testing.T) {
	plantArgv(t, "guest", "exec", "--cmd", "--help")
	var cmd string
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.Usage = func() {}
	StringOnce(fs, &cmd, "cmd", "")
	err := fs.Parse([]string{"--cmd", "--help"})
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("space form accepted an option-shaped value: %v", err)
	}
}

func TestStringOnceRejectsRepeats(t *testing.T) {
	var v string
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.Usage = func() {}
	StringOnce(fs, &v, "ref", "")
	err := fs.Parse([]string{"--ref", "a", "--ref", "b"})
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("repeat accepted: %v", err)
	}
}

func TestStringArrayEqualsSpelling(t *testing.T) {
	plantArgv(t, "container", "run", "--env=A=--x", "--env", "B=2")
	var vals []string
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	StringArray(fs, &vals, "env", "")
	if err := fs.Parse([]string{"--env=A=--x", "--env", "B=2"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vals) != 2 || vals[0] != "A=--x" || vals[1] != "B=2" {
		t.Fatalf("values = %v", vals)
	}
}
