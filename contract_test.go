//go:build windows

// These tests assert the CLI contract against the real binary: exit codes mean what they say,
// --json puts exactly one parseable document on stdout on every path, and exit 64 changed
// nothing on disk.
//
// A green run means "builds, starts, and honours its contract" -- never "works". Nothing here
// reaches HCS, the network, or elevation: hosted runners have no Hyper-V, and "works" is the
// elevated smoke transcript, not this suite.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/store"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hcsctl-contract")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "hcsctl.exe")

	// GOROOT, not PATH: Go may not be on PATH.
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	if _, err := os.Stat(goBin); err != nil {
		goBin = "go"
	}
	if out, err := exec.Command(goBin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("build: " + err.Error() + "\n" + string(out))
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	code   int
	stdout string
	stderr string
}

func invoke(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running %v: %v", args, err)
		}
	}
	return result{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

// oneDoc asserts stdout is exactly one JSON object, parseable standalone, whose "ok" field
// matches. Trailing junk after the document is as much a violation as no document.
func oneDoc(t *testing.T, stdout string, wantOK bool) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\nstdout: %q", err, stdout)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("more than one document on stdout: %q", stdout)
	}
	ok, has := doc["ok"].(bool)
	if !has {
		t.Fatalf("document has no boolean \"ok\": %q", stdout)
	}
	if ok != wantOK {
		t.Fatalf("ok = %v, want %v\nstdout: %q", ok, wantOK, stdout)
	}
}

// usageCases are every shape of rejected command line. All must exit 64, emit one ok:false
// document under --json, and keep stdout empty without it.
var usageCases = []struct {
	name string
	args []string
}{
	{"bare invocation", nil},
	{"unknown verb group", []string{"frobnicate"}},
	{"version with stray argument", []string{"version", "extra"}},
	{"version flag with stray argument", []string{"--version", "extra"}},
	{"completion command", []string{"completion", "bash"}},
	{"hidden completion command", []string{"__complete", "image", ""}},
	{"hidden no-desc completion command", []string{"__completeNoDesc", "image", ""}},
	{"missing subcommand", []string{"container"}},
	{"unknown subcommand", []string{"container", "frobnicate"}},
	{"unknown subcommand with trailing flag", []string{"vm", "frobnicate", "--id", "eb95e0a7-ee3e-4c7b-ba10-4089b4771083"}},
	{"unknown verb group with trailing flag", []string{"frobnicate", "--id", "x"}},
	{"bool flag before the verb", []string{"container", "--follow", "logs", "--id", "x"}},
	// A -- terminator before the verb is exercised in TestUnknownSubcommandIsNamed: this
	// harness appends --json, which a -- would correctly demote to a positional.
	{"mixed spellings keep the option-shaped guard", []string{"container", "run", "--ref", "r", "--mount=--keep", "--mount", "--keep"}},
	{"exec without cmd", []string{"container", "exec", "--id", "a"}},
	{"storage mount missing scratch-dir", []string{"storage", "mount", "--ref", "r"}},
	{"unknown option", []string{"image", "ls", "--bogus", "x"}},
	{"duplicate option", []string{"container", "exec", "--id", "a", "--id", "b", "--cmd", "c"}},
	{"missing required option", []string{"image", "pull"}},
	{"required option given empty", []string{"image", "pull", "--ref", ""}},
	{"option missing value", []string{"image", "pull", "--ref"}},
	{"unparseable ref", []string{"image", "pull", "--ref", "!!!"}},
	{"env without equals", []string{"container", "exec", "--id", "a", "--cmd", "c", "--env", "BAD"}},
	{"env with empty name", []string{"container", "exec", "--id", "a", "--cmd", "c", "--env", "=v"}},
	{"env with empty value", []string{"container", "exec", "--id", "a", "--cmd", "c", "--env", "N="}},
	{"dns-search without network", []string{"container", "run", "--ref", "r", "--dns-search", "d"}},
	{"cpus not a number", []string{"container", "run", "--ref", "r", "--cpus", "two"}},
	{"mount not absolute", []string{"container", "run", "--ref", "r", "--mount", `relative\p:C:\app`}},
	{"mount host missing", []string{"container", "run", "--ref", "r", "--mount", `C:\hcsctl-no-such-dir:C:\app`}},
	{"mount container path repeated", []string{"container", "run", "--ref", "r",
		"--mount", `C:\Windows:C:\app`, "--mount", `C:\Windows:C:\app`}},
	{"storage missing subcommand", []string{"storage"}},
	{"storage setup-base missing layer", []string{"storage", "setup-base"}},
	{"storage setup-base bad size", []string{"storage", "setup-base", "--layer", `C:\Windows`, "--size-gb", "big"}},
	{"storage setup-base not a layer", []string{"storage", "setup-base", "--layer", `C:\Windows`}},
	{"storage mount missing base", []string{"storage", "mount", "--scratch-dir", `C:\x`}},
	{"storage unmount no sandbox", []string{"storage", "unmount", "--scratch-dir", `C:\Windows`}},
	{"storage import missing source", []string{"storage", "import", "--layer", `C:\x`}},
	{"storage export missing dest", []string{"storage", "export", "--layer", `C:\Windows`}},
	{"storage export bad parent", []string{"storage", "export", "--layer", `C:\Windows`, "--dest", `C:\Windows`, "--parent", `C:\hcsctl-no-such-dir`}},
	{"storage mount ref and base exclusive", []string{"storage", "mount", "--ref", "r", "--base", `C:\Windows`, "--scratch-dir", `C:\x`}},
	{"storage destroy missing layer", []string{"storage", "destroy"}},
	{"storage destroy no such dir", []string{"storage", "destroy", "--layer", `C:\hcsctl-no-such-dir`}},
	{"storage attach-overlay missing volume", []string{"storage", "attach-overlay", "--layer", `C:\Windows`}},
	{"storage attach-overlay missing layer", []string{"storage", "attach-overlay", "--volume", `C:\Windows`}},
	{"storage attach-overlay bad filter type", []string{"storage", "attach-overlay", "--volume", `C:\Windows`, "--layer", `C:\Windows`, "--filter-type", "btrfs"}},
	{"storage attach-overlay layer missing", []string{"storage", "attach-overlay", "--volume", `C:\Windows`, "--layer", `C:\hcsctl-no-such-dir`}},
	{"storage attach-overlay bad layer volume guid", []string{"storage", "attach-overlay", "--volume", `C:\Windows`, "--layer", `\\?\Volume{not-a-guid}\Files`}},
	{"storage attach-overlay volume without WcSandboxState", []string{"storage", "attach-overlay", "--volume", `C:\Windows`, "--layer", `C:\Windows`}},
	{"storage detach-overlay missing volume", []string{"storage", "detach-overlay"}},
	{"storage detach-overlay bad filter type", []string{"storage", "detach-overlay", "--volume", `C:\Windows`, "--filter-type", "btrfs"}},
	{"scratch-size no unit", []string{"container", "run", "--ref", "r", "--scratch-size", "40"}},
	{"scratch-size not a number", []string{"container", "run", "--ref", "r", "--scratch-size", "bigGB"}},
	{"scratch-size zero", []string{"layer", "mount", "--ref", "r", "--scratch-size", "0GB"}},
	{"timeout not a duration", []string{"container", "exec", "--id", "a", "--cmd", "c", "--timeout", "soon"}},
	{"timeout not positive", []string{"container", "exec", "--id", "a", "--cmd", "c", "--timeout", "-3s"}},
	{"guest exec timeout below one second", []string{"guest", "exec", "--vmid", "00000000-0000-0000-0000-000000000000", "--cmd", "c", "--timeout", "500ms"}},
	{"tty requires interactive", []string{"container", "exec", "--id", "a", "--cmd", "c", "--tty"}},
	{"interactive rejects stream json", []string{"container", "exec", "--id", "a", "--cmd", "c", "--interactive", "--stream-json"}},
	{"kill without pid", []string{"container", "kill", "--id", "a"}},
	{"kill pid not a number", []string{"container", "kill", "--id", "a", "--pid", "abc"}},
	{"id with traversal", []string{"container", "start", "--id", `..\..\x`}},
	{"id rooted", []string{"container", "start", "--id", `C:\evil`}},
	{"id with separator", []string{"container", "exec", "--id", `a\b`, "--cmd", "c"}},
	{"id reserved device name", []string{"container", "rm", "--id", "NUL"}},
	{"id trailing dot", []string{"container", "create", "--ref", "r", "--id", "x."}},
	{"id derived from traversal ref", []string{"container", "run", "--ref", "..", "--cmd", "c"}},
	{"layer mount id with separator", []string{"layer", "mount", "--ref", "r", "--id", `a\b`}},
	{"layer unmount id dotdot", []string{"layer", "unmount", "--id", ".."}},
	{"cpus above uint32", []string{"container", "run", "--ref", "r", "--cpus", "4294967296"}},
	{"cpus overflows uint64", []string{"container", "run", "--ref", "r", "--cpus", "18446744073709551617"}},
	{"memory-mb above int64", []string{"container", "run", "--ref", "r", "--memory-mb", "9223372036854775808"}},
	{"pid above int32", []string{"container", "kill", "--id", "a", "--pid", "2147483648"}},
	{"size-gb above vhdx ceiling", []string{"storage", "setup-base", "--layer", `C:\Windows`, "--size-gb", "65537"}},
	{"scratch-size above vhdx ceiling", []string{"container", "run", "--ref", "r", "--scratch-size", "65537GB"}},
	{"logs without id", []string{"container", "logs"}},
	{"logs unknown container", []string{"container", "logs", "--id", "zz-no-such"}},
	{"label without equals", []string{"container", "create", "--ref", "r", "--label", "owner"}},
	{"label empty key", []string{"container", "create", "--ref", "r", "--label", "=v"}},
	{"label bad key", []string{"container", "create", "--ref", "r", "--label", "a b=v"}},
	{"label reserved key", []string{"container", "create", "--ref", "r", "--label", "id=x"}},
	{"label duplicate key", []string{"container", "run", "--ref", "r", "--label", "a=1", "--label", "a=2"}},
	{"network create missing name", []string{"network", "create", "--type", "private"}},
	{"network create unsupported type", []string{"network", "create", "--name", "x", "--type", "overlay"}},
	{"network create NAT missing subnet", []string{"network", "create", "--name", "x", "--type", "nat", "--gateway", "192.168.1.1"}},
	{"network create NAT gateway outside subnet", []string{"network", "create", "--name", "x", "--type", "nat", "--subnet", "192.168.1.0/24", "--gateway", "192.168.2.1"}},
	{"network create private with subnet", []string{"network", "create", "--name", "x", "--type", "private", "--subnet", "192.168.1.0/24"}},
	{"network rm missing identity", []string{"network", "rm"}},
	{"network rm ambiguous identity", []string{"network", "rm", "--id", "x", "--name", "x"}},
	{"vm netconfig missing id", []string{"vm", "netconfig"}},
	{"vm netconfig non-guid id", []string{"vm", "netconfig", "--id", "not-a-guid"}},
	{"vm netconfig bad timeout", []string{"vm", "netconfig", "--id", "eb95e0a7-ee3e-4c7b-ba10-4089b4771083", "--timeout", "soon"}},
	{"network inspect missing identity", []string{"network", "inspect"}},
	{"network inspect ambiguous identity", []string{"network", "inspect", "--id", "x", "--name", "x"}},
	{"network inspect unknown option", []string{"network", "inspect", "--name", "x", "--force"}},
	// cim cases are argument-shaped only: capability gates depend on the host build, so
	// they are exercised in the smoke scripts, never here.
	{"cim missing subcommand", []string{"cim"}},
	{"cim create missing dir", []string{"cim", "create", "--cim", `C:\hcsctl-no-such-dir\a.cim`}},
	{"cim create neither cim nor block", []string{"cim", "create", "--dir", `C:\Windows`}},
	{"cim create cim and block exclusive", []string{"cim", "create", "--dir", `C:\Windows`, "--cim", `C:\x\a.cim`, "--block", `C:\x\a.bcim`}},
	{"cim create dir not a directory", []string{"cim", "create", "--dir", `C:\Windows\notepad.exe`, "--cim", `C:\x\a.cim`}},
	{"cim create unlink without fork", []string{"cim", "create", "--dir", `C:\Windows`, "--cim", `C:\x\a.cim`, "--unlink", "f.txt"}},
	{"cim create tombstone on standard cim", []string{"cim", "create", "--dir", `C:\Windows`, "--cim", `C:\x\a.cim`, "--tombstone", "f.txt"}},
	{"cim create consistent on standard cim", []string{"cim", "create", "--dir", `C:\Windows`, "--cim", `C:\x\a.cim`, "--consistent"}},
	{"cim create merged-link without equals", []string{"cim", "create", "--dir", `C:\Windows`, "--block", `C:\x\a.bcim`, "--merged-link", "bad"}},
	{"cim create fork of block cim", []string{"cim", "create", "--dir", `C:\Windows`, "--block", `C:\x\a.bcim`, "--fork-of", "p.cim"}},
	{"cim create fork-of is a path", []string{"cim", "create", "--dir", `C:\Windows`, "--cim", `C:\x\a.cim`, "--fork-of", `sub\p.cim`}},
	{"cim create block device without name", []string{"cim", "create", "--dir", `C:\Windows`, "--block", `\\.\PhysicalDrive9`}},
	{"cim mount neither cim nor block", []string{"cim", "mount"}},
	{"cim mount no such cim", []string{"cim", "mount", "--cim", `C:\hcsctl-no-such-dir\a.cim`}},
	{"cim mount single source", []string{"cim", "mount", "--block", `C:\x\m.bcim`, "--source", `C:\x\l1.bcim`}},
	{"cim mount source with standard cim", []string{"cim", "mount", "--cim", `C:\x\a.cim`, "--source", `C:\x\l1.bcim`, "--source", `C:\x\l2.bcim`}},
	{"cim mount verified with sources", []string{"cim", "mount", "--block", `C:\x\m.bcim`, "--verified", "--source", `C:\x\l1.bcim`, "--source", `C:\x\l2.bcim`}},
	{"cim mount root-hash without verified", []string{"cim", "mount", "--block", `C:\x\a.bcim`, "--root-hash", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}},
	{"cim mount root-hash wrong length", []string{"cim", "mount", "--block", `C:\x\a.bcim`, "--verified", "--root-hash", "abcd"}},
	{"cim mount guid not a guid", []string{"cim", "mount", "--cim", `C:\x\a.cim`, "--guid", "not-a-guid"}},
	{"cim unmount nothing given", []string{"cim", "unmount"}},
	{"cim unmount volume and cim both", []string{"cim", "unmount", "--volume", `\\?\Volume{eb95e0a7-ee3e-4c7b-ba10-4089b4771083}\`, "--cim", `C:\x\a.cim`}},
	{"cim unmount not a volume path", []string{"cim", "unmount", "--volume", `C:\x`}},
	{"cim merge missing block", []string{"cim", "merge", "--source", `C:\x\l1.bcim`, "--source", `C:\x\l2.bcim`}},
	{"cim merge one source", []string{"cim", "merge", "--block", `C:\x\m.bcim`, "--source", `C:\x\l1.bcim`}},
	{"cim merge source type mismatch", []string{"cim", "merge", "--block", `C:\x\m.bcim`, "--source", `C:\x\l1.bcim`, "--source", `\\.\PhysicalDrive9::b.cim`}},
	{"cim usage missing cim", []string{"cim", "usage"}},
	{"cim usage no such cim", []string{"cim", "usage", "--cim", `C:\hcsctl-no-such-dir\a.cim`}},
	{"cim usage not a cim", []string{"cim", "usage", "--cim", `C:\Windows\notepad.exe`}},
	{"cim verify missing block", []string{"cim", "verify"}},
	{"cim destroy missing cim", []string{"cim", "destroy"}},
	{"cim destroy no such cim", []string{"cim", "destroy", "--cim", `C:\hcsctl-no-such-dir\a.cim`}},
	{"cim destroy not a cim", []string{"cim", "destroy", "--cim", `C:\Windows\notepad.exe`}},
}

func TestUsageErrorsExit64(t *testing.T) {
	for _, tc := range usageCases {
		t.Run(tc.name, func(t *testing.T) {
			r := invoke(t, tc.args...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Fatalf("usage error wrote to stdout without --json: %q", r.stdout)
			}
			if r.stderr == "" {
				t.Fatalf("usage error said nothing on stderr")
			}
		})
	}
}

func TestUsageErrorsEmitOneJSONDocument(t *testing.T) {
	for _, tc := range usageCases {
		t.Run(tc.name, func(t *testing.T) {
			r := invoke(t, append(tc.args, "--json")...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			oneDoc(t, r.stdout, false)
		})
	}
}

func TestInteractiveRejectsJSONOutputContracts(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		json bool
	}{
		{"json", []string{"container", "exec", "--id", "a", "--cmd", "c", "--interactive", "--json"}, true},
		{"stream json", []string{"container", "exec", "--id", "a", "--cmd", "c", "--interactive", "--json", "--stream-json"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := invoke(t, tc.args...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			if tc.json {
				oneDoc(t, r.stdout, false)
			}
		})
	}
}

// TestUsageErrorAttemptsNothing hands rejected command lines a store path and asserts the
// path was never created: exit 64 promises nothing was attempted, and the store directory is
// the first thing an attempt would create.
func TestUsageErrorAttemptsNothing(t *testing.T) {
	cases := [][]string{
		{"image", "pull"},                   // missing --ref
		{"image", "ls", "--bogus", "x"},     // unknown option
		{"image", "rm", "--ref", "no/such"}, // no record
		{"container", "exec", "--id", "a", "--cmd", "c", "--env", "BAD"},
		{"container", "run", "--ref", "r", "--dns-search", "d"},
		{"container", "run", "--ref", "r", "--cpus", "two"},
		{"container", "run", "--ref", "r", "--mount", `bad-mount`},
		{"container", "run", "--ref", "r", "--publish", "39082:8082/tcp"},
		{"container", "create", "--ref", "r", "--publish", "bad"},
		{"container", "create", "--ref", "r", "--publish", "0:8082/tcp", "--network", "nat"},
		{"container", "start", "--id", `..\..\x`},
		{"container", "rm", "--id", `C:\evil`, "--force"},
		{"layer", "unmount", "--id", ".."},
		{"container", "create", "--ref", "r", "--label", "a=1", "--label", "a=2"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "store")
			r := invoke(t, append(args, "--store", store)...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("usage error created the store at %s", store)
			}
		})
	}
}

// TestCimUsageErrorAttemptsNothing: the cim verbs take no --store, so the observable
// side effect a usage error must not have is the target image directory itself.
func TestCimUsageErrorAttemptsNothing(t *testing.T) {
	target := filepath.Join(t.TempDir(), "cims")
	r := invoke(t, "cim", "create", "--dir", t.TempDir(),
		"--cim", filepath.Join(target, "a.cim"), "--tombstone", "t")
	if r.code != 64 {
		t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("usage error created the image directory at %s", target)
	}
}

// TestStreamJSONTypesStderr: under --json --stream-json every non-empty stderr line is
// an NDJSON object with a "stream" field; without the flag the same run writes bare text.
// The fixture is a fake materialized store -- valid record, layer dirs with Files and a
// UtilityVM -- so `container run` gets far enough to emit real progress before failing at
// the first HCS call, which hosted runners cannot make.
func TestStreamJSONTypesStderr(t *testing.T) {
	digest := `sha256:` + strings.Repeat("3", 64)
	store := filepath.Join(t.TempDir(), "store")
	layerDir := filepath.Join(store, "layers", strings.Repeat("3", 64))
	for _, d := range []string{filepath.Join(layerDir, "Files"), filepath.Join(layerDir, "UtilityVM"), filepath.Join(store, "images")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rec := `{"ref":"fake/img:1","layerDigests":["` + digest + `"],"diffIDs":["` + digest + `"]}`
	if err := os.WriteFile(recordPath(t, store, "fake/img:1"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"container", "run", "--ref", "fake/img:1", "--store", store, "--json"}

	framed := invoke(t, append(args, "--stream-json")...)
	if framed.stderr == "" {
		t.Fatal("no stderr at all -- the fixture no longer reaches a progress line, and this test proves nothing")
	}
	for _, line := range strings.Split(strings.TrimSpace(framed.stderr), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("stderr line is not NDJSON under --stream-json: %q", line)
		}
		if s, _ := obj["stream"].(string); s == "" {
			t.Fatalf("stderr object has no stream field: %q", line)
		}
	}
	oneDoc(t, framed.stdout, false) // the stdout contract is unchanged

	bare := invoke(t, args...)
	if json.Valid([]byte(strings.SplitN(strings.TrimSpace(bare.stderr), "\n", 2)[0])) {
		t.Fatalf("without --stream-json stderr should be bare text, got %q", bare.stderr)
	}
}

// TestContainerLogs exercises every logs path that needs no HCS: the file and the
// state are the whole interface, so a planted container directory covers them.
func TestContainerLogs(t *testing.T) {
	plant := func(t *testing.T, primary string) string {
		t.Helper()
		store := filepath.Join(t.TempDir(), "store")
		dir := filepath.Join(store, "containers", "p")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		state := `{"id":"p","ref":"r","scratch":"x","utilityVM":"y","chain":[]` + primary + `}`
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(state), 0o644); err != nil {
			t.Fatal(err)
		}
		return store
	}

	t.Run("no primary recorded is exit 64", func(t *testing.T) {
		r := invoke(t, "container", "logs", "--id", "p", "--store", plant(t, ""))
		if r.code != 64 || !strings.Contains(r.stderr, "--cmd") {
			t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
		}
	})
	t.Run("exited primary: retained log and exit code from a fresh invocation", func(t *testing.T) {
		store := plant(t, `,"primary":{"cmd":"app.exe","pid":900,"exitCode":7,"endedUtc":"2026-08-07T00:00:00Z"}`)
		if err := os.WriteFile(filepath.Join(store, "containers", "p", "primary.log"), []byte("retained line\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := invoke(t, "container", "logs", "--id", "p", "--store", store, "--json")
		if r.code != 0 {
			t.Fatalf("exit %d\nstderr: %s", r.code, r.stderr)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatal(err)
		}
		if doc["status"] != "exited" || doc["log"] != "retained line\n" {
			t.Fatalf("status %v, log %q", doc["status"], doc["log"])
		}
		if ec := doc["primary"].(map[string]any)["exitCode"]; ec != float64(7) {
			t.Fatalf("exitCode %v, want 7", ec)
		}
	})
	t.Run("dead pump is reported, not hidden", func(t *testing.T) {
		// 999999 is not a multiple of 4, so it can never be a live Windows pid.
		store := plant(t, `,"primary":{"cmd":"app.exe","pid":900,"pumpPid":999999,"startedUtc":"2026-08-07T00:00:00Z"}`)
		r := invoke(t, "container", "logs", "--id", "p", "--store", store, "--json")
		if r.code != 0 {
			t.Fatalf("exit %d\nstderr: %s", r.code, r.stderr)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatal(err)
		}
		if s, _ := doc["status"].(string); !strings.Contains(s, "pump dead") {
			t.Fatalf("status %q does not report the dead pump", s)
		}
	})
	t.Run("follow of an exited primary drains and finishes", func(t *testing.T) {
		store := plant(t, `,"primary":{"cmd":"app.exe","pid":900,"exitCode":0,"endedUtc":"2026-08-07T00:00:00Z"}`)
		if err := os.WriteFile(filepath.Join(store, "containers", "p", "primary.log"), []byte("a\nb\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := invoke(t, "container", "logs", "--id", "p", "--store", store, "--follow", "--json")
		if r.code != 0 {
			t.Fatalf("follow did not finish cleanly: exit %d\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, true)
		if !strings.Contains(r.stderr, "a\nb\n") {
			t.Fatalf("followed content missing from stderr: %q", r.stderr)
		}
	})
}

// Requested help is exit 64 with the help text on stderr: nothing ran, and exit 0 must never
// be emitted without the verb having run -- a forwarded --help inside a real invocation would
// otherwise record a destructive verb as succeeded. Version is a real verb: exit 0.
func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{
		{"--help"}, {"-h"}, {"help"}, {"help", "vm"}, {"container", "--help"},
		// The review scenario: --help riding a complete destructive invocation.
		{"vm", "stop", "--id", "eb95e0a7-ee3e-4c7b-ba10-4089b4771083", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := invoke(t, args...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Fatalf("help wrote to stdout without --json: %q", r.stdout)
			}
			if !strings.Contains(r.stderr, "usage: hcsctl") {
				t.Fatalf("help did not render usage on stderr: %q", r.stderr[:min(len(r.stderr), 80)])
			}
		})
	}
	t.Run("help with --json emits one failure document", func(t *testing.T) {
		r := invoke(t, "vm", "stop", "--id", "eb95e0a7-ee3e-4c7b-ba10-4089b4771083", "--help", "--json")
		if r.code != 64 {
			t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, false)
	})
	t.Run("unknown help topic", func(t *testing.T) {
		r := invoke(t, "help", "bogus")
		if r.code != 64 || !strings.Contains(r.stderr, "bogus") {
			t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
		}
	})
	for _, args := range [][]string{{"--version"}, {"version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := invoke(t, args...)
			if r.code != 0 {
				t.Fatalf("exit %d, want 0\nstderr: %s", r.code, r.stderr)
			}
			if !strings.Contains(r.stdout, "hcsctl") || !strings.Contains(r.stdout, "contract") {
				t.Fatalf("version output: %q", r.stdout)
			}
		})
	}
	t.Run("json keeps the one-document contract", func(t *testing.T) {
		r := invoke(t, "help", "--json")
		if r.code != 64 {
			t.Fatalf("help --json: exit %d, want 64", r.code)
		}
		oneDoc(t, r.stdout, false)
		r = invoke(t, "version", "--json")
		if r.code != 0 {
			t.Fatalf("version --json: exit %d, want 0", r.code)
		}
		oneDoc(t, r.stdout, true)
	})
	t.Run("version flag is order-independent", func(t *testing.T) {
		for _, args := range [][]string{{"--json", "--version"}, {"--version", "--json"}} {
			r := invoke(t, args...)
			if r.code != 0 {
				t.Fatalf("%v: exit %d, want 0\nstderr: %s", args, r.code, r.stderr)
			}
			oneDoc(t, r.stdout, true)
		}
	})
	t.Run("an option value spelled --help passes through the = spelling", func(t *testing.T) {
		// exec's --cmd may legitimately be the string --help. The = spelling is
		// unambiguous, so it must reach normal dispatch (and fail on the missing
		// container), not be rejected as a forgotten value or hijacked as help.
		r := invoke(t, "container", "exec", "--id", "zz-no-such", "--cmd=--help")
		if r.code == 0 || strings.Contains(r.stdout, "usage: hcsctl") {
			t.Fatalf("option value --help hijacked the invocation: exit %d", r.code)
		}
		if !strings.Contains(r.stderr, "zz-no-such") {
			t.Fatalf("=-spelled value did not reach dispatch: %q", r.stderr)
		}
	})
	t.Run("space form with an option-shaped value is a forgotten value", func(t *testing.T) {
		// Without the = the value would have been swallowed silently by pflag; the guard
		// rejects it and names the escape hatch.
		r := invoke(t, "container", "exec", "--id", "zz-no-such", "--cmd", "--help")
		if r.code != 64 || !strings.Contains(r.stderr, "requires a value") {
			t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
		}
	})
}

// TestUnknownSubcommandIsNamed discriminates the diagnostic from the exit code: a mistyped
// verb followed by a flag must be reported as the unknown verb, not as the unknown flag the
// verb's absence made unparseable.
func TestUnknownSubcommandIsNamed(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"vm", "frobnicate", "--id", "eb95e0a7-ee3e-4c7b-ba10-4089b4771083"}, `unknown vm subcommand "frobnicate"`},
		{[]string{"frobnicate", "--id", "x"}, `unknown verb group "frobnicate"`},
		// A real verb behind a flag or -- is diagnosed as misplacement, not misspelling:
		// pflag must not swallow the verb as the unknown flag's value, and the message must
		// not call a listed verb unknown.
		{[]string{"container", "--follow", "logs", "--id", "x"}, "the verb must come before"},
		{[]string{"vm", "--", "start"}, "the verb must come before"},
	} {
		t.Run(strings.Join(tc.args[:2], " "), func(t *testing.T) {
			r := invoke(t, tc.args...)
			if r.code != 64 {
				t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("stderr does not name the mistake %q: %q", tc.want, r.stderr)
			}
		})
	}
}

// TestCompletionMachineryRejected: cobra's hidden __complete command resolves even behind
// leading flags, and its output is completion text on stdout with exit 0 -- both contract
// breaks. The guard must hold wherever the word can reach cobra.
func TestCompletionMachineryRejected(t *testing.T) {
	r := invoke(t, "--json", "__complete", "network", "")
	if r.code != 64 {
		t.Fatalf("exit %d, want 64\nstdout: %q", r.code, r.stdout)
	}
	oneDoc(t, r.stdout, false)
}

// TestResolveStoreFailureIsUsage: with no --store and no LOCALAPPDATA the default store
// cannot resolve; the command line (with its environment) is bad and nothing was attempted,
// so this is exit 64 -- the classification the pre-cobra dispatch gave every resolve failure.
func TestResolveStoreFailureIsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "container", "logs", "--id", "p", "--json")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "LOCALAPPDATA=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 64 {
		t.Fatalf("exit %d, want 64\nstderr: %s", code, stderr.String())
	}
	oneDoc(t, stdout.String(), false)
}

// TestJSONFlagGrammarMatchesCobra: the pre-parse that seeds the output mode uses pflag's own
// grammar, so a --json placed after the -- terminator is a positional to both parses -- the
// error must arrive as plain text, not as a document the caller never asked for.
func TestJSONFlagGrammarMatchesCobra(t *testing.T) {
	r := invoke(t, "network", "ls", "--", "--json")
	if r.code != 64 {
		t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("terminated --json still selected JSON mode: %q", r.stdout)
	}
}

// TestIDValidationIsWired plants a real target at the traversal destination and asserts the
// command exits 64 with the target untouched. This discriminates wiring from mere existence of
// the validator: the plain usageCases for bad ids would pass even without validation (they fall
// into "no container named" / "no mount named", also 64).
func TestIDValidationIsWired(t *testing.T) {
	t.Run("container rm --id .. cannot reach planted state", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "store")
		if err := os.MkdirAll(filepath.Join(store, "containers"), 0o755); err != nil {
			t.Fatal(err)
		}
		// statePath(store, "..") resolves to store\state.json -- plant a valid record there.
		state := `{"id":"..","ref":"r","scratch":"x","utilityVM":"y","chain":[]}`
		if err := os.WriteFile(filepath.Join(store, "state.json"), []byte(state), 0o644); err != nil {
			t.Fatal(err)
		}
		r := invoke(t, "container", "rm", "--id", "..", "--force", "--store", store)
		if r.code != 64 {
			t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
		}
		if _, err := os.Stat(filepath.Join(store, "state.json")); err != nil {
			t.Fatalf("planted state was consumed or removed: %v", err)
		}
	})
	t.Run("layer unmount --id .. cannot reach the store root", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "store")
		if err := os.MkdirAll(filepath.Join(store, "scratch"), 0o755); err != nil {
			t.Fatal(err)
		}
		// scratchPath(store, "..") resolves to the store root, which exists -- without
		// validation the existence check passes and DestroyLayer runs against it.
		r := invoke(t, "layer", "unmount", "--id", "..", "--store", store)
		if r.code != 64 {
			t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
		}
		if _, err := os.Stat(filepath.Join(store, "scratch")); err != nil {
			t.Fatalf("store scratch directory is gone: %v", err)
		}
	})
}

// TestNumericBoundsAreWired discriminates the bound from the fallthrough: each command would
// exit 64 either way (the ref/container does not exist), so the assertion is on the error
// text: it must name the rejected option, not the missing record.
func TestNumericBoundsAreWired(t *testing.T) {
	errorOf := func(t *testing.T, args ...string) string {
		t.Helper()
		r := invoke(t, append(args, "--json")...)
		if r.code != 64 {
			t.Fatalf("exit %d, want 64\nstderr: %s", r.code, r.stderr)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatalf("stdout is not a document: %v", err)
		}
		msg, _ := doc["error"].(string)
		return msg
	}
	cases := []struct {
		name, want string
		args       []string
	}{
		{"cpus", "--cpus", []string{"container", "run", "--ref", "r", "--cmd", "c", "--cpus", "4294967296"}},
		{"memory-mb", "--memory-mb", []string{"container", "run", "--ref", "r", "--cmd", "c", "--memory-mb", "9223372036854775808"}},
		{"pid", "--pid", []string{"container", "kill", "--id", "a", "--pid", "2147483648"}},
		{"scratch-size", "65537GB", []string{"container", "run", "--ref", "r", "--cmd", "c", "--scratch-size", "65537GB"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if msg := errorOf(t, tc.args...); !strings.Contains(msg, tc.want) {
				t.Fatalf("error %q does not mention %q -- the bound is not wired", msg, tc.want)
			}
		})
	}
	t.Run("size-gb", func(t *testing.T) {
		// --layer must be an existing directory so the size check is what rejects.
		msg := errorOf(t, "storage", "setup-base", "--layer", t.TempDir(), "--size-gb", "65537")
		if !strings.Contains(msg, "--size-gb") {
			t.Fatalf("error %q does not mention --size-gb -- the bound is not wired", msg)
		}
	})
}

func TestSuccessPath(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")

	t.Run("json is one ok document", func(t *testing.T) {
		r := invoke(t, "image", "ls", "--store", store, "--json")
		if r.code != 0 {
			t.Fatalf("exit %d, want 0\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, true)
	})
	t.Run("info json is one ok document", func(t *testing.T) {
		r := invoke(t, "info", "--store", store, "--json")
		if r.code != 0 {
			t.Fatalf("exit %d, want 0\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, true)
	})
	t.Run("info carries tool and contract versions", func(t *testing.T) {
		r := invoke(t, "info", "--store", store, "--json")
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatal(err)
		}
		tool, _ := doc["toolVersion"].(string)
		contract, _ := doc["contractVersion"].(string)
		if tool == "" {
			t.Fatal("toolVersion missing or empty -- a consumer's preflight has nothing to log")
		}
		if contract == "" {
			t.Fatal("contractVersion missing or empty -- a consumer's preflight has nothing to check")
		}
		if host, _ := doc["version"].(string); host == tool {
			t.Fatalf("toolVersion %q equals the host OS version -- the two must not be confusable", tool)
		}
	})
	t.Run("human mode puts no document on stdout", func(t *testing.T) {
		r := invoke(t, "image", "ls", "--store", store)
		if r.code != 0 {
			t.Fatalf("exit %d, want 0\nstderr: %s", r.code, r.stderr)
		}
		if strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
			t.Fatalf("human mode leaked a document to stdout: %q", r.stdout)
		}
		if r.stdout == "" {
			t.Fatalf("human mode said nothing on stdout")
		}
	})
}

// TestFailurePath exercises exit 1 -- ran and failed -- without HCS, elevation or network: a
// record file holding invalid JSON makes `image rm` fail after argument validation passed.
func TestFailurePath(t *testing.T) {
	makeStore := func(t *testing.T) string {
		t.Helper()
		store := filepath.Join(t.TempDir(), "store")
		images := filepath.Join(store, "images")
		if err := os.MkdirAll(images, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recordPath(t, store, "x"), []byte("not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		return store
	}

	t.Run("exit 1 and one json document", func(t *testing.T) {
		r := invoke(t, "image", "rm", "--ref", "x", "--store", makeStore(t), "--json")
		if r.code != 1 {
			t.Fatalf("exit %d, want 1\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, false)
	})
	t.Run("semantically invalid record cannot panic", func(t *testing.T) {
		// Valid JSON, mismatched arrays: import must error, not panic, on a record like this.
		store := filepath.Join(t.TempDir(), "store")
		images := filepath.Join(store, "images")
		if err := os.MkdirAll(images, 0o755); err != nil {
			t.Fatal(err)
		}
		d := `"sha256:` + strings.Repeat("0", 64) + `"`
		rec := `{"ref":"x","layerDigests":[],"diffIDs":[` + d + `]}`
		if err := os.WriteFile(recordPath(t, store, "x"), []byte(rec), 0o644); err != nil {
			t.Fatal(err)
		}
		r := invoke(t, "image", "rm", "--ref", "x", "--store", store, "--json")
		if r.code != 1 {
			t.Fatalf("exit %d, want 1 (2 would be a panic)\nstderr: %s", r.code, r.stderr)
		}
		oneDoc(t, r.stdout, false)
	})
	t.Run("human mode keeps stdout empty", func(t *testing.T) {
		r := invoke(t, "image", "rm", "--ref", "x", "--store", makeStore(t))
		if r.code != 1 {
			t.Fatalf("exit %d, want 1\nstderr: %s", r.code, r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("failure wrote to stdout without --json: %q", r.stdout)
		}
		if r.stderr == "" {
			t.Fatalf("failure said nothing on stderr")
		}
	})
}

// recordPath is where the store keys ref's record; fixtures write there directly.
func recordPath(t *testing.T, root, ref string) string {
	t.Helper()
	st, err := store.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return st.RecordPath(ref)
}
