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
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hcsctl-contract")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "hcsctl.exe")

	// GOROOT rather than PATH: on the dev host Go is installed but not always on PATH.
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
	{"missing subcommand", []string{"container"}},
	{"unknown subcommand", []string{"container", "frobnicate"}},
	{"unknown option", []string{"image", "ls", "--bogus", "x"}},
	{"duplicate option", []string{"container", "exec", "--id", "a", "--id", "b", "--cmd", "c"}},
	{"missing required option", []string{"image", "pull"}},
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
	{"scratch-size no unit", []string{"container", "run", "--ref", "r", "--scratch-size", "40"}},
	{"scratch-size not a number", []string{"container", "run", "--ref", "r", "--scratch-size", "bigGB"}},
	{"scratch-size zero", []string{"layer", "mount", "--ref", "r", "--scratch-size", "0GB"}},
	{"timeout not a duration", []string{"container", "exec", "--id", "a", "--cmd", "c", "--timeout", "soon"}},
	{"timeout not positive", []string{"container", "exec", "--id", "a", "--cmd", "c", "--timeout", "-3s"}},
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

// TestUsageErrorAttemptsNothing hands rejected command lines a store path and asserts the
// path was never created: exit 64 promises nothing was attempted, and the store directory is
// the first thing an attempt would create.
func TestUsageErrorAttemptsNothing(t *testing.T) {
	cases := [][]string{
		{"image", "pull"},                    // missing --ref
		{"image", "ls", "--bogus", "x"},      // unknown option
		{"image", "rm", "--ref", "no/such"},  // no record
		{"container", "exec", "--id", "a", "--cmd", "c", "--env", "BAD"},
		{"container", "run", "--ref", "r", "--dns-search", "d"},
		{"container", "run", "--ref", "r", "--cpus", "two"},
		{"container", "run", "--ref", "r", "--mount", `bad-mount`},
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

// TestStreamJSONTypesStderr (#28): under --json --stream-json every non-empty stderr line is
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
	if err := os.WriteFile(filepath.Join(store, "images", "fake_img_1.json"), []byte(rec), 0o644); err != nil {
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

// TestContainerLogs (#33) exercises every logs path that needs no HCS: the file and the
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

// Requested help and version are exit 0 with output on stdout -- unlike the usage text that
// accompanies an error, which stays on stderr (#25).
func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		t.Run(strings.Join(args, ""), func(t *testing.T) {
			r := invoke(t, args...)
			if r.code != 0 {
				t.Fatalf("exit %d, want 0\nstderr: %s", r.code, r.stderr)
			}
			if !strings.Contains(r.stdout, "usage: hcsctl") {
				t.Fatalf("help did not render usage on stdout: %q", r.stdout[:min(len(r.stdout), 80)])
			}
		})
	}
	for _, args := range [][]string{{"--version"}, {"version"}} {
		t.Run(strings.Join(args, ""), func(t *testing.T) {
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
		for _, args := range [][]string{{"help", "--json"}, {"version", "--json"}} {
			r := invoke(t, args...)
			if r.code != 0 {
				t.Fatalf("%v: exit %d, want 0", args, r.code)
			}
			oneDoc(t, r.stdout, true)
		}
	})
	t.Run("an option value spelled --help is not hijacked", func(t *testing.T) {
		// Leading position only: exec's --cmd may legitimately be the string --help. This
		// must reach normal dispatch (and fail on the missing container), not print usage.
		r := invoke(t, "container", "exec", "--id", "zz-no-such", "--cmd", "--help")
		if r.code == 0 || strings.Contains(r.stdout, "usage: hcsctl") {
			t.Fatalf("option value --help hijacked the invocation: exit %d", r.code)
		}
	})
}

// TestIDValidationIsWired plants a real target at the traversal destination and asserts the
// command exits 64 with the target untouched. This discriminates wiring from mere existence of
// the validator: the plain usageCases for bad ids would pass even without validation (they fall
// into "no container named" / "no mount named", also 64). Before the fix, these two commands
// found their traversal target -- the planted state parsed, the scratch stat succeeded -- and
// proceeded toward destruction: container rm's os.RemoveAll would have deleted the store root.
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
// text -- post-#21 it names the rejected option; pre-#21 it named the missing record, which
// means the oversized value had parsed and execution had moved on.
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
	t.Run("info carries tool and contract versions (#29)", func(t *testing.T) {
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
		if err := os.WriteFile(filepath.Join(images, "x.json"), []byte("not json"), 0o644); err != nil {
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
	t.Run("semantically invalid record cannot panic (#22)", func(t *testing.T) {
		// Valid JSON, mismatched arrays: pre-#22 import indexed LayerDigests[i] over DiffIDs
		// and a record like this panicked instead of erroring.
		store := filepath.Join(t.TempDir(), "store")
		images := filepath.Join(store, "images")
		if err := os.MkdirAll(images, 0o755); err != nil {
			t.Fatal(err)
		}
		d := `"sha256:` + strings.Repeat("0", 64) + `"`
		rec := `{"ref":"x","layerDigests":[],"diffIDs":[` + d + `]}`
		if err := os.WriteFile(filepath.Join(images, "x.json"), []byte(rec), 0o644); err != nil {
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
