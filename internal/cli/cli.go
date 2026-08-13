// Package cli holds the pieces every verb group shares: argument parsing, output, exit codes.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Exit codes. 64 is EX_USAGE from sysexits.h.
const (
	OK     = 0
	Failed = 1
	Usage  = 64
)

// ContractVersion is the number a consumer's preflight checks (#29). Bump it when the shape
// of a result document changes, a field's meaning changes, or an exit code's meaning changes
// -- and ONLY then. Adding a new verb, option, or document field is not a bump: a consumer
// reading fields it knows keeps working. If you are editing a Result document or the exit
// codes above, you are the person this comment is for.
const ContractVersion = "1"

// ToolVersion identifies the build for humans in a bug report. Release builds stamp it:
//
//	go build -ldflags "-X github.com/joshmakestuff/hcsctl/internal/cli.ToolVersion=v0.2.0" .
//
// A dev build reports "dev" rather than a version it does not have.
var ToolVersion = "dev"

// UsageError means the command line was wrong and nothing was attempted.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func Usagef(format string, a ...any) error {
	return &UsageError{Msg: fmt.Sprintf(format, a...)}
}

// Args is a minimal flag parser. Deliberately not the flag package: verbs are nouns followed
// by verbs followed by options, and `flag` wants options first.
type Args struct {
	Words   []string // positional, e.g. ["image", "pull"]
	options map[string]string
	multi   map[string][]string
	flags   map[string]bool
}

// repeatable options accumulate instead of hitting the duplicate check. The duplicate
// rejection is deliberate -- it catches typos -- so repeatability is opted into per option
// here rather than relaxed globally.
var repeatable = map[string]bool{"--env": true, "--mount": true, "--parent": true, "--label": true, "--publish": true, "--acl": true}

// Parse splits argv. Anything starting with "--" is an option; those in boolFlags take no
// value, the rest consume the next argument.
func Parse(argv []string, boolFlags ...string) (*Args, error) {
	isFlag := map[string]bool{}
	for _, f := range boolFlags {
		isFlag[f] = true
	}
	a := &Args{options: map[string]string{}, multi: map[string][]string{}, flags: map[string]bool{}}
	for i := 0; i < len(argv); i++ {
		s := argv[i]
		switch {
		case !strings.HasPrefix(s, "--"):
			a.Words = append(a.Words, s)
		case isFlag[s]:
			a.flags[s] = true
		case repeatable[s]:
			if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
				return nil, Usagef("%s requires a value", s)
			}
			a.multi[s] = append(a.multi[s], argv[i+1])
			i++
		default:
			if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
				return nil, Usagef("%s requires a value", s)
			}
			if _, dup := a.options[s]; dup {
				return nil, Usagef("%s given more than once", s)
			}
			a.options[s] = argv[i+1]
			i++
		}
	}
	return a, nil
}

func (a *Args) Word(i int) string {
	if i < len(a.Words) {
		return a.Words[i]
	}
	return ""
}

func (a *Args) Option(name string) string { return a.options[name] }
func (a *Args) Flag(name string) bool     { return a.flags[name] }

// Options returns every value a repeatable option was given, in order.
func (a *Args) Options(name string) []string { return a.multi[name] }

func (a *Args) Require(name string) (string, error) {
	if v := a.options[name]; v != "" {
		return v, nil
	}
	return "", Usagef("%s is required", name)
}

// RejectUnknown fails on any option the command does not understand, so a typo is an error
// rather than a silently ignored setting.
func (a *Args) RejectUnknown(known ...string) error {
	ok := map[string]bool{"--json": true, "--stream-json": true}
	for _, k := range known {
		ok[k] = true
	}
	for k := range a.options {
		if !ok[k] {
			return Usagef("unknown option %s", k)
		}
	}
	for k := range a.multi {
		if !ok[k] {
			return Usagef("unknown option %s", k)
		}
	}
	for k := range a.flags {
		if !ok[k] {
			return Usagef("unknown option %s", k)
		}
	}
	return nil
}

// reservedNames are the Win32 device names that resolve regardless of directory. The check is
// against the part before the first dot, because "CON.txt" names the same device "CON" does.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidateID rejects an id that is not a safe leaf name. IDs are joined into store paths that
// later reach DestroyLayer and os.RemoveAll -- operations that commonly run elevated -- so
// anything that could escape the intended subtree (separators, traversal, rooted paths) or
// alias a different name (reserved device names; trailing dots and spaces, which Windows
// strips) is exit 64 before any path is built. Applies to derived ids too: a ref is as
// caller-controlled as an id.
func ValidateID(id string) error {
	if id == "" {
		return Usagef("id is empty")
	}
	if id == "." || id == ".." {
		return Usagef("id %q is not a name", id)
	}
	if i := strings.IndexAny(id, `/\:*?"<>|`); i >= 0 {
		return Usagef("id %q contains %q -- an id is a single name, not a path", id, id[i:i+1])
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return Usagef("id contains a control character")
		}
	}
	if strings.HasPrefix(id, " ") || strings.HasSuffix(id, " ") || strings.HasSuffix(id, ".") {
		return Usagef("id %q begins or ends with a space or dot, which Windows strips", id)
	}
	base, _, _ := strings.Cut(id, ".")
	if reservedNames[strings.ToUpper(base)] {
		return Usagef("id %q is a Windows reserved device name", id)
	}
	return nil
}

// ParseUint is the one bounded numeric parser (#21): every numeric option names the range its
// sink actually accepts, so overflow is exit 64 instead of a silent wrap. The hand-rolled
// parsers this replaces wrapped on uint64 overflow -- `--cpus 18446744073709551617` parsed as 1.
// The error text is written to read after an option name: Usagef("--cpus %v", err).
func ParseUint(s string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("must be at most %d, got %s", max, s)
		}
		return 0, fmt.Errorf("must be a positive integer, got %q", s)
	}
	if n == 0 {
		return 0, fmt.Errorf("must be positive, got 0")
	}
	if n > max {
		return 0, fmt.Errorf("must be at most %d, got %s", max, s)
	}
	return n, nil
}

// maxSizeBytes is 64 TB, the VHDX format ceiling -- every size option here ends up in a VHDX
// one way or another (scratch layers, base layers), so it is the shared operational bound.
const maxSizeBytes = 64 << 40

// ParseSize turns a human size -- "40GB", "40960MB" -- into bytes. The unit is required:
// a bare number is ambiguous enough to be a mistake, and this is used for disk sizes where
// the wrong guess costs tens of gigabytes.
func ParseSize(s string) (uint64, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	var mult uint64
	var digits string
	switch {
	case strings.HasSuffix(upper, "GB"):
		mult, digits = 1<<30, strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		mult, digits = 1<<20, strings.TrimSuffix(upper, "MB")
	default:
		return 0, Usagef("size %q needs a unit: GB or MB", s)
	}
	if digits == "" {
		return 0, Usagef("size %q has no number", s)
	}
	// The bound is in the given unit -- 64 TB expressed in GB or MB -- so a too-large size is
	// rejected with a number the caller can act on rather than silently wrapping.
	n, err := ParseUint(digits, maxSizeBytes/mult)
	if err != nil {
		return 0, Usagef("size %q: %v", s, err)
	}
	return n * mult, nil
}

// Emit is the output sink. In JSON mode stdout carries exactly one document and progress goes
// to stderr, so a consumer never has to scrape.
//
// StreamJSON (#28) types the one stream that was untyped: with it, everything on stderr is
// NDJSON -- one object per line -- so a consumer following a long-running exec can attribute
// every line without matching on message text. {"stream":"progress","msg":...} is hcsctl's
// own voice; guest output is framed by the container package as
// {"stream":"stdout"|"stderr","data":...}. Takes effect only alongside JSON mode: without
// --json there is no consumer, and human output stays human.
type Emit struct {
	JSON       bool
	StreamJSON bool
}

func (e Emit) framing() bool { return e.JSON && e.StreamJSON }

func (e Emit) Progress(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if e.framing() {
		e.streamLine(map[string]string{"stream": "progress", "msg": msg})
		return
	}
	if e.JSON {
		fmt.Fprintln(os.Stderr, msg)
	} else {
		fmt.Fprintln(os.Stdout, msg)
	}
}

func (e Emit) streamLine(obj map[string]string) {
	b, err := json.Marshal(obj)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stderr, string(b))
}

// NewStreamWriter frames one guest stream as NDJSON lines (#28). Complete lines are emitted
// as they arrive, without their line ending; a partial line is buffered to the next write --
// so a consumer sees whole lines and a rune split across reads cannot be mangled -- capped at
// 64 KB so a line-less guest cannot hold output hostage. Close flushes the remainder.
func NewStreamWriter(e Emit, stream string) *StreamWriter {
	return &StreamWriter{e: e, stream: stream}
}

type StreamWriter struct {
	e      Emit
	stream string
	buf    []byte
}

const streamLineCap = 64 * 1024

func (w *StreamWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > streamLineCap {
		w.emit(w.buf)
		w.buf = nil
	}
	return len(p), nil
}

func (w *StreamWriter) Close() error {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = nil
	}
	return nil
}

func (w *StreamWriter) emit(line []byte) {
	w.e.streamLine(map[string]string{"stream": w.stream, "data": strings.TrimSuffix(string(line), "\r")})
}

// StreamLogLine frames one retained-log line (#33's `container logs --follow`). The stream
// is "log", not "stdout"/"stderr": primary.log merges the guest's two streams, so per-stream
// attribution is gone by design once output is replayed from the file.
func (e Emit) StreamLogLine(line string) {
	e.streamLine(map[string]string{"stream": "log", "data": line})
}

// Result prints the command's single result: the document in JSON mode, human() otherwise.
func (e Emit) Result(doc any, human func()) {
	if e.JSON {
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal result: %v\n", err)
			return
		}
		fmt.Println(string(b))
		return
	}
	human()
}

// Failure reports a terminal error. In JSON mode it is still a well-formed document, so a
// consumer parses one shape whether the command worked or not.
func (e Emit) Failure(stage string, err error) {
	if e.JSON {
		b, _ := json.MarshalIndent(map[string]any{
			"ok": false, "stage": stage, "error": err.Error(),
		}, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Fprintf(os.Stderr, "error [%s]: %v\n", stage, err)
}

// labelKeyRe constrains a label key to something a consumer can use as a map key or a JSON
// field without quoting games.
var labelKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ParseLabels turns repeated --label key=value into the stored map. hcsctl assigns labels no
// meaning: they are stored, reported, and never interpreted (#31). Ownership and run identity
// are the consumer's policy -- record an owner pid, and scavenge only on proof it is dead.
//
// Values are stored verbatim, empty included -- unlike --env, nothing downstream deletes an
// empty value. A repeated key is a usage error, matching --id's duplicate rule.
//
// reserved is the caller's own state-document field names. A label may not shadow one, because
// a consumer that flattens the document would silently get the label instead of the field.
// Each verb group carries its own set, since each has its own state shape.
func ParseLabels(a *Args, reserved map[string]bool) (map[string]string, error) {
	vals := a.Options("--label")
	if len(vals) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(vals))
	for _, v := range vals {
		k, val, found := strings.Cut(v, "=")
		if !found || k == "" {
			return nil, Usagef("--label wants key=value, got %q", v)
		}
		if !labelKeyRe.MatchString(k) {
			return nil, Usagef("--label key %q -- keys are alphanumeric with ._- after the first character", k)
		}
		if reserved[k] {
			return nil, Usagef("--label key %q collides with a field the state document already carries", k)
		}
		if _, dup := labels[k]; dup {
			return nil, Usagef("--label %q given more than once", k)
		}
		labels[k] = val
	}
	return labels, nil
}
