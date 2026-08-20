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

// ContractVersion is the number a consumer's preflight checks. Bump it when the shape of a
// result document changes, a field's meaning changes, or an exit code's meaning changes --
// and ONLY then. Adding a new verb, option, or document field is not a bump: a consumer
// reading fields it knows keeps working.
// "2": requested help became exit 64 with a usage-failure document (it was exit 0 with an
// ok:true help document) -- an exit code's meaning changed.
const ContractVersion = "2"

// ToolVersion identifies the build for humans in a bug report. Release builds stamp it:
//
//	go build -ldflags "-X github.com/joshmakestuff/hcsctl/internal/cli.ToolVersion=v0.2.0" .
//
// A dev build reports "dev".
var ToolVersion = "dev"

// ErrReported is returned by a verb that already emitted its one result document and
// failed: exit 1 with nothing further, because a second document would break the
// one-document contract.
var ErrReported = errors.New("failed; already reported")

// UsageError means the command line was wrong and nothing was attempted.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func Usagef(format string, a ...any) error {
	return &UsageError{Msg: fmt.Sprintf(format, a...)}
}

// Require rejects a required option that was not given. The caller holds the value in a
// flag-bound variable; empty means unset, because no option here accepts an empty value.
func Require(name, value string) error {
	if value == "" {
		return Usagef("%s is required", name)
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

// ParseUint is the bounded numeric parser: every numeric option names the range its sink
// accepts, so overflow is exit 64 instead of a silent wrap. The error text is written to read
// after an option name: Usagef("--cpus %v", err).
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

// ParseSize turns a human size -- "40GB", "40960MB" -- into bytes. The unit is required.
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
	// rejected with a number in that unit.
	n, err := ParseUint(digits, maxSizeBytes/mult)
	if err != nil {
		return 0, Usagef("size %q: %v", s, err)
	}
	return n * mult, nil
}

// Emit is the output sink. In JSON mode stdout carries exactly one document and progress goes
// to stderr, so a consumer never has to scrape.
//
// With StreamJSON, everything on stderr is NDJSON -- one object per line -- so a consumer
// following a long-running exec can attribute every line without matching on message text.
// {"stream":"progress","msg":...} is hcsctl's own voice; guest output is framed as
// {"stream":"stdout"|"stderr","data":...}. Takes effect only alongside JSON mode: without
// --json human output stays human.
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

// NewStreamWriter frames one guest stream as NDJSON lines. Complete lines are emitted as
// they arrive, without their line ending; a partial line is buffered to the next write, so a
// rune split across reads is not mangled, capped at 64 KB. Close flushes the remainder.
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

// StreamLogLine frames one retained-log line (`container logs --follow`). The stream is
// "log", not "stdout"/"stderr": primary.log merges the guest's two streams, so per-stream
// attribution is not available once output is replayed from the file.
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
// meaning: they are stored, reported, and never interpreted.
//
// Values are stored verbatim, empty included. A repeated key is a usage error.
//
// reserved is the caller's own state-document field names. A label may not shadow one: a
// consumer that flattens the document would get the label instead of the field. Each verb
// group carries its own set.
func ParseLabels(vals []string, reserved map[string]bool) (map[string]string, error) {
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
