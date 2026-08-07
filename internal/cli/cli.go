// Package cli holds the pieces every verb group shares: argument parsing, output, exit codes.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
var repeatable = map[string]bool{"--env": true, "--mount": true, "--parent": true}

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
	ok := map[string]bool{"--json": true}
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
type Emit struct{ JSON bool }

func (e Emit) Progress(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if e.JSON {
		fmt.Fprintln(os.Stderr, msg)
	} else {
		fmt.Fprintln(os.Stdout, msg)
	}
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
