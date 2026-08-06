// Package cli holds the pieces every verb group shares: argument parsing, output, exit codes.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Exit codes. 64 is EX_USAGE from sysexits.h.
const (
	OK     = 0
	Failed = 1
	Usage  = 64
)

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
