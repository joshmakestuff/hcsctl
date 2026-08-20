// The cobra glue: what every command needs to keep the contract that cobra's defaults
// would break. Exit 64 rides on *UsageError, so everything argument-shaped that can fail
// here must fail with one.
package cli

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// StringOnce declares a string option that may be given at most once. pflag's own StringVar
// is last-one-wins, and a silently dropped value is how a command reaches the wrong target.
func StringOnce(fs *pflag.FlagSet, p *string, name, usage string) {
	fs.Var(&onceValue{p: p, name: name}, name, usage)
}

type onceValue struct {
	p    *string
	name string
	set  bool
}

func (o *onceValue) String() string { return *o.p }
func (o *onceValue) Type() string   { return "string" }

func (o *onceValue) Set(s string) error {
	if o.set {
		return errors.New("given more than once")
	}
	if err := optionShaped(o.name, s, 0); err != nil {
		return err
	}
	o.set = true
	*o.p = s
	return nil
}

// StringArray declares a repeatable string option. Like StringOnce it refuses a value that
// is spelled like an option.
func StringArray(fs *pflag.FlagSet, p *[]string, name, usage string) {
	fs.Var(&arrayValue{p: p, name: name}, name, usage)
}

type arrayValue struct {
	p    *[]string
	name string
}

func (a *arrayValue) String() string { return strings.Join(*a.p, ",") }
func (a *arrayValue) Type() string   { return "stringArray" }

func (a *arrayValue) Set(s string) error {
	if err := optionShaped(a.name, s, len(*a.p)); err != nil {
		return err
	}
	*a.p = append(*a.p, s)
	return nil
}

// Duration declares a duration option parsed and bounded at parse time, so a bad value is
// exit 64 through the flag-error path before any RunE runs, with one wording everywhere.
// def is the value when the option is absent; zero means the verb treats absence specially
// (unbounded, wait forever) and suppresses pflag's "(default ...)" in help. min is a floor
// beyond positive -- guest exec's wire protocol truncates to whole seconds, so it takes 1s;
// everything else passes 0 and accepts any positive duration.
func Duration(fs *pflag.FlagSet, p *time.Duration, name string, def, min time.Duration, usage string) {
	*p = def
	fs.Var(&durationValue{p: p, min: min}, name, usage)
}

type durationValue struct {
	p   *time.Duration
	min time.Duration
	set bool
}

func (d *durationValue) String() string {
	if *d.p == 0 {
		return ""
	}
	return d.p.String()
}
func (d *durationValue) Type() string { return "duration" }

func (d *durationValue) Set(s string) error {
	if d.set {
		return errors.New("given more than once")
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return errors.New("must be a positive duration, e.g. 10s")
	}
	if v < d.min {
		return fmt.Errorf("must be a duration of at least %s, e.g. 30s", d.min)
	}
	d.set = true
	*d.p = v
	return nil
}

// GUID declares an option whose value must be a GUID, parsed at Set time so a bad one is
// exit 64 through the flag-error path with one wording. A friendly name is never silently
// accepted: the GUID doubles as the VM's hvsocket address, so a non-GUID id would make a VM
// the printed id cannot reach. The handle carries both shapes a caller wants: Value() is the
// struct guest dials; Value().String() is the canonical rendering, which is what store paths
// must be built from, not the raw spelling. WasSet distinguishes absent from given for verbs
// that mint an id when none is offered.
func GUID(fs *pflag.FlagSet, name, usage string) *GUIDFlag {
	g := &GUIDFlag{}
	fs.Var(g, name, usage)
	return g
}

type GUIDFlag struct {
	v   guid.GUID
	set bool
}

func (g *GUIDFlag) String() string {
	if !g.set {
		return ""
	}
	return g.v.String()
}
func (g *GUIDFlag) Type() string { return "guid" }

func (g *GUIDFlag) Set(s string) error {
	if g.set {
		return errors.New("given more than once")
	}
	v, err := guid.FromString(s)
	if err != nil {
		return fmt.Errorf("not a GUID: %v", err)
	}
	g.v, g.set = v, true
	return nil
}

func (g *GUIDFlag) Value() guid.GUID { return g.v }
func (g *GUIDFlag) WasSet() bool     { return g.set }

// argv is what optionShaped scans for the = spelling; a variable so tests can plant one.
var argv = func() []string { return os.Args[1:] }

// optionShaped guards the space form against a forgotten value: pflag hands the next
// argument over as the value no matter what it looks like, so `--cmd --json` would silently
// swallow --json -- the exact drift this package exists to prevent, and exit 64 promises
// nothing was attempted. A value that genuinely begins with -- is still expressible: the
// = spelling is unambiguous, so `--cmd=--help` is accepted. pflag's Set carries no syntax
// context, so the check locates this Set's own occurrence -- the nth token spelling the
// flag -- in the raw command line and asks whether THAT token used the = form; a match
// anywhere else (an earlier =-spelled instance of a repeatable flag) proves nothing about
// this one.
func optionShaped(name, s string, occurrence int) error {
	if !strings.HasPrefix(s, "--") {
		return nil
	}
	long, eq := "--"+name, "--"+name+"="
	n := 0
	for _, a := range argv() {
		if a != long && !strings.HasPrefix(a, eq) {
			continue
		}
		if n == occurrence {
			if a == eq+s {
				return nil
			}
			break
		}
		n++
	}
	return fmt.Errorf("requires a value -- to pass a value beginning with --, write --%s=%s", name, s)
}

// Required marks the named options as required, checked before the verb's RunE runs with
// the same "--name is required" voice Require uses -- but declared beside the flags, so a
// flag the synopsis calls required cannot lack the check. Not cobra's MarkFlagRequired: its
// validation runs after PreRunE and returns a plain error, which would exit 1 -- nothing was
// attempted, so this must be 64.
func Required(cmd *cobra.Command, names ...string) {
	for _, n := range names {
		if cmd.Flags().Lookup(n) == nil {
			// A misspelled name would otherwise report "--x is required" forever; this is
			// a wiring bug, caught the first time the command is constructed.
			panic("cli.Required: no --" + n + " on " + cmd.Name())
		}
	}
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		for _, n := range names {
			// An explicitly empty value counts as absent, as cli.Require ruled: no option
			// here accepts an empty value.
			if f := c.Flags().Lookup(n); !f.Changed || f.Value.String() == "" {
				return Usagef("--%s is required", n)
			}
		}
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}

// NoExtraArgs rejects stray positionals as a usage error. cobra's own NoArgs returns a plain
// error, which would exit 1 -- but nothing was attempted, so this must be 64.
func NoExtraArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return Usagef("unexpected argument %q", args[0])
	}
	return nil
}

// SubcommandNames lists cmd's visible subcommands for a diagnostic. Derived from the
// registered commands, never hand-written, so the list a caller is offered cannot go stale.
// Hidden commands and help are not part of the surface being offered.
func SubcommandNames(cmd *cobra.Command) string {
	var names []string
	for _, c := range cmd.Commands() {
		if c.Hidden || c.Name() == "help" {
			continue
		}
		names = append(names, c.Name())
	}
	return strings.Join(names, ", ")
}

// Group builds a verb-group command. cobra routes to the verbs; anything that lands on the
// group itself -- a bare group, a mistyped verb, a flag or -- terminator ahead of the verb
// -- is a usage error naming the actual mistake. Flag parsing is disabled on the group: it
// has no flags of its own, and letting pflag run would consume the verb after an unknown
// boolean flag (`container --follow logs` would eat "logs" as --follow's value) and
// misdiagnose the line as a bare group. With parsing off, the RunE reads the raw tokens.
// Leaf verbs parse strictly as ever.
func Group(use, short string, verbs ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:                use,
		Short:              short,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: func(c *cobra.Command, args []string) error {
			// Parsing is off, so --help is honoured by hand; Help() routes through the
			// root's help func and run() turns it into exit 64 like any other help.
			if slices.Contains(args, "--help") || slices.Contains(args, "-h") {
				return c.Help()
			}
			verb := ""
			for _, a := range args {
				if !strings.HasPrefix(a, "-") {
					verb = a
					break
				}
			}
			switch {
			case verb == "":
				return Usagef("%s needs a subcommand: %s", c.Name(), SubcommandNames(c))
			case hasVerb(c, verb):
				// The verb exists; a flag or -- ahead of it kept cobra from routing there.
				return Usagef("%s %s: the verb must come before any flags or -- (write: %s %s [options])",
					c.Name(), verb, c.CommandPath(), verb)
			default:
				return Usagef("unknown %s subcommand %q (expected %s)", c.Name(), verb, SubcommandNames(c))
			}
		},
	}
	cmd.AddCommand(verbs...)
	return cmd
}

func hasVerb(c *cobra.Command, name string) bool {
	for _, sub := range c.Commands() {
		if sub.Name() == name {
			return true
		}
	}
	return false
}
