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
	if err := optionShaped(o.name, s); err != nil {
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
	if err := optionShaped(a.name, s); err != nil {
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

// argv is what optionShaped scans for the = spelling; a variable so tests can plant one.
var argv = func() []string { return os.Args[1:] }

// optionShaped guards the space form against a forgotten value: pflag hands the next
// argument over as the value no matter what it looks like, so `--cmd --json` would silently
// swallow --json -- the exact drift this package exists to prevent, and exit 64 promises
// nothing was attempted. A value that genuinely begins with -- is still expressible: the
// = spelling is unambiguous, so `--cmd=--help` is accepted. pflag's Set carries no syntax
// context, hence the scan of the raw command line for the = token.
func optionShaped(name, s string) error {
	if !strings.HasPrefix(s, "--") {
		return nil
	}
	if slices.Contains(argv(), "--"+name+"="+s) {
		return nil
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

// Group builds a verb-group command. cobra routes to the verbs; a bare group or an unknown
// verb is a usage error naming the verbs that exist. Without the RunE, cobra would print
// help and exit 0 for a bare group, and exit 1 for an unknown verb.
func Group(use, short string, verbs ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ArbitraryArgs,
		// A group has no local flags, so a flag reaching it rode behind a mistyped verb
		// (`vm frobnicate --id x`). Strict parsing would report the flag; allowing unknown
		// flags lets the RunE name the actual mistake, the verb. Leaf verbs stay strict --
		// the allowance is per-command, not inherited.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return Usagef("%s needs a subcommand: %s", c.Name(), SubcommandNames(c))
			}
			return Usagef("unknown %s subcommand %q (expected %s)", c.Name(), args[0], SubcommandNames(c))
		},
	}
	cmd.AddCommand(verbs...)
	return cmd
}
