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

// NoExtraArgs rejects stray positionals as a usage error. cobra's own NoArgs returns a plain
// error, which would exit 1 -- but nothing was attempted, so this must be 64.
func NoExtraArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return Usagef("unexpected argument %q", args[0])
	}
	return nil
}

// Group builds a verb-group command. cobra routes to the verbs; a bare group or an unknown
// verb is a usage error naming the verbs that exist. Without the RunE, cobra would print
// help and exit 0 for a bare group, and exit 1 for an unknown verb.
func Group(use, short string, verbs ...*cobra.Command) *cobra.Command {
	name := strings.Fields(use)[0]
	names := make([]string, len(verbs))
	for i, v := range verbs {
		names[i] = v.Name()
	}
	list := strings.Join(names, ", ")
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return Usagef("%s needs a subcommand: %s", name, list)
			}
			return Usagef("unknown %s subcommand %q (expected %s)", name, args[0], list)
		},
	}
	cmd.AddCommand(verbs...)
	return cmd
}
