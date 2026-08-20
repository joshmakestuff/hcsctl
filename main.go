//go:build windows

// hcsctl is a CLI over the Windows Host Compute Service, built on Microsoft/hcsshim.
//
// It surfaces HCS -- images, layers, compute systems, networking -- as a tool you can drive
// from a shell or an agent.
//
// Two rules this repo is built to:
//
//	Public hcsshim packages only. pkg/*, the hcsshim root package, computestorage, osversion.
//	Where hcsshim exports no public equivalent -- the v2 compute-system API that `vm` needs --
//	bind the documented Windows entry point in vmcompute.dll directly. Copying or vendoring
//	hcsshim's internal/ source is out.
//
//	Every verb honours the same contract: --json puts exactly one document on stdout with
//	progress on stderr, and exit codes mean 0 ok, 1 ran and failed, 64 bad arguments with
//	nothing attempted.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/joshmakestuff/hcsctl/internal/cim"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/joshmakestuff/hcsctl/internal/container"
	"github.com/joshmakestuff/hcsctl/internal/guest"
	"github.com/joshmakestuff/hcsctl/internal/image"
	"github.com/joshmakestuff/hcsctl/internal/layer"
	"github.com/joshmakestuff/hcsctl/internal/network"
	"github.com/joshmakestuff/hcsctl/internal/storage"
	"github.com/joshmakestuff/hcsctl/internal/sysinfo"
	"github.com/joshmakestuff/hcsctl/internal/vm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// scanOutputFlags reads --json/--stream-json before cobra runs, so a malformed command line
// is still reported in the shape the caller asked for. The pre-parse is pflag itself --
// unknown flags whitelisted, everything else its real grammar, = forms and the -- terminator
// included -- so it cannot drift from the parse cobra performs later.
func scanOutputFlags(argv []string) cli.Emit {
	fs := pflag.NewFlagSet("hcsctl", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.Usage = func() {}
	fs.SetOutput(io.Discard)
	wantJSON := fs.Bool("json", false, "")
	wantStream := fs.Bool("stream-json", false, "")
	// Declared so an undeclared --help/-h cannot abort this parse with pflag's ErrHelp
	// before a later --json is reached; the value is cobra's to act on.
	fs.BoolP("help", "h", false, "")
	// A parse error (--json=notabool) leaves the defaults standing; cobra reports it.
	_ = fs.Parse(argv)
	return cli.Emit{JSON: *wantJSON, StreamJSON: *wantStream}
}

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	e := scanOutputFlags(argv)

	// cobra registers its hidden completion machinery at Execute time with no option to
	// suppress it, and its output is shell script on stdout -- a contract break under
	// --json. Rejected here, before cobra ever sees it. The scan skips leading flags
	// because cobra does too: `--json __complete ...` resolves the hidden command just as
	// well as a bare one. Global flags are all booleans, so the first non-flag token is
	// the group word, never a flag's value.
	for _, a := range argv {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == cobra.ShellCompRequestCmd || a == cobra.ShellCompNoDescRequestCmd {
			e.Failure("usage", fmt.Errorf("shell completion is not supported"))
			return cli.Usage
		}
		break
	}

	helpRequested := false
	root := newRoot(e, &helpRequested)
	root.SetArgs(argv)
	cmd, err := root.ExecuteC()
	if err == nil {
		if helpRequested {
			// The help text is on stderr and the verb never ran. Exit 64 keeps the safe
			// signal for a script that forwarded a stray --help into a real invocation:
			// exit 0 is never emitted without the verb having run.
			e.Failure("usage", fmt.Errorf("help requested; nothing attempted"))
			return cli.Usage
		}
		return cli.OK
	}
	if errors.Is(err, cli.ErrReported) {
		return cli.Failed
	}
	var ue *cli.UsageError
	if errors.As(err, &ue) {
		// Failure before usage, so the one document is first on stdout under --json; the
		// usage text accompanies the error on stderr, where it has always lived.
		e.Failure("usage", err)
		fmt.Fprint(os.Stderr, cmd.UsageString())
		return cli.Usage
	}
	e.Failure("run", err)
	return cli.Failed
}

func newRoot(e cli.Emit, helpRequested *bool) *cobra.Command {
	root := &cobra.Command{
		Use:   "hcsctl <group> <verb> [options]",
		Short: "a CLI over the Windows Host Compute Service",
		Long: `hcsctl -- a CLI over the Windows Host Compute Service

exit codes: 0 ok, 1 ran and failed, 64 bad arguments (nothing attempted)
            a guest process's own exit code is reported as exitCode in the result, not as
            hcsctl's exit code`,
		// No completion command: its output is shell script on stdout, which the --json
		// contract cannot admit. The hidden __complete twin is rejected in run().
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		// An unknown flag at the root rode behind a mistyped group (`hcsctl frobnicate
		// --id x`); allowing it lets the RunE name the group, the actual mistake, exactly
		// as cli.Group does for verbs.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		Args:               cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				// --version is a root-local flag, not cobra's Version field: cobra's own
				// handling prints bare text, which would break the --json contract. Local,
				// not persistent, so a verb given --version rejects it instead of silently
				// ignoring it.
				if v, _ := c.Flags().GetBool("version"); v {
					versionCmd(e)
					return nil
				}
				return cli.Usagef("a verb group is required (%s)", cli.SubcommandNames(c))
			}
			return cli.Usagef("unknown verb group %q (expected: %s)", args[0], cli.SubcommandNames(c))
		},
		// The contract owns error reporting: one document on stdout under --json, the
		// message and usage on stderr. cobra's own printing would break both.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	pf := root.PersistentFlags()
	// The values are read by scanOutputFlags before cobra runs, so a malformed command
	// line is still reported in the requested shape. Declared here so cobra accepts and
	// documents them.
	pf.Bool("json", false, "one JSON document on stdout; progress on stderr")
	pf.Bool("stream-json", false, "with --json: stderr becomes NDJSON, one object per line, so a consumer following a long exec can attribute every line -- {\"stream\":\"progress\"} is hcsctl, {\"stream\":\"stdout\"|\"stderr\"} is the guest, per line, live. The final document is unchanged")
	root.Flags().Bool("version", false, "the tool and contract versions")

	root.AddCommand(
		image.Command(e),
		layer.Command(e),
		container.Command(e),
		storage.Command(e),
		cim.Command(e),
		network.Command(e),
		vm.Command(e),
		guest.Command(e),
		sysinfo.Command(e),
		versionCommand(e),
	)

	// pflag's parse errors (unknown option, missing value, given more than once) mean bad
	// arguments with nothing attempted: exit 64.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return cli.Usagef("%v", err)
	})

	// Requested help means nothing was attempted, so it is exit 64 like every other
	// command line that ran no verb: the full help text on stderr, where usage has always
	// lived, and run() emits the one failure document under --json. Exit 0 with help would
	// let a forwarded --help make a script record a verb as succeeded when it never ran.
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		*helpRequested = true
		var b strings.Builder
		if long := strings.TrimRight(c.Long, "\n"); long != "" {
			b.WriteString(long)
			b.WriteString("\n\n")
		} else if c.Short != "" {
			b.WriteString(c.Short)
			b.WriteString("\n\n")
		}
		b.WriteString(c.UsageString())
		fmt.Fprint(os.Stderr, b.String())
	})

	// cobra's default help command exits 0 even for an unknown topic. This one routes a
	// known topic through the help func above; either way the exit-64 rule holds.
	root.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "help about any command",
		RunE: func(_ *cobra.Command, args []string) error {
			target, rest, _ := root.Find(args)
			if len(rest) > 0 {
				return cli.Usagef("unknown help topic %q", strings.Join(args, " "))
			}
			return target.Help()
		},
	})

	root.SetUsageTemplate(usageTemplate)
	disableFlagsInUseLine(root)
	return root
}

// disableFlagsInUseLine keeps " [flags]" out of every use line: each command's Use string
// already carries its synopsis.
func disableFlagsInUseLine(c *cobra.Command) {
	c.DisableFlagsInUseLine = true
	for _, sub := range c.Commands() {
		disableFlagsInUseLine(sub)
	}
}

// usageTemplate is cobra's default reshaped to this tool's voice: the usage line is
// lowercase and inline (a consumer's contract test greps for "usage: hcsctl").
const usageTemplate = `usage: {{.UseLine}}{{if .HasAvailableSubCommands}}

commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

options:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

global options:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} <command> --help" for more information about a command.{{end}}
`

func versionCommand(e cli.Emit) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "the tool and contract versions",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			versionCmd(e)
			return nil
		},
	}
}

func versionCmd(e cli.Emit) int {
	e.Result(map[string]any{
		"ok": true, "command": "version",
		"toolVersion": cli.ToolVersion, "contractVersion": cli.ContractVersion,
	}, func() {
		fmt.Printf("hcsctl %s (contract %s)\n", cli.ToolVersion, cli.ContractVersion)
	})
	return cli.OK
}
