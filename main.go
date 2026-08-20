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
	"os"
	"strconv"
	"strings"

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
)

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	// Read --json off argv, not off the parse: a malformed command line must still be
	// reported in the shape the caller asked for. pflag also accepts --json=<bool>, so the
	// scan must too -- via the same strconv.ParseBool pflag uses -- or the form would be
	// accepted and silently ignored.
	wantJSON, wantStream := false, false
	scanBool := func(a, name string, dst *bool) {
		if a == name {
			*dst = true
		} else if rest, ok := strings.CutPrefix(a, name+"="); ok {
			if v, err := strconv.ParseBool(rest); err == nil {
				*dst = v
			}
		}
	}
	for _, a := range argv {
		scanBool(a, "--json", &wantJSON)
		scanBool(a, "--stream-json", &wantStream)
	}
	e := cli.Emit{JSON: wantJSON, StreamJSON: wantStream}

	// version is answered before cobra runs so `hcsctl --version --json` keeps the
	// one-document contract; cobra's own --version handling prints bare text. Leading
	// position only: an option's *value* may be the string "--version".
	if len(argv) > 0 && (argv[0] == "--version" || argv[0] == "version") {
		return versionCmd(e)
	}

	root := newRoot(e)
	root.SetArgs(argv)
	cmd, err := root.ExecuteC()
	if err == nil {
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

func newRoot(e cli.Emit) *cobra.Command {
	root := &cobra.Command{
		Use:   "hcsctl <group> <verb> [options]",
		Short: "a CLI over the Windows Host Compute Service",
		Long: `hcsctl -- a CLI over the Windows Host Compute Service

exit codes: 0 ok, 1 ran and failed, 64 bad arguments (nothing attempted)
            a guest process's own exit code is reported as exitCode in the result, not as
            hcsctl's exit code`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cli.Usagef("a verb group is required (image, layer, container, vm, guest, network, storage, info)")
			}
			return cli.Usagef("unknown verb group %q (expected: image, layer, container, vm, guest, network, storage, info)", args[0])
		},
		// The contract owns error reporting: one document on stdout under --json, the
		// message and usage on stderr. cobra's own printing would break both.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	pf := root.PersistentFlags()
	// The values are read off raw argv in run(), before parsing, so a malformed command
	// line is still reported in the requested shape. Declared here so cobra accepts and
	// documents them.
	pf.Bool("json", false, "one JSON document on stdout; progress on stderr")
	pf.Bool("stream-json", false, "with --json: stderr becomes NDJSON, one object per line, so a consumer following a long exec can attribute every line -- {\"stream\":\"progress\"} is hcsctl, {\"stream\":\"stdout\"|\"stderr\"} is the guest, per line, live. The final document is unchanged")

	root.AddCommand(
		image.Command(e),
		layer.Command(e),
		container.Command(e),
		storage.Command(e),
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

	// Requested help honours the output contract: exit 0, help on stdout, one document
	// under --json. The usage text that accompanies an error stays on stderr.
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		var b strings.Builder
		if long := strings.TrimRight(c.Long, "\n"); long != "" {
			b.WriteString(long + "\n\n")
		} else if c.Short != "" {
			b.WriteString(c.Short + "\n\n")
		}
		b.WriteString(c.UsageString())
		text := b.String()
		e.Result(map[string]any{"ok": true, "command": "help", "usage": text}, func() {
			fmt.Print(text)
		})
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
