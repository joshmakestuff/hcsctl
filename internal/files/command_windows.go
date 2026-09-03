//go:build windows

package files

import (
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"github.com/spf13/cobra"
)

// Command is `hcsctl files`.
func Command(e cli.Emit) *cobra.Command {
	return cli.Group("files", "host-side SMB share for VM bind mounts",
		prepareCmd(e), inspectCmd(e), removeCmd(e),
		exposeCmd(e), unexposeCmd(e), lsCmd(e))
}

func exposeCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var name, source, root string
	var readOnly bool
	var labels []string
	cmd := &cobra.Command{
		Use:   "expose --vmid <guid> --name <n> --source <dir> [--ro] [--label k=v]... [--root <dir>]",
		Short: "expose a host directory to a VM under the share root (unelevated)",
		Long: `Expose a host directory to a VM: create a junction <root>\<vmid>\<name> to the
source and grant the share user access to it. Unelevated. The guest mounts \\<gateway>\<share>\<vmid>\<name>.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return expose(vmid.Value(), name, source, readOnly, labels, root, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID")
	cli.StringOnce(cmd.Flags(), &name, "name", "exposure name, unique per VM; becomes the last path element")
	cli.StringOnce(cmd.Flags(), &source, "source", "host directory to expose, a drive-letter absolute path")
	cli.Required(cmd, "vmid", "name", "source")
	cmd.Flags().BoolVar(&readOnly, "ro", false, "expose through the read-only share")
	cli.StringArray(cmd.Flags(), &labels, "label", "opaque key=value stored with the exposure, repeatable")
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	return cmd
}

func unexposeCmd(e cli.Emit) *cobra.Command {
	var vmid *cli.GUIDFlag
	var name, root string
	cmd := &cobra.Command{
		Use:   "unexpose --vmid <guid> [--name <n>] [--root <dir>]",
		Short: "remove a VM's exposures (unelevated)",
		Long: `Remove one exposure (--name) or all of a VM's exposures: delete the junction(s)
and revoke the share user's access when no other exposure still needs it. Unelevated.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return unexpose(vmid.Value(), name, root, e)
		},
	}
	vmid = cli.GUID(cmd.Flags(), "vmid", "the VM's id, a GUID")
	cli.Required(cmd, "vmid")
	cli.StringOnce(cmd.Flags(), &name, "name", "a single exposure to remove; absent removes all of the VM's")
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	return cmd
}

func lsCmd(e cli.Emit) *cobra.Command {
	var root string
	cmd := &cobra.Command{
		Use:   "ls [--root <dir>]",
		Short: "list VM exposures under the share root (unelevated)",
		Args:  cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return lsExposures(root, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	return cmd
}

func prepareCmd(e cli.Emit) *cobra.Command {
	var networks []string
	var root string
	cmd := &cobra.Command{
		Use:   "prepare --network <name>... [--root <dir>]",
		Short: "prepare the host for VM bind mounts (elevated, once)",
		Long: `Prepare the host for VM bind mounts. Elevated, once per host. Creates the
share root, a local user and its credential, a read-write and a read-only share over the root,
and an inbound TCP 445 firewall rule bound to each named network's host vNIC. Repeatable: it
adds any new networks to the rule and rotates the credential.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return prepare(networks, root, e)
		},
	}
	cli.StringArray(cmd.Flags(), &networks, "network", "hcsctl network whose guests may reach the share, repeatable")
	cli.Required(cmd, "network")
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	return cmd
}

func inspectCmd(e cli.Emit) *cobra.Command {
	var root string
	cmd := &cobra.Command{
		Use:   "inspect [--root <dir>]",
		Short: "report whether the host is prepared for VM bind mounts (unelevated)",
		Long: `Report whether the host is prepared for VM bind mounts. Unelevated; "not
prepared" is an answer, not a failure, so it exits 0.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return inspect(root, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	return cmd
}

func removeCmd(e cli.Emit) *cobra.Command {
	var root string
	var force bool
	cmd := &cobra.Command{
		Use:   "remove [--force] [--root <dir>]",
		Short: "undo files prepare (elevated)",
		Long: `Undo files prepare: remove the firewall rule, the shares, the credential, the
user, and the state file. Refuses while any VM exposure remains under the root unless --force.
The root directory is left when it still contains anything.`,
		Args: cli.NoExtraArgs,
		RunE: func(*cobra.Command, []string) error {
			if root == "" {
				root = DefaultRoot()
			}
			return remove(root, force, e)
		},
	}
	cli.StringOnce(cmd.Flags(), &root, "root", "share root directory (default %ProgramData%\\hcsctl\\files)")
	cmd.Flags().BoolVar(&force, "force", false, "remove even while VM exposures remain under the root")
	return cmd
}
