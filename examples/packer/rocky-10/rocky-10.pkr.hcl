# Example: bake the hcsguest agent into a Rocky Linux 10 image with Packer.
#
# The point of this example is the agent-install step, not the OS install. It runs the SAME
# script a user runs by hand -- install/install-hcsguest.sh -- so there is no second copy of
# the install logic to keep in step with the installer. Everything above that (ISO, kickstart)
# is ordinary example scaffolding; replace it with your own base-image process.
#
# This is an example, not a supported hcsctl feature. It is written to `packer validate`
# cleanly; it has not been run end to end in CI.

packer {
  required_version = ">= 1.16.0"
  required_plugins {
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = "~> 1.1"
    }
  }
}

variable "iso_path" {
  type        = string
  description = "Path to a Rocky Linux 10 DVD ISO. Example scaffolding: how you obtain it is out of scope."
}

variable "iso_checksum" {
  type    = string
  default = "none"
}

variable "root_password" {
  type        = string
  description = "Root password for the build VM. A test fixture, not a secret store."
  sensitive   = true
}

variable "guest_agent_path" {
  type        = string
  description = "Path on the build host to the linux/amd64 hcsguest binary (release asset hcsguest-linux-amd64)."
}

variable "guest_agent_sha256" {
  type        = string
  description = "SHA-256 of guest_agent_path, from the release SHA256SUMS. The installer refuses a mismatch."
}

variable "output_directory" {
  type    = string
  default = "output/rocky-10"
}

variable "vm_name" {
  type    = string
  default = "rocky-10-hcsguest"
}

variable "switch_name" {
  type    = string
  default = "Default Switch"
}

variable "headless" {
  type    = bool
  default = true
}

source "hyperv-iso" "rocky-10" {
  iso_url      = var.iso_path
  iso_checksum = var.iso_checksum

  generation         = 2
  enable_secure_boot = false

  memory                = 2048
  cpus                  = 2
  enable_dynamic_memory = false
  disk_size             = 20480
  switch_name           = var.switch_name
  headless              = var.headless

  # Anaconda reads ks.cfg automatically from a volume labelled OEMDRV -- no boot_command
  # keystroke timing to get wrong.
  cd_label = "OEMDRV"
  cd_content = {
    "ks.cfg" = templatefile("${path.root}/ks/ks.pkrtpl.cfg", {
      root_password = var.root_password
    })
  }

  boot_wait    = "15s"
  boot_command = ["<up><enter>"]

  communicator = "ssh"
  ssh_username = "root"
  ssh_password = var.root_password
  ssh_timeout  = "60m"

  shutdown_command = "/sbin/shutdown -P now"
  shutdown_timeout = "15m"

  skip_export     = true
  skip_compaction = false
  keep_registered = false

  output_directory = var.output_directory
  vm_name          = var.vm_name
}

build {
  name    = "rocky-10-hcsguest"
  sources = ["source.hyperv-iso.rocky-10"]

  # Stage the installer and the pinned artifact into the guest.
  provisioner "file" {
    source      = "${path.root}/../../../install/install-hcsguest.sh"
    destination = "/tmp/install-hcsguest.sh"
  }
  provisioner "file" {
    source      = var.guest_agent_path
    destination = "/tmp/hcsguest-linux-amd64"
  }

  # Run the real installer. -p is the local-artifact path, -s pins the checksum. The installer
  # itself verifies the binary's version stamp, registers the systemd unit, starts it, and
  # fails this build if the service does not come up.
  provisioner "shell" {
    inline = [
      "sh /tmp/install-hcsguest.sh -p /tmp/hcsguest-linux-amd64 -s ${var.guest_agent_sha256}",
    ]
  }

  # Prove the unit survives a reboot: reboot, let SSH drop, then reconnect and assert active.
  provisioner "shell" {
    expect_disconnect = true
    inline            = ["systemctl reboot"]
  }
  provisioner "shell" {
    pause_before = "20s"
    inline = [
      "systemctl is-active --quiet hcsguest.service || { journalctl -u hcsguest.service --no-pager -n 40; exit 1; }",
      "echo 'hcsguest active after reboot'",
    ]
  }

  # After the image boots under HCS, verify host reachability from the host itself:
  #   hcsctl guest info --vmid <guid>
  # That check cannot run inside the Packer build; the build VM is not an HCS compute system.
}
