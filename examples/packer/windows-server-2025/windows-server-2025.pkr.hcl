# Example: bake the hcsguest agent into a Windows Server 2025 image with Packer.
#
# The point of this example is the agent-install step, not the OS install. It runs the SAME
# script a user runs by hand -- install/Install-HcsGuest.ps1 -- so there is no second copy of
# the install logic to keep in step with the installer. Everything above that (ISO, answer
# file) is ordinary example scaffolding; replace it with your own base-image process.
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
  description = "Path to a Windows Server 2025 ISO. Example scaffolding: how you obtain it is out of scope."
}

variable "iso_checksum" {
  type    = string
  default = "none"
}

variable "admin_password" {
  type        = string
  description = "Administrator password for the build VM. A test fixture, not a secret store. Avoid & < > \" ' -- the value is written into XML."
  sensitive   = true
}

variable "image_name" {
  type        = string
  description = "Exact edition name in install.wim; a Server ISO holds several."
  default     = "Windows Server 2025 Standard"
}

variable "guest_agent_path" {
  type        = string
  description = "Path on the build host to the windows/amd64 hcsguest.exe (release asset hcsguest-windows-amd64.exe)."
}

variable "guest_agent_sha256" {
  type        = string
  description = "SHA-256 of guest_agent_path, from the release SHA256SUMS. The installer refuses a mismatch."
}

variable "output_directory" {
  type    = string
  default = "output/windows-server-2025"
}

variable "vm_name" {
  type    = string
  default = "windows-server-2025-hcsguest"
}

variable "switch_name" {
  type    = string
  default = "Default Switch"
}

variable "headless" {
  type    = bool
  default = true
}

source "hyperv-iso" "server-2025" {
  iso_url      = var.iso_path
  iso_checksum = var.iso_checksum

  generation         = 2
  enable_secure_boot = false

  memory                = 4096
  cpus                  = 4
  enable_dynamic_memory = false
  disk_size             = 40960
  switch_name           = var.switch_name
  headless              = var.headless

  # Windows Setup searches removable media for Autounattend.xml. cd_content templates it so
  # the password is not written to the repo.
  cd_label = "UNATTEND"
  cd_content = {
    "Autounattend.xml" = templatefile("${path.root}/answer/Autounattend.pkrtpl.xml", {
      admin_password = var.admin_password
      image_name     = var.image_name
    })
  }

  boot_wait    = "2s"
  boot_command = ["<enter>"]

  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.admin_password
  winrm_use_ntlm = true
  winrm_timeout  = "60m"

  shutdown_command = "shutdown /s /t 5 /f /d p:4:1 /c \"packer shutdown\""
  shutdown_timeout = "15m"

  skip_export     = true
  skip_compaction = false
  keep_registered = false

  output_directory = var.output_directory
  vm_name          = var.vm_name
}

build {
  name    = "windows-server-2025-hcsguest"
  sources = ["source.hyperv-iso.server-2025"]

  # Stage the installer and the pinned artifact into the guest.
  provisioner "file" {
    source      = "${path.root}/../../../install/Install-HcsGuest.ps1"
    destination = "C:/Windows/Temp/Install-HcsGuest.ps1"
  }
  provisioner "file" {
    source      = var.guest_agent_path
    destination = "C:/Windows/Temp/hcsguest.exe"
  }

  # Run the real installer. -Path is the local artifact, -Sha256 pins the checksum. The
  # installer verifies the binary's version stamp, registers the Windows service, starts it,
  # and fails this build if it does not reach Running.
  provisioner "powershell" {
    inline = [
      "& C:/Windows/Temp/Install-HcsGuest.ps1 -Path C:/Windows/Temp/hcsguest.exe -Sha256 ${var.guest_agent_sha256}",
    ]
  }

  # Prove the service survives a reboot.
  provisioner "windows-restart" {}

  provisioner "powershell" {
    inline = [
      "$s = Get-Service hcsguest",
      "if ($s.Status -ne 'Running') { throw \"hcsguest is $($s.Status) after reboot, not Running\" }",
      "Write-Output 'hcsguest Running after reboot'",
    ]
  }

  # After the image boots under HCS, verify host reachability from the host itself:
  #   hcsctl guest info --vmid <guid>
  # That check cannot run inside the Packer build; the build VM is not an HCS compute system.
}
