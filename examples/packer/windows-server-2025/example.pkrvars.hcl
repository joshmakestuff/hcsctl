# Copy to a file of your own and fill in. Then:
#   packer init .
#   packer build -var-file=example.pkrvars.hcl .

iso_path       = "C:/isos/windows-server-2025.iso"
iso_checksum   = "none"
admin_password = "change-me"
image_name     = "Windows Server 2025 Standard"

# Download hcsguest-windows-amd64.exe and its SHA256SUMS line from the hcsctl release whose
# tag matches your host hcsctl, then point at the local file and paste its checksum here.
guest_agent_path   = "C:/artifacts/hcsguest-windows-amd64.exe"
guest_agent_sha256 = "6FD6E8F47442DA430D6E7C18ECC3A9B967513C2AB12FA44C88CA30200971C217"
