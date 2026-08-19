# Copy to a file of your own and fill in. Then:
#   packer init .
#   packer build -var-file=example.pkrvars.hcl .

iso_path      = "C:/isos/Rocky-10-x86_64-dvd.iso"
iso_checksum  = "none"
root_password = "change-me"

# Download hcsguest-linux-amd64 and its SHA256SUMS line from the hcsctl release whose tag
# matches your host hcsctl, then point at the local file and paste its checksum here.
guest_agent_path   = "C:/artifacts/hcsguest-linux-amd64"
guest_agent_sha256 = "89819C256C5F5431927107FDC45F37636BCCC28B851020CAE3EE453EAFD091B1"
