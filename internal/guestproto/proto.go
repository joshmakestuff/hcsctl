// Package guestproto is the wire contract between hcsctl on the host and hcsguest inside a
// guest VM. Both halves import it, so the contract cannot drift between them.
//
// It has no build tags and no Windows or Linux import, so the same definitions compile into
// a Linux guest binary.
package guestproto

import "time"

// ServiceID is the Hyper-V socket service the agent binds and the host dials. A service GUID
// needs no registration under GuestCommunicationServices for a host to reach it.
const ServiceID = "b7a4e3c6-8f21-4d5e-9c30-2a6f1b8d4e57"

// VsockPort is the Linux equivalent. A Linux guest listens on AF_VSOCK and the host maps the
// port through the VSOCK template GUID, so the two guests are reached the same way from the
// caller's point of view but do not share an address.
const VsockPort = 5731

// Protocol is the wire version. A mismatch is a hard failure and is never negotiated.
//
// Adding a verb is not a bump: an old agent answers an unknown verb with a Failure document
// naming it. The number moves only when an existing verb's wire shape or meaning changes.
const Protocol = 1

// Request is one JSON object, newline-terminated, sent as the first thing on a connection.
// One request per connection, no multiplexing.
type Request struct {
	Protocol int    `json:"protocol"`
	Verb     string `json:"verb"`

	// Port is the guest-side TCP port for the forward verb. The agent dials it on loopback
	// inside the guest, so a forward is not subject to the guest firewall.
	Port int `json:"port,omitempty"`

	// Command is the exec verb's command line, run by the guest's own shell: cmd.exe /c on
	// Windows, /bin/sh -c on Linux. A single line, not an argv, matching
	// `hcsctl container exec --cmd`.
	Command string `json:"command,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	// Env entries are NAME=value, added to the guest's own environment, not replacing it.
	Env []string `json:"env,omitempty"`
	// TimeoutSeconds kills the process in the guest on expiry. Enforced guest-side as well as
	// host-side, so a host that gives up does not leave the process running forever.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// NetConfig is the netconfig verb's payload.
	NetConfig *NetConfig `json:"netConfig,omitempty"`

	// Mount is the mount verb's payload; Unmount is the unmount verb's.
	Mount   *Mount   `json:"mount,omitempty"`
	Unmount *Unmount `json:"unmount,omitempty"`
}

// Mount asks the agent to attach an SMB share at Path inside the guest. The host reaches its
// own SMB server at the guest's gateway; the credential authenticates to it.
//
// UNC is the Windows spelling, `\\host\share\sub`. The Linux agent rewrites it to
// `//host/share/sub` for cifs; the Windows agent connects the `\\host\share` root and puts a
// directory symlink at Path pointing at the full UNC.
//
// The password travels the host-to-guest hvsocket, not a network. It never appears on a host
// command line: hcsctl reads it from Windows Credential Manager (or stdin) and puts it here.
type Mount struct {
	UNC      string `json:"unc"`
	Path     string `json:"path"`
	User     string `json:"user"`
	Password string `json:"password"`
	ReadOnly bool   `json:"readOnly,omitempty"`
	// UID and GID map ownership for the Linux cifs mount. Zero means the cifs default (the
	// mounting user, root). Ignored on Windows.
	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
}

// MountResult reports what the agent did. Applied names the mechanism: "cifs" on Linux,
// "wnet+symlink" on Windows.
type MountResult struct {
	OK       bool   `json:"ok"`
	Protocol int    `json:"protocol"`
	Applied  string `json:"applied"`
	Path     string `json:"path"`
	UNC      string `json:"unc"`
	ReadOnly bool   `json:"readOnly"`
}

// Unmount asks the agent to detach the mount at Path. Only the mount point is named; the
// agent undoes whatever it did for that path.
type Unmount struct {
	Path string `json:"path"`
}

// UnmountResult reports what the agent undid. Applied is "umount" on Linux, "symlink" on
// Windows (the directory symlink is removed; the share connection is left for the guest's
// lifetime, shared with any sibling mount of the same share).
type UnmountResult struct {
	OK       bool   `json:"ok"`
	Protocol int    `json:"protocol"`
	Applied  string `json:"applied"`
	Path     string `json:"path"`
}

// NetConfig asks the agent to program an interface with the addressing the host already
// knows: on an hcsctl-owned network, HNS allocates the endpoint's address at create and no
// DHCP server exists to deliver it, so the host sends it through this verb.
//
// The agent applies it through the guest's own network mechanism, never around it. An
// address added with raw `ip addr add` is torn down when NetworkManager's DHCP transaction
// fails 45 s later; a connection-profile change holds. On Windows, netsh static config
// holds, because manual assignment itself moves the interface off DHCP.
type NetConfig struct {
	// Interface is the connection to modify. Empty means the guest's default: eth0 on Linux
	// (a single-NIC guest without predictable interface names), the single connected adapter
	// on Windows.
	Interface string `json:"interface,omitempty"`
	// Addresses in CIDR form. At least one is required.
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
}

// NetConfigResult reports what the guest observes AFTER applying, not what was requested.
type NetConfigResult struct {
	OK       bool `json:"ok"`
	Protocol int  `json:"protocol"`
	// Applied names the mechanism, e.g. "nmcli".
	Applied   string    `json:"applied"`
	Addresses []Address `json:"addresses"`
}

// ForwardOK is the agent's reply to a forward request, sent before any payload, so the caller
// knows the guest side connected before it starts copying.
type ForwardOK struct {
	OK       bool   `json:"ok"`
	Protocol int    `json:"protocol"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

// Address is what the guest believes about its own addressing.
type Address struct {
	Interface string `json:"interface"`
	Address   string `json:"address"` // CIDR
	Family    string `json:"family"`  // ipv4 or ipv6
}

// Info answers readiness and addressing together. A successful read of this document means
// the guest booted, the transport is up, and the agent is serving.
type Info struct {
	OK           bool   `json:"ok"`
	Protocol     int    `json:"protocol"`
	AgentVersion string `json:"agentVersion"`
	// AgentCommit is the hcsctl commit the agent was built from: which agent a guest is
	// actually running.
	AgentCommit   string    `json:"agentCommit"`
	OS            string    `json:"os"`
	OSVersion     string    `json:"osVersion"`
	Hostname      string    `json:"hostname"`
	BootTimeUTC   time.Time `json:"bootTimeUtc"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	Addresses     []Address `json:"addresses"`
}

// Failure is what the agent returns instead of a verb's document. It carries ok:false so a
// caller can discriminate on one field regardless of which verb it asked for.
type Failure struct {
	OK       bool   `json:"ok"`
	Protocol int    `json:"protocol"`
	Error    string `json:"error"`
}
