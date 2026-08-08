// Package guestproto is the wire contract between hcsctl on the host and hcsguest inside a
// guest VM. Both halves import it, so the contract cannot drift between them -- that is the
// whole reason the agent lives in this repo rather than beside the image templates (#40).
//
// It is deliberately free of build tags and of any Windows or Linux import, so the same
// definitions compile into a Linux guest binary.
package guestproto

import "time"

// ServiceID is the Hyper-V socket service the agent binds and the host dials. Measured in
// #37: a service GUID needs no registration under GuestCommunicationServices for a host to
// reach it, so this value is ours to choose and nothing else has to know it.
const ServiceID = "b7a4e3c6-8f21-4d5e-9c30-2a6f1b8d4e57"

// VsockPort is the Linux equivalent. A Linux guest listens on AF_VSOCK and the host maps the
// port through the VSOCK template GUID, so the two guests are reached the same way from the
// caller's point of view but do not share an address.
const VsockPort = 5731

// Protocol is the wire version. A mismatch is a hard failure and is never negotiated: nothing
// in this workspace has users, so an old agent is a bug to fix rather than a case to support.
const Protocol = 1

// Request is one JSON object, newline-terminated, sent as the first thing on a connection.
// One request per connection, no multiplexing -- hvsocket connections are cheap and a
// multiplexer is where the defects would live.
type Request struct {
	Protocol int    `json:"protocol"`
	Verb     string `json:"verb"`

	// Port is the guest-side TCP port for the forward verb. The agent dials it on loopback
	// inside the guest, which is why a forward is not subject to the guest firewall.
	Port int `json:"port,omitempty"`
}

// ForwardOK is the agent's reply to a forward request, sent before any payload. The caller
// needs to know the guest side connected before it starts copying, so a failed connect
// surfaces as an error rather than as a connection that accepts bytes and drops them.
type ForwardOK struct {
	OK       bool   `json:"ok"`
	Protocol int    `json:"protocol"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

// Address is what the guest believes about its own addressing. This is the field that
// removes the ~14 s DHCP-lease poll on the host: the guest already knows.
type Address struct {
	Interface string `json:"interface"`
	Address   string `json:"address"` // CIDR
	Family    string `json:"family"`  // ipv4 or ipv6
}

// Info answers readiness and addressing together, which is why it is the first verb. A
// successful read of this document means the guest booted, the transport is up, and the
// agent is serving -- three things the host otherwise infers separately and slowly.
type Info struct {
	OK            bool      `json:"ok"`
	Protocol      int       `json:"protocol"`
	AgentVersion  string    `json:"agentVersion"`
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
