//go:build windows

package guest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// ApplyNetConfig sends a netconfig request to a VM's agent and returns the guest's post-apply
// attestation. Used by `vm netconfig`.
func ApplyNetConfig(vmid guid.GUID, nc guestproto.NetConfig, timeout time.Duration) (*guestproto.NetConfigResult, error) {
	svc, err := serviceFor(vmid, timeout)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := winio.Dial(ctx, &winio.HvsockAddr{VMID: vmid, ServiceID: svc})
	if err != nil {
		return nil, fmt.Errorf("dial guest: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req, _ := json.Marshal(guestproto.Request{
		Protocol:  guestproto.Protocol,
		Verb:      "netconfig",
		NetConfig: &nc,
	})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("send netconfig: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("read netconfig result: %w", err)
	}
	var res guestproto.NetConfigResult
	if err := json.Unmarshal(line, &res); err != nil {
		return nil, fmt.Errorf("agent sent something that is not a document: %v", err)
	}
	if !res.OK {
		var f guestproto.Failure
		_ = json.Unmarshal(line, &f)
		return nil, fmt.Errorf("agent refused netconfig: %s", f.Error)
	}
	return &res, nil
}
