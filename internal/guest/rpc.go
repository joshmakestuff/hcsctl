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

// call sends one request to a VM's agent and unmarshals the single-document reply into T. It
// is the shared body of the single-shot verbs (netconfig, mount, unmount): dial the service,
// write the request line, read one line back, and fail on an agent Failure or a non-document.
//
// The reply is probed for ok before unmarshalling into T, so an agent Failure becomes an
// error naming the verb rather than a T with a zero OK field.
func call[T any](vmid guid.GUID, req guestproto.Request, timeout time.Duration) (*T, error) {
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
	body, _ := json.Marshal(req)
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("send %s: %w", req.Verb, err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("read %s result: %w", req.Verb, err)
	}

	var probe struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal(line, &probe)
	if !probe.OK {
		var f guestproto.Failure
		_ = json.Unmarshal(line, &f)
		return nil, fmt.Errorf("agent refused %s: %s", req.Verb, f.Error)
	}

	var res T
	if err := json.Unmarshal(line, &res); err != nil {
		return nil, fmt.Errorf("agent sent something that is not a document: %v", err)
	}
	return &res, nil
}
