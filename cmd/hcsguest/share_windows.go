//go:build windows

package main

import (
	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

func mountManagedShare(*guestproto.Share) (func() error, error) {
	return nil, errShareNotImplemented
}
