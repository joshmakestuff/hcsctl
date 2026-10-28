//go:build windows

package main

import "errors"

// A path and share name alone cannot authorize removing a Windows mapping.
func captureShareIntent(*shareIntent) error { return nil }
func recoverShareIntent(shareIntent) (func() error, error) {
	return nil, errors.New("native mapping requires reconciliation")
}
