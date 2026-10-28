//go:build linux

package main

// Linux mount state and its journal are boot-volatile.
var recoverPreviousBootShare func(shareIntent) error
