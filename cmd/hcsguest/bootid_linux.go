//go:build linux

package main

import (
	"fmt"
	"os"
)

func readBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read boot identity: %w", err)
	}
	return parseBootID(string(b))
}
