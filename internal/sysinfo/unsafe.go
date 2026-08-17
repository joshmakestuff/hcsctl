//go:build windows

package sysinfo

import "unsafe"

// unsafePointer is the one unsafe conversion this package needs.
func unsafePointer(b *byte) unsafe.Pointer { return unsafe.Pointer(b) }
