//go:build windows

package sysinfo

import "unsafe"

// unsafePointer keeps the one unsafe conversion this package needs in a file of its own, so
// the rest reads as ordinary Go.
func unsafePointer(b *byte) unsafe.Pointer { return unsafe.Pointer(b) }
