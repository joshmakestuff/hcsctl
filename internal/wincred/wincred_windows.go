//go:build windows

// Package wincred is a thin binding over the Windows Credential Manager (advapi32
// CredRead/Write/Delete). hcsctl uses it so an SMB share credential written once by the
// elevated `files prepare` is read by the unelevated `guest mount` of the same user, without
// the password ever crossing a command line.
//
// Credentials are stored as CRED_TYPE_GENERIC with CRED_PERSIST_LOCAL_MACHINE, which is
// shared across the same user's elevated and unelevated tokens (measured, findings.md "SMB
// bind mounts", G3).
package wincred

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW = advapi32.NewProc("CredWriteW")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

// credentialW mirrors CREDENTIALW. Only the fields hcsctl sets or reads are named precisely;
// the rest are placeholders of the right width so the struct layout matches the API.
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Write stores (user, password) under target, replacing any existing credential.
func Write(target, user, password string) error {
	blob := utf16Bytes(password)
	c := credentialW{
		Type:               credTypeGeneric,
		TargetName:         windows.StringToUTF16Ptr(target),
		Persist:            credPersistLocalMachine,
		CredentialBlobSize: uint32(len(blob)),
		UserName:           windows.StringToUTF16Ptr(user),
	}
	if len(blob) > 0 {
		c.CredentialBlob = &blob[0]
	}
	r, _, err := procCredWriteW.Call(uintptr(unsafe.Pointer(&c)), 0)
	if r == 0 {
		return fmt.Errorf("CredWriteW %q: %w", target, err)
	}
	return nil
}

// Read returns the user and password stored under target.
func Read(target string) (user, password string, err error) {
	var p *credentialW
	r, _, e := procCredReadW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(target))),
		credTypeGeneric, 0, uintptr(unsafe.Pointer(&p)))
	if r == 0 {
		return "", "", fmt.Errorf("CredReadW %q: %w", target, e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(p)))
	user = windows.UTF16PtrToString(p.UserName)
	if p.CredentialBlobSize > 0 && p.CredentialBlob != nil {
		blob := unsafe.Slice(p.CredentialBlob, p.CredentialBlobSize)
		password = utf16FromBytes(blob)
	}
	return user, password, nil
}

// Delete removes the credential under target.
func Delete(target string) error {
	r, _, err := procCredDelete.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(target))),
		credTypeGeneric, 0)
	if r == 0 {
		return fmt.Errorf("CredDeleteW %q: %w", target, err)
	}
	return nil
}

// utf16Bytes encodes a string as a little-endian UTF-16 byte blob, no terminator, matching
// how CredWrite expects the credential blob.
func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func utf16FromBytes(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
