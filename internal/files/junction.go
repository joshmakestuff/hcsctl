package files

import (
	"encoding/binary"
	"unicode/utf16"
)

// ioReparseTagMountPoint is the reparse tag for a junction (directory mount point). Declared
// here (not only in the windows file) so the pure buffer builder and its test need no build tag.
const ioReparseTagMountPoint = 0xA0000003

// mountPointReparseData builds the REPARSE_DATA_BUFFER for a junction to target: a mount-point
// reparse point whose substitute name is \??\<target> and print name is <target>, each UTF-16
// with a NUL, offsets and lengths in bytes. The bytes are identical to what `mklink /J` writes
// (verified in findings.md "SMB bind mounts", G8), so a junction hcsctl makes is
// indistinguishable from the shell's.
func mountPointReparseData(target string) []byte {
	sub := utf16.Encode([]rune(`\??\` + target))
	prn := utf16.Encode([]rune(target))
	subLen := len(sub) * 2
	prnLen := len(prn) * 2

	// PathBuffer: substitute name, NUL, print name, NUL.
	pathBuf := make([]byte, subLen+2+prnLen+2)
	for i, v := range sub {
		binary.LittleEndian.PutUint16(pathBuf[i*2:], v)
	}
	for i, v := range prn {
		binary.LittleEndian.PutUint16(pathBuf[subLen+2+i*2:], v)
	}

	// The mount-point data: SubstituteNameOffset/Length, PrintNameOffset/Length (8 bytes),
	// then PathBuffer.
	dataLen := 8 + len(pathBuf)
	buf := make([]byte, 8+dataLen)
	binary.LittleEndian.PutUint32(buf[0:], ioReparseTagMountPoint)
	binary.LittleEndian.PutUint16(buf[4:], uint16(dataLen))
	binary.LittleEndian.PutUint16(buf[6:], 0) // Reserved
	binary.LittleEndian.PutUint16(buf[8:], 0) // SubstituteNameOffset
	binary.LittleEndian.PutUint16(buf[10:], uint16(subLen))
	binary.LittleEndian.PutUint16(buf[12:], uint16(subLen+2)) // PrintNameOffset
	binary.LittleEndian.PutUint16(buf[14:], uint16(prnLen))
	copy(buf[16:], pathBuf)
	return buf
}
