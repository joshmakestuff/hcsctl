package files

import "fmt"

// SDDL access masks, as hex strings for SDDL:
//
//	0x1F01FF  full control on a file object (everything)
//	0x1200A9  read + execute (read data, read attrs/EA, execute/traverse, read control, sync)
//	0x1200AD  read + execute + add subdirectory (0x1200A9 | FILE_ADD_SUBDIRECTORY 0x4)
const (
	maskFull      = "0x1F01FF"
	maskReadExec  = "0x1200A9"
	maskListWrite = "0x1200AD"
)

// sharePermissionSDDL is the security descriptor for a share: full or read-only for one SID.
// A share ACL is a gate in front of the NTFS ACL; the effective access is the intersection.
func sharePermissionSDDL(sid string, full bool) string {
	mask := maskReadExec
	if full {
		mask = maskFull
	}
	return fmt.Sprintf("D:(A;;%s;;;%s)", mask, sid)
}

// rootDirectorySDDL is the NTFS DACL for the share root:
//
//   - SYSTEM and Administrators: full, inherited (OICI).
//   - CREATOR OWNER: full on what it creates, inherit-only (OICIIO), so an unelevated
//     developer who makes <root>\<vmid> owns it outright.
//   - Authenticated Users: list + add subdirectory + traverse on the container only (CI), so
//     any developer can create their VM's subdirectory but not read another's files here.
//   - the share user: read + execute, inherited (OICI), so the SMB server can traverse the
//     root to reach the junctions; the junction targets get their own ACE at expose time.
//
// PAI makes the DACL protected (no inheritance from ProgramData) and auto-inherited downward.
func rootDirectorySDDL(shareUserSID string) string {
	return "D:PAI" +
		"(A;OICI;FA;;;SY)" +
		"(A;OICI;FA;;;BA)" +
		"(A;OICIIO;FA;;;CO)" +
		fmt.Sprintf("(A;CI;%s;;;AU)", maskListWrite) +
		fmt.Sprintf("(A;OICI;%s;;;%s)", maskReadExec, shareUserSID)
}
