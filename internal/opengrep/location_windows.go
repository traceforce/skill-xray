package opengrep

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The owners a component of the engine's path may have besides this user, and the principals
// that stand for every user of the machine, in SID form.
const (
	administrators   = "S-1-5-32-544"
	localSystem      = "S-1-5-18"
	trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

var everyUser = map[string]bool{"S-1-1-0": true, "S-1-5-11": true, "S-1-5-32-545": true}

// The other allow entry kinds a DACL can hold: a callback entry has the allow entry's layout up to
// its SID, an object entry puts two GUIDs before the SID, which this check does not parse.
const (
	accessAllowedObjectACEType         = 0x5
	accessAllowedCallbackACEType       = 0x9
	accessAllowedCallbackObjectACEType = 0xb
)

// The rights that replace a file are writing to it, removing it and taking over its security;
// the right that replaces an entry of a directory is removing it from that directory. Adding
// entries leaves the existing ones alone, as under a sticky directory on Unix, and the drive
// root grants every authenticated user that much. A link, symlink or junction, is replaced by
// rewriting where it points: FSCTL_SET_REPARSE_POINT accepts a handle opened for writing data
// (the directory's "add file" bit), appending data or writing attributes, any one alone, so a
// link takes the file rights plus the attribute right. The same call turns the engine file
// itself into a link where symbolic links need no privilege, so a file takes the attribute
// right too; a directory on the path holds the next component, and the call refuses a
// directory that is not empty, so a directory does not. x/sys does not name FILE_DELETE_CHILD.
const (
	fileDeleteChild = 0x40
	takeover        = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
	fileWrite       = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | takeover
	dirWrite        = fileDeleteChild | takeover
)

// trustedComponent refuses a component of the engine's path that a user other than this one or
// an administrator could replace: its owner must be this process's user, Administrators, SYSTEM
// or TrustedInstaller, and no allow entry of its DACL that applies to it may grant Everyone,
// Authenticated Users or Users a right that replaces it. A group one of them granted keeps it.
func trustedComponent(path string, info os.FileInfo) error {
	sd, err := securityOf(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	user, err := currentUser()
	if err != nil {
		return err
	}
	if o := owner.String(); o != user && o != administrators && o != localSystem && o != trustedInstaller {
		return fmt.Errorf("%s is owned by another user", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no access control list", path)
	}
	var rights windows.ACCESS_MASK = fileWrite // a file, or a symlink or junction, which Lstat does not report as a directory
	if info.IsDir() {
		rights = dirWrite
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&rights == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
			if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); everyUser[sid.String()] {
				return fmt.Errorf("%s is writable by %s", path, sid)
			}
		case accessAllowedObjectACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("%s grants a replacing right through an object entry this check does not read", path)
		}
	}
	return nil
}

// securityOf reads the owner and DACL of the component itself, a link or junction included,
// through a handle opened without following it; addressed by name, the system would describe
// the link's target instead.
func securityOf(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	name, err := windows.UTF16PtrFromString(extendedPath(path))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
}

// extendedPath is the path in the extended-length form the system takes without parsing it;
// a UNC path keeps its server and share under the UNC device.
func extendedPath(path string) string {
	switch {
	case strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`):
		return path
	case strings.HasPrefix(path, `\\`):
		return `\\?\UNC\` + path[2:]
	}
	return `\\?\` + path
}

// currentUser is the SID of this process's user.
func currentUser() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser() // a pseudo handle with query access; nothing to close
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// fileBasicInfo is FILE_BASIC_INFO, which x/sys does not declare: four FILETIME values and the
// attributes.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
}

// changeTime is the file's change time as the file system reports it for the open handle; every
// write to its data or its metadata moves it.
func changeTime(f *os.File, _ os.FileInfo) (int64, error) {
	var b fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&b)), uint32(unsafe.Sizeof(b))); err != nil {
		return 0, err
	}
	return b.ChangeTime, nil
}
