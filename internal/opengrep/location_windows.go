package opengrep

import (
	"fmt"
	"os"
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

// The rights that replace a file are writing to it, removing it and taking over its security;
// the right that replaces an entry of a directory is removing it from that directory. Adding
// entries leaves the existing ones alone, as under a sticky directory on Unix, and the drive
// root grants every authenticated user that much. x/sys does not name FILE_DELETE_CHILD.
const (
	fileDeleteChild = 0x40
	takeover        = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
	fileWrite       = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | takeover
	dirWrite        = fileDeleteChild | takeover
)

// trustedComponent refuses a component of the engine's path that a user other than this one or
// an administrator could replace: its owner must be this process's user, Administrators, SYSTEM
// or TrustedInstaller, and no allow entry of its DACL that applies to it may grant Everyone,
// Authenticated Users or Users a right that replaces it. A group one of them granted keeps it.
func trustedComponent(path string, info os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
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
	var rights windows.ACCESS_MASK = fileWrite
	if info.IsDir() {
		rights = dirWrite
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&rights == 0 {
			continue
		}
		if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); everyUser[sid.String()] {
			return fmt.Errorf("%s is writable by %s", path, sid)
		}
	}
	return nil
}

// currentUser is the SID of this process's user.
func currentUser() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
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
