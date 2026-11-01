//go:build windows

package authstate

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateKeyFilePermissions(file *os.File, _ os.FileInfo) error {
	// Check the already-open handle, so a path replacement cannot change which
	// file is validated. Windows mode bits do not describe NTFS permissions.
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || !sd.IsValid() {
		return errors.New("authentication key file security descriptor cannot be verified")
	}
	defer func() { runtime.KeepAlive(sd) }()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("authentication service identity cannot be verified")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(user.User.Sid) || sid.Equals(system) || sid.Equals(admins))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return errors.New("authentication key file must be owned by the service identity, system or administrators")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("authentication key file requires a private discretionary ACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return errors.New("authentication key file ACL cannot be verified")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("authentication key file has an unsupported access-control entry")
		}
		// ACCESS_ALLOWED_ACE stores the SID inline beginning at SidStart, as
		// specified by the Windows API. The descriptor/GetAce validate its layout.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- Documented Windows inline SID layout from a validated security descriptor.
		if !trusted(sid) {
			return errors.New("authentication key file ACL grants access outside the service identity, system or administrators")
		}
	}
	return nil
}
