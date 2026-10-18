//go:build windows

package ttlmgr

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// HardenDir restricts a directory to the current user, SYSTEM and Administrators, replacing
// the inherited permissions. The default location for this store is under the user's profile,
// but the store also holds the captured original values that a restore depends on, so an
// over-permissive inherited ACL is worth removing.
//
// It is best-effort: a failure is returned, and the caller decides whether to continue. Losing
// the capture log matters, so a failure here is reported rather than ignored.
func HardenDir(dir string) error {
	return hardenPath(dir, true)
}

// HardenFile restricts one file to the current user, SYSTEM and Administrators.
func HardenFile(path string) error {
	return hardenPath(path, false)
}

// hardenPath rewrites a path's DACL so that only the current user, SYSTEM and the
// Administrators group retain access. Inheritance is disabled so a permissive parent cannot
// widen it again, and the current user is always granted full control so the application keeps
// working even when it is running unelevated.
func hardenPath(path string, isDir bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	adminSID, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	systemSID, systemErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)

	flags := uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.SUB_CONTAINERS_ONLY_INHERIT)
	if !isDir {
		flags = windows.NO_INHERITANCE
	}

	entries := []windows.EXPLICIT_ACCESS{
		fullControl(user.User.Sid, flags),
	}
	// SYSTEM and Administrators are added when resolvable. Failing to add them is not fatal:
	// the current user keeps access and the directory is still narrower than before, but the
	// error is returned so the caller can report the reduced hardening.
	if systemErr == nil {
		entries = append(entries, fullControl(systemSID, flags))
	}
	if adminErr == nil {
		entries = append(entries, fullControl(adminSID, flags))
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		filepath.Clean(path),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		return err
	}
	return nil
}

// fullControl builds one access-control entry granting GENERIC_ALL to sid.
func fullControl(sid *windows.SID, flags uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       flags,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
