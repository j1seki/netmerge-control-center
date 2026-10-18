//go:build !windows

package ttlmgr

import "os"

// HardenDir tightens a directory's mode bits to owner-only. Away from Windows this is the
// available protection; on Windows an ACL is applied instead.
func HardenDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return nil
}

// HardenFile tightens a file's mode bits to owner-only.
func HardenFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}
