//go:build darwin && cgo

package skills

/*
#include <sys/acl.h>
#include <stdlib.h>
#include <errno.h>

static int youtrack_has_extended_acl(const char *path) {
	acl_t value = acl_get_file(path, ACL_TYPE_EXTENDED);
	if (value == NULL) {
		return errno == ENOENT ? 0 : -1;
	}
	acl_entry_t entry;
	int result = acl_get_entry(value, ACL_FIRST_ENTRY, &entry);
	acl_free(value);
	return result == 1 ? 1 : 0;
}
*/
import "C"

import (
	"os"
	"syscall"
	"unsafe"
)

func isSharedWritable(path string, info os.FileInfo) bool {
	if info.Mode().Perm()&0o022 != 0 {
		return true
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	// Fail closed when the ACL cannot be inspected.
	return C.youtrack_has_extended_acl(cPath) != 0
}

func isStickyDirectory(info os.FileInfo) bool {
	mode := info.Mode()
	return mode.IsDir() && mode&os.ModeSticky != 0
}

func hasUnsafeOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid()
}
