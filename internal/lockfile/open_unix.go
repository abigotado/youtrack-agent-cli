//go:build !windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openLockNoFollow(directory, name string) (*os.File, error) {
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open lock directory without symlinks: %w", err)
	}
	defer unix.Close(directoryFD)

	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_CREAT | unix.O_EXCL
	fd, err := unix.Openat(directoryFD, name, flags, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("construct lock file handle")
	}
	fail := func(cause error) (*os.File, error) {
		_ = file.Close()
		return nil, cause
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return fail(fmt.Errorf("secure new lock file: %w", err))
		}
	}
	opened, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	var linked unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		uint64(openedStat.Dev) != uint64(linked.Dev) || uint64(openedStat.Ino) != uint64(linked.Ino) {
		return fail(errors.New("lock path is not the opened regular 0600 file"))
	}
	return file, nil
}
