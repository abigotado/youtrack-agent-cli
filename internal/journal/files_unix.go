//go:build darwin || linux

package journal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"golang.org/x/sys/unix"
)

// secureJournalDirectory pins all migration file operations to one private
// directory handle. A pathname swap cannot redirect an individual read/write.
type secureJournalDirectory struct {
	file *os.File
	fd   int
}

func migrationAvailable() bool { return true }

func migrationUnsupported() error {
	return journalConflict("JOURNAL_MIGRATION_UNSUPPORTED", "secure journal migration is not available on this platform")
}

func validJournalDirectoryInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o700 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		stat.Uid == uint32(os.Geteuid())
}

func openSecureJournalDirectory(path string) (*secureJournalDirectory, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open migration journal directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), "migration journal directory")
	if file == nil {
		_ = unix.Close(fd) // No handle exists to close after failed construction.
		return nil, errInvalidJournalWire
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o7777 != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close() // Rejecting the directory; close cannot make it safe.
		return nil, errx.Internal("migration journal directory is not an owned private 0700 directory")
	}
	return &secureJournalDirectory{file: file, fd: fd}, nil
}

func (d *secureJournalDirectory) close() error { return d.file.Close() }

func readJournalFile(directory, name string, limit int) (raw []byte, err error) {
	d, err := openSecureJournalDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := d.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close journal directory: %w", closeErr))
		}
	}()
	return d.read(name, limit)
}

func validJournalFileStat(stat unix.Stat_t, limit int) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 &&
		stat.Uid == uint32(os.Geteuid()) && uint64(stat.Nlink) == 1 &&
		stat.Size >= 0 && stat.Size <= int64(limit)
}

func sameJournalInode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino
}

func (d *secureJournalDirectory) read(name string, limit int) ([]byte, error) {
	raw, _, err := d.readIdentified(name, limit)
	return raw, err
}

func (d *secureJournalDirectory) readIdentified(name string, limit int) (raw []byte, identity journalFileIdentity, err error) {
	var linked unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, journalFileIdentity{}, os.ErrNotExist
		}
		return nil, journalFileIdentity{}, fmt.Errorf("inspect migration journal entry: %w", err)
	}
	if !validJournalFileStat(linked, limit) {
		return nil, journalFileIdentity{}, errInvalidJournalWire
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, journalFileIdentity{}, fmt.Errorf("open migration journal entry: %w", err)
	}
	file := os.NewFile(uintptr(fd), "migration journal entry")
	if file == nil {
		_ = unix.Close(fd) // No handle exists to close after failed construction.
		return nil, journalFileIdentity{}, errInvalidJournalWire
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close migration journal entry: %w", closeErr))
		}
	}()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !validJournalFileStat(opened, limit) || !sameJournalInode(linked, opened) {
		return nil, journalFileIdentity{}, errInvalidJournalWire
	}
	before, err := file.Stat()
	if err != nil {
		return nil, journalFileIdentity{}, fmt.Errorf("stat migration journal entry: %w", err)
	}
	raw, err = io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, journalFileIdentity{}, fmt.Errorf("read migration journal entry: %w", err)
	}
	var after, current unix.Stat_t
	if len(raw) > limit || int64(len(raw)) != opened.Size ||
		unix.Fstat(fd, &after) != nil || unix.Fstatat(d.fd, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!validJournalFileStat(after, limit) || !validJournalFileStat(current, limit) ||
		!sameJournalInode(opened, after) || !sameJournalInode(opened, current) ||
		opened.Size != after.Size || opened.Size != current.Size {
		return nil, journalFileIdentity{}, errInvalidJournalWire
	}
	info, err := file.Stat()
	if err != nil || !info.ModTime().Equal(before.ModTime()) {
		return nil, journalFileIdentity{}, errInvalidJournalWire
	}
	return raw, journalFileIdentity{dev: uint64(opened.Dev), ino: uint64(opened.Ino),
		size: opened.Size, modified: info.ModTime()}, nil
}

func (d *secureJournalDirectory) createTemp(prefix string, raw []byte) (name string, err error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate migration temporary name: %w", err)
	}
	name = prefix + hex.EncodeToString(random[:]) + ".tmp"
	tempName := name
	fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create migration temporary file: %w", err)
	}
	defer func() {
		if err != nil {
			if removeErr := unix.Unlinkat(d.fd, tempName, 0); removeErr != nil && !errors.Is(removeErr, unix.ENOENT) {
				err = errors.Join(err, fmt.Errorf("remove migration temporary file: %w", removeErr))
			}
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd) // Preserve the protection error.
		return "", fmt.Errorf("protect migration temporary file: %w", err)
	}
	file := os.NewFile(uintptr(fd), "migration temporary file")
	if file == nil {
		_ = unix.Close(fd) // No handle exists to close after failed construction.
		return "", errInvalidJournalWire
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close() // Preserve the write error.
		return "", fmt.Errorf("write migration temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close() // Preserve the sync error.
		return "", fmt.Errorf("sync migration temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close migration temporary file: %w", err)
	}
	return name, nil
}

func (d *secureJournalDirectory) unlink(name string) error {
	if err := unix.Unlinkat(d.fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove migration temporary file: %w", err)
	}
	return nil
}

func defaultMigrationRename(fd int, oldName, newName string) error {
	return unix.Renameat(fd, oldName, fd, newName)
}

func defaultMarkerLink(fd int, oldName, newName string) error {
	return unix.Linkat(fd, oldName, fd, newName, 0)
}
