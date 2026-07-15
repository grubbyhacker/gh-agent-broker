//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// This is the executable PR 4 isolation proof. Separate paths under a shared
// UID would pass this test incorrectly; each session must use a unique UID/GID
// and a 0700 workspace. It is intentionally skipped outside a root-owned Linux
// CI runner because changing process credentials is the property under test.
func TestSessionWorkspaceCrossUIDIsolation(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires root-owned Linux runner for cross-UID proof")
	}
	root := t.TempDir()
	for _, item := range []struct {
		name     string
		uid, gid uint32
	}{{"one", 22001, 22001}, {"two", 22002, 22002}} {
		path := filepath.Join(root, item.name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(item.uid), int(item.gid)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "private"), []byte(item.name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Join(path, "private"), int(item.uid), int(item.gid)); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct {
		uid, gid uint32
		target   string
	}{{22001, 22001, filepath.Join(root, "two", "private")}, {22002, 22002, filepath.Join(root, "one", "private")}} {
		cmd := exec.Command("/bin/sh", "-c", "test -r \"$1\" || test -w \"$1\" || test -x \"$(dirname \"$1\")\"", "sh", check.target)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: check.uid, Gid: check.gid}}
		if err := cmd.Run(); err == nil {
			t.Fatalf("uid %d crossed session boundary %s", check.uid, check.target)
		}
	}
}
