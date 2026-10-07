package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func protonTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	master := os.NewFile(uintptr(fd), "proton-test-pty")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	if !term.IsTerminal(int(slave.Fd())) {
		t.Fatal("PTY slave is not a terminal")
	}
	return master, slave
}

func TestProtonInteractiveRejectsRedirectedOutputBeforeSessionAccess(t *testing.T) {
	_, terminal := protonTestPTY(t)
	dir := t.TempDir()
	config := ProtonConfig{SessionFile: filepath.Join(dir, "session"), SessionKeyFile: filepath.Join(dir, "missing-key"), AppVersion: "Other"}
	file, err := os.CreateTemp(dir, "redirected-output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, output := range []io.Writer{io.Discard, file, (*os.File)(nil)} {
		err := RunProtonAuth(context.Background(), config, terminal, output)
		if err == nil || !strings.Contains(err.Error(), "requires terminal output") {
			t.Fatalf("redirected output reached session or network initialization: %v", err)
		}
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("redirected terminal output was written")
	}
	if _, err := os.Stat(config.SessionFile + ".lock"); !os.IsNotExist(err) {
		t.Fatal("session accessed before terminal gate")
	}
}

func TestProtonTerminalEnterWorksOnlyForExplicitContinuation(t *testing.T) {
	master, terminal := protonTestPTY(t)
	done := make(chan error, 1)
	go func() {
		value, err := protonTerminalSecret(terminal, terminal, "Synthetic Enter prompt: ")
		defer clear(value)
		if err == nil && len(value) != 0 {
			err = fmt.Errorf("empty Enter returned nonempty input")
		}
		done <- err
	}()
	// Queue Enter through the PTY. No credential or live account is involved.
	if _, err := master.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		master.Close()
		terminal.Close()
		t.Fatal("empty Enter did not return")
	}
	if _, err := readProtonAuthInput(context.Background(), func(string) ([]byte, error) { return nil, nil }, "Credential: "); err == nil {
		t.Fatal("empty Enter was accepted as a credential")
	}
}
