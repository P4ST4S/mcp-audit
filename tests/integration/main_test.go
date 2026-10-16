//go:build integration

package integration_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const signingSecret = "0123456789abcdef0123456789abcdef"

var (
	binaryPath   string
	upstreamPath string
	suiteDir     string
)

func TestMain(m *testing.M) {
	var err error
	suiteDir, err = os.MkdirTemp("", "mcp-audit-integration-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(suiteDir, "mcp-audit")
	upstreamPath = filepath.Join(suiteDir, "stdio-upstream")
	if err := buildBinary(binaryPath, "../../cmd/mcp-audit"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(suiteDir)
		os.Exit(1)
	}
	if err := buildBinary(upstreamPath, "./testdata/upstream"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(suiteDir)
		os.Exit(1)
	}
	exitCode := m.Run()
	_ = os.RemoveAll(suiteDir)
	os.Exit(exitCode)
}

func buildBinary(output, source string) error {
	command := exec.Command("go", "build", "-o", output, source)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", source, err, stderr.String())
	}
	return nil
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func commandEnv(overrides map[string]string, remove ...string) []string {
	removed := make(map[string]bool, len(remove))
	for _, name := range remove {
		removed[name] = true
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !removed[name] {
			env = append(env, item)
		}
	}
	for name, value := range overrides {
		env = append(env, name+"="+value)
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int, process *exec.Cmd, stderr *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if process.ProcessState != nil && process.ProcessState.Exited() {
			t.Fatalf("proxy exited before listening: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proxy did not listen on %s: %s", address, stderr.String())
}

func stopProcess(t *testing.T, command *exec.Cmd, stderr *lockedBuffer) {
	t.Helper()
	if command.Process == nil || command.ProcessState != nil {
		return
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal process: %v", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatalf("process shutdown: %v\n%s", err, stderr.String())
		}
	case <-time.After(7 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("process did not stop after interrupt: %s", stderr.String())
	}
}

type lockedBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

func newLockedBuffer() *lockedBuffer {
	return &lockedBuffer{}
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
