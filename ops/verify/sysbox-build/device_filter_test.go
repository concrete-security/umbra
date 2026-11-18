package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
	"github.com/opencontainers/runc/libcontainer/cgroups/ebpf/devicefilter"
	"github.com/opencontainers/runc/libcontainer/devices"
)

func requireQualificationRunner(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("device-filter qualification requires a disposable GitHub-hosted runner")
	}
}

func privateDeviceCgroup(t *testing.T) *os.File {
	t.Helper()
	requireQualificationRunner(t)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp("/sys/fs/cgroup", "umbra-sysbox-device-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return dir
}

func nullDeviceRules(t *testing.T) (asm.Instructions, string) {
	t.Helper()
	insts, license, err := devicefilter.DeviceFilter([]*devices.Rule{
		{Type: 'c', Major: 1, Minor: 3, Permissions: "rwm", Allow: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return insts, license
}

func probeDevice(t *testing.T, dir *os.File, path, mode, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUmbraDeviceProbe$")
	cmd.Env = append(os.Environ(), "UMBRA_DEVICE_PROBE="+path, "UMBRA_DEVICE_MODE="+mode)
	// Enter the private cgroup before exec; the Go test runner never moves.
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != want {
		t.Fatalf("%s %s: want %q, got %q, error %v", path, mode, want, output, err)
	}
}

// TestUmbraDeviceProbe performs a real device open in a child cgroup.
func TestUmbraDeviceProbe(t *testing.T) {
	path := os.Getenv("UMBRA_DEVICE_PROBE")
	if path == "" {
		return
	}
	requireQualificationRunner(t)
	if path != "/dev/null" && path != "/dev/zero" {
		t.Fatal("unexpected probe device")
	}
	flag := os.O_RDONLY
	if os.Getenv("UMBRA_DEVICE_MODE") == "write" {
		flag = os.O_WRONLY
	}
	file, err := os.OpenFile(path, flag, 0)
	switch {
	case err == nil:
		file.Close()
		fmt.Print("allowed")
	case errors.Is(err, syscall.EPERM):
		fmt.Print("denied")
	default:
		t.Fatal(err)
	}
	os.Exit(0)
}

// TestUmbraDeviceFilterLifecycleSuccess checks denial, allowed I/O and explicit detach.
func TestUmbraDeviceFilterLifecycleSuccess(t *testing.T) {
	dir := privateDeviceCgroup(t)
	probeDevice(t, dir, "/dev/zero", "read", "allowed")
	insts, license := nullDeviceRules(t)
	closer, err := LoadAttachCgroupDeviceFilter(insts, license, int(dir.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read", "write"} {
		probeDevice(t, dir, "/dev/null", mode, "allowed")
		probeDevice(t, dir, "/dev/zero", mode, "denied")
	}
	if err := closer(); err != nil {
		t.Fatal(err)
	}
	probeDevice(t, dir, "/dev/zero", "read", "allowed")
}

// TestUmbraDeviceAttachHelper exits after attaching, like the runc parent process.
func TestUmbraDeviceAttachHelper(t *testing.T) {
	path := os.Getenv("UMBRA_DEVICE_ATTACH")
	if path == "" {
		return
	}
	requireQualificationRunner(t)
	if !strings.HasPrefix(path, "/sys/fs/cgroup/umbra-sysbox-device-") {
		t.Fatal("unexpected qualification cgroup")
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	insts, license := nullDeviceRules(t)
	if _, err := LoadAttachCgroupDeviceFilter(insts, license, int(dir.Fd())); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

// TestUmbraDeviceFilterSurvivesLoaderExitSuccess requires kernel-owned enforcement.
func TestUmbraDeviceFilterSurvivesLoaderExitSuccess(t *testing.T) {
	dir := privateDeviceCgroup(t)
	probeDevice(t, dir, "/dev/zero", "read", "allowed")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUmbraDeviceAttachHelper$")
	cmd.Env = append(os.Environ(), "UMBRA_DEVICE_ATTACH="+dir.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("attach helper: %v: %s", err, output)
	}
	probeDevice(t, dir, "/dev/null", "read", "allowed")
	probeDevice(t, dir, "/dev/zero", "read", "denied")
}

// TestUmbraDeviceFilterInvalidTargetFailure must return the invalid-fd kernel error.
func TestUmbraDeviceFilterInvalidTargetFailure(t *testing.T) {
	requireQualificationRunner(t)
	insts, license := nullDeviceRules(t)
	if _, err := LoadAttachCgroupDeviceFilter(insts, license, -1); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("want EBADF for invalid attachment target, got %v", err)
	}
}
