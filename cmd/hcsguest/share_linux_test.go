//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"golang.org/x/sys/unix"
)

func TestLinuxShareMount(t *testing.T) {
	oldMount, oldUnmount, oldDial := shareMount, shareUnmount, shareDial
	t.Cleanup(func() { shareMount, shareUnmount, shareDial = oldMount, oldUnmount, oldDial })
	var source, filesystem, options string
	var flags uintptr
	shareMount = func(src, target, fs string, f uintptr, data string) error {
		source, filesystem, options, flags = src, fs, data, f
		if !strings.HasPrefix(target, "/proc/self/fd/") {
			t.Errorf("unverified target: %s", target)
		}
		return nil
	}
	busy := true
	shareUnmount = func(_ string, f int) error {
		if f != 0 {
			t.Errorf("lazy unmount: %d", f)
		}
		if busy {
			busy = false
			return unix.EBUSY
		}
		return nil
	}
	s := &guestproto.Share{Transport: "smb-tcp", Source: `\\server\share`, Path: t.TempDir(), User: "user", Password: "secret", UID: 12, GID: 34, ReadOnly: true}
	cleanup, err := mountManagedShare(s)
	if err != nil {
		t.Fatal(err)
	}
	if source != "//server/share" || filesystem != "cifs" || flags&unix.MS_RDONLY == 0 || !strings.Contains(options, "username=user,password=secret,uid=12,gid=34") {
		t.Fatal("incorrect CIFS mount")
	}
	if err := cleanup(); !errors.Is(err, errShareBusy) {
		t.Fatalf("busy: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	s.Password = "bad,ro"
	if _, err := mountManagedShare(s); err == nil {
		t.Fatal("accepted ambiguous credential")
	}
	s.Password = "secret"
	s.Path = "/"
	if _, err := mountManagedShare(s); err == nil {
		t.Fatal("accepted root")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Path = dir
	if _, err := mountManagedShare(s); err == nil {
		t.Fatal("accepted nonempty target")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	s.Path = link
	if _, err := mountManagedShare(s); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestLinuxPlan9Descriptor(t *testing.T) {
	oldMount, oldUnmount, oldDial := shareMount, shareUnmount, shareDial
	t.Cleanup(func() { shareMount, shareUnmount, shareDial = oldMount, oldUnmount, oldDial })
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	var f *os.File
	shareDial = func(port uint32) (*os.File, error) {
		if port != 44 {
			t.Errorf("port: %d", port)
		}
		f = os.NewFile(uintptr(pair[0]), "test")
		return f, nil
	}
	shareMount = func(_, _, fs string, flags uintptr, data string) error {
		want := fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,msize=65536,aname=access", f.Fd(), f.Fd())
		if fs != "9p" || !strings.Contains(data, want) || flags&unix.MS_RDONLY == 0 {
			t.Errorf("bad 9p options: %s", data)
		}
		return nil
	}
	shareUnmount = func(string, int) error { return nil }
	cleanup, err := mountManagedShare(&guestproto.Share{Transport: "plan9", Source: "access", Port: 44, Path: t.TempDir(), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("socket not closed: %v", err)
	}
}

func TestLinuxSMBVsockMountLifetime(t *testing.T) {
	oldMount, oldUnmount := shareMount, shareUnmount
	t.Cleanup(func() { shareMount, shareUnmount = oldMount, oldUnmount })
	var address string
	shareMount = func(source, _, fs string, _ uintptr, data string) error {
		if source != "//server/share" || fs != "cifs" {
			t.Errorf("unexpected source or filesystem")
		}
		for _, option := range strings.Split(data, ",") {
			if strings.HasPrefix(option, "port=") {
				address = "127.0.0.1:" + strings.TrimPrefix(option, "port=")
			}
		}
		if !strings.Contains(data, "ip=127.0.0.1") || address == "" {
			t.Error("missing loopback relay")
		}
		return nil
	}
	busy := true
	shareUnmount = func(string, int) error {
		if busy {
			busy = false
			return unix.EBUSY
		}
		return nil
	}
	cleanup, err := mountManagedShare(&guestproto.Share{Transport: "smb-hvsocket", Source: `\\server\share`, Port: 99, Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err = cleanup(); !errors.Is(err, errShareBusy) {
		t.Fatalf("busy: %v", err)
	}
	c, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatalf("relay closed after busy: %v", err)
	}
	c.Close()
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	if c, err = net.DialTimeout("tcp4", address, time.Second); err == nil {
		c.Close()
		t.Fatal("relay still listening")
	}
}

func TestLinuxRelayShutdown(t *testing.T) {
	oldDial := shareDial
	t.Cleanup(func() { shareDial = oldDial })
	peer := make(chan net.Conn, 1)
	shareDial = func(port uint32) (*os.File, error) {
		if port != 123 {
			t.Errorf("wrong port %d", port)
		}
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(pair[1]), "peer")
		conn, err := net.FileConn(f)
		f.Close()
		if err != nil {
			unix.Close(pair[0])
			return nil, err
		}
		peer <- conn
		return os.NewFile(uintptr(pair[0]), "dial"), nil
	}
	r, err := newShareRelay(123)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", r.port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := <-peer
	defer p.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	p.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := p.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("relay: %q %v", buf[:n], err)
	}
	done := make(chan struct{})
	go func() { r.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop")
	}
}
