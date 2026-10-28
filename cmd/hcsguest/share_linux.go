//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
	"github.com/mdlayher/socket"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

var shareMount = unix.Mount
var shareUnmount = unix.Unmount
var shareDial = dialShareVSock
var shareRelayDial = dialRelayVSock
var shareMountID = mountID
var shareTrustedDirectory = trustedShareDirectory

func trustedShareDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("untrusted mount target ancestor")
	}
	return nil
}

func mountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("mount identity unavailable")
	}
	return st.Mnt_id, nil
}

// mountTarget opens each component without following symbolic links. The final
// directory must already exist and be empty; the backend never removes it.
func mountTarget(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("invalid mount target")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := shareTrustedDirectory(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == nil && i == len(parts)-1 {
			var parent, child unix.Statx_t
			if e = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &parent); e == nil {
				e = unix.Statx(next, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &child)
			}
			if e == nil && (parent.Mask&unix.STATX_MNT_ID == 0 || child.Mask&unix.STATX_MNT_ID == 0 || parent.Mnt_id != child.Mnt_id) {
				e = errors.New("mount target is already a mount point")
			}
			if e != nil {
				unix.Close(next)
			}
		}
		if e == nil {
			e = shareTrustedDirectory(next)
			if e != nil {
				unix.Close(next)
			}
		}
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	entries, err := f.Readdirnames(1)
	if err != io.EOF || len(entries) != 0 {
		f.Close()
		if err != nil && err != io.EOF {
			return nil, err
		}
		return nil, errors.New("mount target is not empty")
	}
	return f, nil
}

func mountManagedShare(s *guestproto.Share) (func() error, error) {
	if s == nil || s.UID < 0 || s.GID < 0 {
		return nil, errors.New("invalid share")
	}
	target, err := mountTarget(s.Path)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	parentFD, err := unix.Openat(int(target.Fd()), "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(parentFD), "share-parent")
	keepParent := false
	defer func() {
		if !keepParent {
			parent.Close()
		}
	}()
	anchoredPath := fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), filepath.Base(s.Path))
	var original, named unix.Stat_t
	if err = unix.Fstat(int(target.Fd()), &original); err != nil {
		return nil, err
	}
	if err = unix.Fstatat(parentFD, filepath.Base(s.Path), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if original.Dev != named.Dev || original.Ino != named.Ino {
		return nil, errors.New("mount target changed")
	}
	oldID, err := shareMountID(int(target.Fd()))
	if err != nil {
		return nil, err
	}
	// Mount through the verified directory descriptor rather than re-resolving
	// an attacker-controlled pathname during the mount syscall.
	mountPath := fmt.Sprintf("/proc/self/fd/%d", target.Fd())
	flags := uintptr(0)
	if s.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	var source, fs, data string
	var relay *shareRelay
	var socket *os.File
	switch s.Transport {
	case "smb-tcp", "smb-hvsocket":
		source = strings.ReplaceAll(s.Source, `\`, "/")
		parts := strings.Split(source, "/")
		if len(parts) != 4 || parts[0] != "" || parts[1] != "" || parts[2] == "" || parts[3] == "" || strings.ContainsAny(source, ",\x00\n\r") {
			return nil, errors.New("invalid SMB source")
		}
		if strings.ContainsAny(s.User, "\x00\n\r") || strings.ContainsAny(s.Password, "\x00\n\r") {
			return nil, errors.New("invalid SMB credential")
		}
		fs = "cifs"
		// CIFS's monolithic mount parser interprets doubled commas as one.
		data = fmt.Sprintf("username=%s,password=%s,uid=%d,gid=%d", strings.ReplaceAll(s.User, ",", ",,"), strings.ReplaceAll(s.Password, ",", ",,"), s.UID, s.GID)
		if s.Transport == "smb-hvsocket" {
			if s.Port == 0 {
				return nil, errors.New("invalid vsock port")
			}
			relay, err = newShareRelay(s.Port)
			if err != nil {
				return nil, err
			}
			data += ",ip=127.0.0.1,port=" + strconv.Itoa(relay.port())
		}
	case "plan9":
		if s.Port == 0 || s.Source == "" || strings.ContainsAny(s.Source, ",\x00\n\r") {
			return nil, errors.New("invalid plan9 share")
		}
		socket, err = shareDial(s.Port)
		if err != nil {
			return nil, err
		}
		fs, source = "9p", mountPath
		data = fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,msize=65536,aname=%s", socket.Fd(), socket.Fd(), s.Source)
	default:
		return nil, errShareNotImplemented
	}
	if err = shareMount(source, mountPath, fs, flags, data); err != nil {
		if relay != nil {
			relay.close()
		}
		if socket != nil {
			if closeErr := socket.Close(); closeErr != nil {
				return nil, fmt.Errorf("mount and socket cleanup: %w", errors.Join(err, closeErr))
			}
		}
		if errors.Is(err, unix.ENODEV) {
			return nil, fmt.Errorf("%w: mount filesystem: %w", errSharePrerequisiteMissing, err)
		}
		return nil, fmt.Errorf("mount share: %w", err)
	}
	mountedFD, identityErr := unix.Openat(parentFD, filepath.Base(s.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	var id uint64
	if identityErr == nil {
		id, identityErr = shareMountID(mountedFD)
		if identityErr == nil && id == oldID {
			identityErr = errors.New("new mount identity not found")
		}
	}
	if identityErr != nil && mountedFD >= 0 {
		unix.Close(mountedFD)
		mountedFD = -1
	}
	keepParent = true
	return func() error {
		if identityErr != nil {
			return fmt.Errorf("mounted identity unavailable: %w", identityErr)
		}
		fd, err := unix.Openat(parentFD, filepath.Base(s.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		current, err := shareMountID(fd)
		unix.Close(fd)
		if err != nil {
			return err
		}
		if current != id {
			return errors.New("mounted identity changed")
		}
		// A descriptor referencing this mount itself counts as a busy user in
		// Linux do_umount. The pinned parent and root-owned, non-writable path
		// prevent unprivileged replacement while that reference is dropped.
		unix.Close(mountedFD)
		mountedFD = -1
		if err := shareUnmount(anchoredPath, 0); err != nil {
			mountedFD, identityErr = unix.Openat(parentFD, filepath.Base(s.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if identityErr == nil {
				var retryID uint64
				retryID, identityErr = shareMountID(mountedFD)
				if identityErr == nil && retryID != id {
					identityErr = errors.New("mounted identity changed")
				}
				if identityErr != nil {
					unix.Close(mountedFD)
					mountedFD = -1
				}
			}
			if errors.Is(err, unix.EBUSY) {
				return fmt.Errorf("%w: %v", errShareBusy, err)
			}
			return err
		}
		if relay != nil {
			relay.close()
		}
		if socket != nil {
			socket.Close()
		}
		parent.Close()
		return nil
	}, nil
}

func dialShareVSock(port uint32) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*os.File, error) { unix.Close(fd); return nil, e }
	err = unix.Connect(fd, &unix.SockaddrVM{CID: 2, Port: port})
	if err == unix.EINPROGRESS {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, e := unix.Poll(poll, 3000)
		if e != nil {
			return fail(e)
		}
		if n == 0 {
			return fail(errors.New("vsock dial timed out"))
		}
		code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if e != nil {
			return fail(e)
		}
		if code != 0 {
			return fail(unix.Errno(code))
		}
	} else if err != nil {
		return fail(err)
	}
	if err = unix.SetNonblock(fd, false); err != nil {
		return fail(err)
	}
	return os.NewFile(uintptr(fd), "share-vsock"), nil
}

type shareRelay struct {
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup
	limit       chan struct{}
	vsockPort   uint32
	ctx         context.Context
	cancel      context.CancelFunc
}

// mdlayher/vsock v1.3.0 Dial uses context.Background internally. Its socket
// package supplies the same pollable transport with cancellable Connect.
type relayVSockConn struct {
	*socket.Conn
	remote net.Addr
}

func (c *relayVSockConn) LocalAddr() net.Addr  { return &vsock.Addr{} }
func (c *relayVSockConn) RemoteAddr() net.Addr { return c.remote }
func dialRelayVSock(ctx context.Context, port uint32) (net.Conn, error) {
	c, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "vsock", nil)
	if err != nil {
		return nil, err
	}
	if _, err = c.Connect(ctx, &unix.SockaddrVM{CID: vsock.Host, Port: port}); err != nil {
		c.Close()
		return nil, err
	}
	return &relayVSockConn{Conn: c, remote: &vsock.Addr{ContextID: vsock.Host, Port: port}}, nil
}

func newShareRelay(port uint32) (*shareRelay, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &shareRelay{listener: l, connections: make(map[net.Conn]struct{}), limit: make(chan struct{}, 16), vsockPort: port, ctx: ctx, cancel: cancel}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}
func (r *shareRelay) port() int { return r.listener.Addr().(*net.TCPAddr).Port }
func (r *shareRelay) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		c.Close()
		return false
	}
	r.connections[c] = struct{}{}
	return true
}
func (r *shareRelay) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.connections, c)
	r.mu.Unlock()
	c.Close()
}
func (r *shareRelay) serve() {
	defer r.wg.Done()
	for {
		c, err := r.listener.Accept()
		if err != nil {
			return
		}
		select {
		case r.limit <- struct{}{}:
		default:
			c.Close()
			continue
		}
		if !r.track(c) {
			<-r.limit
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.limit }()
			defer r.untrack(c)
			ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
			peer, err := shareRelayDial(ctx, r.vsockPort)
			cancel()
			if err != nil {
				return
			}
			if !r.track(peer) {
				return
			}
			defer r.untrack(peer)
			done := make(chan struct{})
			go func() { io.Copy(peer, c); peer.Close(); close(done) }()
			io.Copy(c, peer)
			c.Close()
			peer.Close()
			<-done
		}()
	}
}
func (r *shareRelay) close() {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.listener.Close()
	for c := range r.connections {
		c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}
