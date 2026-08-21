//go:build windows

// Package vmcompute is a narrow binding to the v2 compute-system API in vmcompute.dll.
//
// hcsshim exports no public v2 compute-system API. Its only public constructor,
// hcsshim.CreateContainer, takes a schema 1 ContainerConfig, which cannot express a
// VirtualMachine document (VHDX boot, UEFI firmware, COM ports, HvSocket service table).
// This package binds the documented vmcompute.dll entry points directly and does not copy
// hcsshim internal/ source.
//
// # Shape
//
// Every call is asynchronous. It returns either a terminal HRESULT or ERROR_VMCOMPUTE_OPERATION_PENDING,
// and completion arrives on a registered callback. A System registers its callback at open
// time and each operation waits on the notification that names it. S_FALSE (1) is a success
// HRESULT, so success is a range and not a value.
package vmcompute

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim"
	"golang.org/x/sys/windows"
)

var (
	dll = windows.NewLazySystemDLL("vmcompute.dll")

	procCreate     = dll.NewProc("HcsCreateComputeSystem")
	procOpen       = dll.NewProc("HcsOpenComputeSystem")
	procClose      = dll.NewProc("HcsCloseComputeSystem")
	procStart      = dll.NewProc("HcsStartComputeSystem")
	procShutdown   = dll.NewProc("HcsShutdownComputeSystem")
	procTerminate  = dll.NewProc("HcsTerminateComputeSystem")
	procPause      = dll.NewProc("HcsPauseComputeSystem")
	procResume     = dll.NewProc("HcsResumeComputeSystem")
	procProperties = dll.NewProc("HcsGetComputeSystemProperties")
	procModify     = dll.NewProc("HcsModifyComputeSystem")
	procEnumerate  = dll.NewProc("HcsEnumerateComputeSystems")
	procRegister   = dll.NewProc("HcsRegisterComputeSystemCallback")
	procUnregister = dll.NewProc("HcsUnregisterComputeSystemCallback")
	procGrant      = dll.NewProc("GrantVmAccess")
	procRevoke     = dll.NewProc("RevokeVmAccess")

	procCreateProcess     = dll.NewProc("HcsCreateProcess")
	procOpenProcess       = dll.NewProc("HcsOpenProcess")
	procCloseProcess      = dll.NewProc("HcsCloseProcess")
	procTerminateProcess  = dll.NewProc("HcsTerminateProcess")
	procSignalProcess     = dll.NewProc("HcsSignalProcess")
	procGetProcessProps   = dll.NewProc("HcsGetProcessProperties")
	procModifyProcess     = dll.NewProc("HcsModifyProcess")
	procRegisterProcess   = dll.NewProc("HcsRegisterProcessCallback")
	procUnregisterProcess = dll.NewProc("HcsUnregisterProcessCallback")

	ole32             = windows.NewLazySystemDLL("ole32.dll")
	procCoTaskMemFree = ole32.NewProc("CoTaskMemFree")
)

// HRESULTs that carry meaning here. Pending is a success in the sense that the operation was
// accepted; the callback says whether it worked.
const (
	sOK     = 0
	sFalse  = 1
	pending = 0xC0370103 // ERROR_VMCOMPUTE_OPERATION_PENDING
)

// Notification types delivered to the callback. Only the ones this package waits on.
const (
	notifyExited            = 0x00000001
	notifyCreateCompleted   = 0x00000002
	notifyStartCompleted    = 0x00000003
	notifyPauseCompleted    = 0x00000004
	notifyResumeCompleted   = 0x00000005
	notifyProcessExited     = 0x00010000
	notifyServiceDisconnect = 0x01000000
)

// Error carries the HRESULT and, when HCS supplied one, the result document. The document
// names the part of the configuration HCS rejected.
type Error struct {
	Op     string
	Code   uint32
	Result string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("%s: 0x%08x (%s)", e.Op, e.Code, syscall.Errno(e.Code&0xffff).Error())
	if e.Result != "" {
		msg += ": " + e.Result
	}
	return msg
}

// System is an open handle to a compute system, with its notification callback registered.
type System struct {
	ID string

	mu       sync.Mutex
	handle   uintptr
	callback uintptr // the registered HCS_CALLBACK, freed at Close
	number   uintptr // this System's key in callbackMap
}

// -- the callback plumbing ---------------------------------------------------------------
//
// syscall.NewCallback is a process-lifetime resource with a hard cap, so exactly one is made,
// for the whole package. Each System gets a number instead, and the native side hands that
// number back as the context argument.

var (
	callbackOnce sync.Once
	callbackPtr  uintptr

	callbackMu   sync.RWMutex
	callbackNext uintptr
	callbackMap  = map[uintptr]map[uint32]chan error{}
)

func watcher(notification uint32, number uintptr, status uintptr, _ *uint16) uintptr {
	var err error
	if int32(status) < 0 {
		err = &Error{Op: "notification", Code: uint32(status)}
	}
	callbackMu.RLock()
	channels := callbackMap[number]
	callbackMu.RUnlock()
	if ch, ok := channels[notification]; ok {
		// Buffered, depth 1. A second notification of the same type is dropped; the native
		// callback thread must not block.
		select {
		case ch <- err:
		default:
		}
	}
	return 0
}

func waitedOn() []uint32 {
	return []uint32{notifyExited, notifyCreateCompleted, notifyStartCompleted,
		notifyPauseCompleted, notifyResumeCompleted, notifyServiceDisconnect}
}

// registerChannels allocates the next callback number and a channel per
// notification. With no arguments it registers the system set; a Process
// passes its own set (process exit + service disconnect).
func registerChannels(ns ...uint32) uintptr {
	callbackOnce.Do(func() { callbackPtr = syscall.NewCallback(watcher) })
	if len(ns) == 0 {
		ns = waitedOn()
	}
	channels := map[uint32]chan error{}
	for _, n := range ns {
		channels[n] = make(chan error, 1)
	}
	callbackMu.Lock()
	defer callbackMu.Unlock()
	callbackNext++
	number := callbackNext
	callbackMap[number] = channels
	return number
}

func channelFor(number uintptr, notification uint32) chan error {
	callbackMu.RLock()
	defer callbackMu.RUnlock()
	return callbackMap[number][notification]
}

func dropChannels(number uintptr) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	delete(callbackMap, number)
}

// -- string plumbing ---------------------------------------------------------------------

// takeString consumes and frees an out-parameter string HCS allocated with CoTaskMemAlloc.
// Every out-parameter string must go through here.
func takeString(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	_, _, _ = procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	return s
}

func utf16(s string) uintptr {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0
	}
	return uintptr(unsafe.Pointer(p))
}

// -- calls -------------------------------------------------------------------------------

// Create makes a compute system from a v2 document and waits for the create to complete. It
// does not start it.
func Create(id string, document any, timeout time.Duration) (*System, error) {
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}

	s := &System{ID: id, number: registerChannels()}

	var handle uintptr
	var result *uint16
	hr, _, _ := procCreate.Call(utf16(id), utf16(string(body)), 0,
		uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)

	if !ok(hr) && !isPending(hr) {
		dropChannels(s.number)
		return nil, &Error{Op: "HcsCreateComputeSystem", Code: uint32(hr), Result: doc}
	}
	s.handle = handle

	// The callback must be registered before the create completes is waited on -- HCS holds
	// the notification until something is listening.
	if err := s.registerCallback(); err != nil {
		_, _, _ = procClose.Call(handle)
		dropChannels(s.number)
		return nil, err
	}

	if isPending(hr) {
		if err := s.wait(notifyCreateCompleted, "HcsCreateComputeSystem", timeout); err != nil {
			_ = s.Terminate(30 * time.Second)
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Open reopens an existing compute system by id. A compute system is host-global, so a
// process that did not create it can still drive it.
func Open(id string) (*System, error) {
	s := &System{ID: id, number: registerChannels()}
	var handle uintptr
	var result *uint16
	hr, _, _ := procOpen.Call(utf16(id), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) {
		dropChannels(s.number)
		return nil, &Error{Op: "HcsOpenComputeSystem", Code: uint32(hr), Result: doc}
	}
	s.handle = handle
	if err := s.registerCallback(); err != nil {
		_, _, _ = procClose.Call(handle)
		dropChannels(s.number)
		return nil, err
	}
	return s, nil
}

func (s *System) registerCallback() error {
	var cb uintptr
	hr, _, _ := procRegister.Call(s.handle, callbackPtr, s.number, uintptr(unsafe.Pointer(&cb)))
	if !ok(hr) {
		return &Error{Op: "HcsRegisterComputeSystemCallback", Code: uint32(hr)}
	}
	s.callback = cb
	return nil
}

// Start boots the system and waits for the start to complete. For a VM, start completing
// means the firmware runs, not that the guest is up. Guest readiness is a separate probe.
func (s *System) Start(timeout time.Duration) error {
	return s.operation(procStart, "HcsStartComputeSystem", "", notifyStartCompleted, timeout)
}

// Shutdown asks the guest to shut down through the integration service, then waits for the
// system to exit. It needs the guest's shutdown IC, so it fails on a guest that lacks one.
func (s *System) Shutdown(timeout time.Duration) error {
	const options = `{"Mechanism":"IntegrationService","Type":"Shutdown"}`
	return s.operation(procShutdown, "HcsShutdownComputeSystem", options, notifyExited, timeout)
}

// Terminate powers the system off. It needs no guest cooperation.
func (s *System) Terminate(timeout time.Duration) error {
	return s.operation(procTerminate, "HcsTerminateComputeSystem", "", notifyExited, timeout)
}

// Pause suspends the system. For a VM this freezes the virtual processors; for
// a process-isolated container the platform refuses it (0x80070032,
// ERROR_NOT_SUPPORTED -- measured 2026-08-21 on the v2 route; the v1 route
// calls the same HcsPauseComputeSystem, so the outcome is route-independent by
// construction [v1 not measured]).
func (s *System) Pause(timeout time.Duration) error {
	return s.operation(procPause, "HcsPauseComputeSystem", "", notifyPauseCompleted, timeout)
}

// Resume restarts a paused system.
func (s *System) Resume(timeout time.Duration) error {
	return s.operation(procResume, "HcsResumeComputeSystem", "", notifyResumeCompleted, timeout)
}

func (s *System) operation(proc *windows.LazyProc, name, options string, notification uint32, timeout time.Duration) error {
	s.mu.Lock()
	handle := s.handle
	s.mu.Unlock()
	if handle == 0 {
		return &Error{Op: name, Code: uint32(windows.ERROR_INVALID_HANDLE)}
	}

	var opts uintptr
	if options != "" {
		opts = utf16(options)
	}
	var result *uint16
	hr, _, _ := proc.Call(handle, opts, uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if err, wait := awaitNeeded(hr, name, doc); err != nil {
		return err
	} else if wait {
		return s.wait(notification, name, timeout)
	}
	return nil
}

func (s *System) wait(notification uint32, name string, timeout time.Duration) error {
	ch := channelFor(s.number, notification)
	if ch == nil {
		return &Error{Op: name, Code: uint32(windows.ERROR_INVALID_HANDLE)}
	}
	disconnect := channelFor(s.number, notifyServiceDisconnect)
	select {
	case err := <-ch:
		if err != nil {
			if e, isHcs := err.(*Error); isHcs {
				e.Op = name
			}
			return err
		}
		return nil
	case <-disconnect:
		return &Error{Op: name, Code: uint32(windows.RPC_S_SERVER_UNAVAILABLE),
			Result: "the compute service disconnected"}
	case <-time.After(timeout):
		return fmt.Errorf("%s: no completion notification within %s", name, timeout)
	}
}

// Properties returns the system's property document. An empty query asks for the defaults.
func (s *System) Properties(query string) (string, error) {
	if query == "" {
		query = "{}"
	}
	var props, result *uint16
	hr, _, _ := procProperties.Call(s.handle, utf16(query),
		uintptr(unsafe.Pointer(&props)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	out := takeString(props)
	if !ok(hr) {
		return "", &Error{Op: "HcsGetComputeSystemProperties", Code: uint32(hr), Result: doc}
	}
	return out, nil
}

// Modify applies a settings document to a running system.
func (s *System) Modify(settings string) error {
	var result *uint16
	hr, _, _ := procModify.Call(s.handle, utf16(settings), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) && !isPending(hr) {
		return &Error{Op: "HcsModifyComputeSystem", Code: uint32(hr), Result: doc}
	}
	return nil
}

// Close releases the handle. When the document set ShouldTerminateOnLastHandleClosed, closing
// the last handle is what powers the system off -- so a caller that wants the VM to outlive
// the process must not set that.
func (s *System) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.callback != 0 {
		_, _, _ = procUnregister.Call(s.callback)
		s.callback = 0
	}
	if s.handle != 0 {
		_, _, _ = procClose.Call(s.handle)
		s.handle = 0
	}
	dropChannels(s.number)
}

// Enumerate lists compute systems the host knows about. The query is a JSON document; empty
// means everything.
func Enumerate(query string) (string, error) {
	if query == "" {
		query = "{}"
	}
	var systems, result *uint16
	hr, _, _ := procEnumerate.Call(utf16(query),
		uintptr(unsafe.Pointer(&systems)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	out := takeString(systems)
	if !ok(hr) {
		return "", &Error{Op: "HcsEnumerateComputeSystems", Code: uint32(hr), Result: doc}
	}
	return out, nil
}

// GrantVmAccess adds an ACE for a VM's own SID to a file, so the VM worker process can open
// it. A VHDX without the grant fails at start time with access-denied; the error names the
// disk, not the missing ACE. Callers grant every attached path, not only newly created ones.
//
// It is exported from vmcompute.dll under this bare name, not an Hcs-prefixed one.
func GrantVmAccess(vmID, path string) error {
	hr, _, _ := procGrant.Call(utf16(vmID), utf16(path))
	if !ok(hr) {
		return &Error{Op: "GrantVmAccess", Code: uint32(hr), Result: path}
	}
	return nil
}

// RevokeVmAccess removes the ACE GrantVmAccess added.
//
// The ACE persists after the VM is removed (measured: grants survive create/rm cycles).
// Without revoke, a base image accumulates one dead "NT VIRTUAL MACHINE\<guid>" entry per VM.
//
// Exported from vmcompute.dll under the bare name, like GrantVmAccess.
func RevokeVmAccess(vmID, path string) error {
	hr, _, _ := procRevoke.Call(utf16(vmID), utf16(path))
	if !ok(hr) {
		return &Error{Op: "RevokeVmAccess", Code: uint32(hr), Result: path}
	}
	return nil
}

// IsNotFound reports whether the host has no compute system by that id. This is the normal
// state of a VM that has shut down, not only of one that never existed: HCS destroys the
// compute system when it exits, so "stopped" and "never created" are the same answer here.
func IsNotFound(err error) bool {
	e, isHcs := err.(*Error)
	return isHcs && e.Code == systemNotFound
}

const systemNotFound = 0xC037010E // HCS_E_SYSTEM_NOT_FOUND

func ok(hr uintptr) bool        { return hr == sOK || hr == sFalse }
func isPending(hr uintptr) bool { return uint32(hr) == pending }

// awaitNeeded classifies a completed HRESULT: a non-pending failure is the error to report,
// a non-pending success needs no completion notification, and only a pending result waits.
func awaitNeeded(hr uintptr, name, doc string) (error, bool) {
	if !ok(hr) && !isPending(hr) {
		return &Error{Op: name, Code: uint32(hr), Result: doc}, false
	}
	if isPending(hr) {
		return nil, true
	}
	return nil, false
}

// -- processes ---------------------------------------------------------------------------
//
// The v2 route runs guest processes through HcsCreateProcess / HcsOpenProcess /
// HcsTerminateProcess / HcsGetProcessProperties with a per-process callback
// (hcsNotificationProcessExited is delivered on the PROCESS callback, never the
// system one -- measured 2026-08-21; a system-callback wait hangs to its bound).
// hcsshim exports no public v2 process API, so these bindings mirror its
// internal/hcs process.go shapes without copying source. The container package
// adapts this type to the verb surface (Stdio, WaitTimeout, Kill, ExitCode).

// ProcessInfo is the HCS_PROCESS_INFORMATION returned by HcsCreateProcess: the
// guest pid and the three stdio handles HCS created for it.
type ProcessInfo struct {
	ProcessID uint32
	_         uint32 // reserved padding, must stay
	StdInput  syscall.Handle
	StdOutput syscall.Handle
	StdError  syscall.Handle
}

// processStatus is the ProcessStatus property document, subset that matters.
type processStatus struct {
	Exited         bool   `json:"Exited,omitempty"`
	ExitCode       uint32 `json:"ExitCode,omitempty"`
	LastWaitResult int32  `json:"LastWaitResult,omitempty"`
}

// Process is an open handle to a process inside a compute system, with its own
// process callback registered. It exposes the surface the container verbs need,
// matching hcsshim.Process's method shapes (minus ResizeConsole).
type Process struct {
	system   *System
	handle   syscall.Handle
	pid      uint32
	callback uintptr // registered HCS_CALLBACK, freed at Close
	number   uintptr // this Process's key in callbackMap

	stdioMu sync.Mutex
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser

	exitedOnce sync.Once
	exited     chan struct{}
	exitCode   int
	waitErr    error
}

// CreateProcess launches a process in the system. params is the v2
// ProcessParameters document; HCS creates the stdio pipes and returns their
// handles in ProcessInfo.
func (s *System) CreateProcess(params any) (*Process, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	handle := s.handle
	s.mu.Unlock()
	if handle == 0 {
		return nil, &Error{Op: "HcsCreateProcess", Code: uint32(windows.ERROR_INVALID_HANDLE)}
	}

	p := &Process{system: s, number: registerChannels(notifyProcessExited, notifyServiceDisconnect), exited: make(chan struct{})}
	var info ProcessInfo
	var ph syscall.Handle
	var result *uint16
	hr, _, _ := procCreateProcess.Call(handle, utf16(string(body)),
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&ph)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) {
		dropChannels(p.number)
		return nil, &Error{Op: "HcsCreateProcess", Code: uint32(hr), Result: doc}
	}
	p.handle = ph
	p.pid = info.ProcessID

	if err := p.registerCallback(); err != nil {
		p.Close()
		return nil, err
	}
	files, err := makeOpenFiles([]syscall.Handle{info.StdInput, info.StdOutput, info.StdError})
	if err != nil {
		p.Close()
		return nil, err
	}
	p.stdioMu.Lock()
	if files[0] != nil {
		p.stdin = files[0]
	}
	if files[1] != nil {
		p.stdout = files[1]
	}
	if files[2] != nil {
		p.stderr = files[2]
	}
	p.stdioMu.Unlock()
	go p.waitBackground()
	return p, nil
}

// OpenProcess gets a handle to an existing process by pid, e.g. for a kill
// delivered through a fresh system handle (hcsshim's Kill shape).
func (s *System) OpenProcess(pid int) (*Process, error) {
	p := &Process{system: s, number: registerChannels(notifyProcessExited, notifyServiceDisconnect), exited: make(chan struct{})}
	var ph syscall.Handle
	var result *uint16
	hr, _, _ := procOpenProcess.Call(s.handle, uintptr(uint32(pid)),
		uintptr(unsafe.Pointer(&ph)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) {
		dropChannels(p.number)
		return nil, &Error{Op: "HcsOpenProcess", Code: uint32(hr), Result: doc}
	}
	p.handle = ph
	p.pid = uint32(pid)
	if err := p.registerCallback(); err != nil {
		p.Close()
		return nil, err
	}
	go p.waitBackground()
	return p, nil
}

func (p *Process) registerCallback() error {
	var cb uintptr
	hr, _, _ := procRegisterProcess.Call(uintptr(p.handle), callbackPtr, p.number,
		uintptr(unsafe.Pointer(&cb)))
	if !ok(hr) {
		return &Error{Op: "HcsRegisterProcessCallback", Code: uint32(hr)}
	}
	p.callback = cb
	return nil
}

func (p *Process) waitForExit() error {
	ch := channelFor(p.number, notifyProcessExited)
	if ch == nil {
		return &Error{Op: "process exit", Code: uint32(windows.ERROR_INVALID_HANDLE)}
	}
	disconnect := channelFor(p.number, notifyServiceDisconnect)
	select {
	case err := <-ch:
		if err != nil {
			if e, isHcs := err.(*Error); isHcs {
				e.Op = "process exit"
			}
			return err
		}
		return nil
	case <-disconnect:
		return &Error{Op: "process exit", Code: uint32(windows.RPC_S_SERVER_UNAVAILABLE),
			Result: "the compute service disconnected"}
	}
}

// waitBackground waits for the process-exit notification, reads the reaped exit
// code, and releases Wait/WaitTimeout. Called exactly once per process handle.
func (p *Process) waitBackground() {
	err := p.waitForExit()
	code := -1
	if err == nil {
		// The notification means the process is reaped, so the property read is
		// authoritative. Reading before the notification yields 0xFFFFFFFF (the
		// measured pre-reap artifact) -- the notification is what makes the
		// read trustworthy, which is why the surface binds the callback.
		st, perr := p.properties()
		if perr != nil {
			err = perr
		} else {
			code = int(st.ExitCode)
		}
	}
	p.exitedOnce.Do(func() {
		p.exitCode = code
		p.waitErr = err
		close(p.exited)
	})
}

// Pid returns the process id within the container.
func (p *Process) Pid() int {
	return int(p.pid)
}

// Stdio returns the process's stdin, stdout and stderr pipes.
func (p *Process) Stdio() (io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	p.stdioMu.Lock()
	defer p.stdioMu.Unlock()
	return p.stdin, p.stdout, p.stderr, nil
}

// CloseStdin closes the write side of the stdin pipe so the guest sees EOF. The
// modify request is what tells the guest; the local file close follows.
func (p *Process) CloseStdin() error {
	if p.stopped() {
		return nil
	}
	const req = `{"Operation":"CloseHandle","CloseHandle":{"Handle":"StdIn"}}`
	var result *uint16
	hr, _, _ := procModifyProcess.Call(uintptr(p.handle), utf16(req), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) {
		return &Error{Op: "HcsModifyProcess", Code: uint32(hr), Result: doc}
	}
	p.stdioMu.Lock()
	if p.stdin != nil {
		_ = p.stdin.Close()
		p.stdin = nil
	}
	p.stdioMu.Unlock()
	return nil
}

// Wait blocks until the process exits. It returns the exit notification error,
// if any; the exit code itself comes from ExitCode.
func (p *Process) Wait() error {
	<-p.exited
	return p.waitErr
}

// WaitTimeout waits for the exit or the duration. The timeout error wraps
// hcsshim.ErrTimeout so hcsshim.IsTimeout recognizes it, matching the v1 route.
func (p *Process) WaitTimeout(d time.Duration) error {
	select {
	case <-p.exited:
		return p.waitErr
	case <-time.After(d):
		return fmt.Errorf("process wait: %w", hcsshim.ErrTimeout)
	}
}

// ExitCode returns the exit code. The process must have exited (Wait/WaitTimeout
// must have returned first).
func (p *Process) ExitCode() (int, error) {
	<-p.exited
	return p.exitCode, p.waitErr
}

// Kill terminates the process. It delivers the terminate through a fresh system
// handle (hcsshim's Kill shape): HCS serializes signals per compute-system
// handle, so a kill behind a stuck operation on our handle would never deliver.
// It does not wait; WaitTimeout confirms.
func (p *Process) Kill() error {
	if p.stopped() {
		return &Error{Op: "HcsTerminateProcess", Code: uint32(windows.ERROR_INVALID_HANDLE),
			Result: "process already exited"}
	}
	sys2, err := Open(p.system.ID)
	if err != nil {
		return err
	}
	defer sys2.Close()
	ph2, err := sys2.OpenProcess(p.Pid())
	if err != nil {
		return err
	}
	defer ph2.Close()
	return ph2.terminate()
}

func (p *Process) terminate() error {
	var result *uint16
	hr, _, _ := procTerminateProcess.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	if !ok(hr) {
		return &Error{Op: "HcsTerminateProcess", Code: uint32(hr), Result: doc}
	}
	return nil
}

// properties reads the process property document (three native args: process,
// properties, result -- the two-arg call AV'd in the probe, measured).
func (p *Process) properties() (processStatus, error) {
	var props, result *uint16
	hr, _, _ := procGetProcessProps.Call(uintptr(p.handle),
		uintptr(unsafe.Pointer(&props)), uintptr(unsafe.Pointer(&result)))
	doc := takeString(result)
	out := takeString(props)
	if !ok(hr) {
		return processStatus{}, &Error{Op: "HcsGetProcessProperties", Code: uint32(hr), Result: doc}
	}
	var st processStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return processStatus{}, err
	}
	return st, nil
}

func (p *Process) stopped() bool {
	select {
	case <-p.exited:
		return true
	default:
		return false
	}
}

// Close releases the process handle, its callback and its stdio pipes. It does
// not kill or wait on the process.
func (p *Process) Close() error {
	var first error
	if p.callback != 0 {
		hr, _, _ := procUnregisterProcess.Call(p.callback)
		if !ok(hr) {
			first = &Error{Op: "HcsUnregisterProcessCallback", Code: uint32(hr)}
		}
		p.callback = 0
	}
	p.stdioMu.Lock()
	if p.stdin != nil {
		_ = p.stdin.Close()
		p.stdin = nil
	}
	if p.stdout != nil {
		_ = p.stdout.Close()
		p.stdout = nil
	}
	if p.stderr != nil {
		_ = p.stderr.Close()
		p.stderr = nil
	}
	p.stdioMu.Unlock()
	if p.handle != 0 {
		hr, _, _ := procCloseProcess.Call(uintptr(p.handle))
		if !ok(hr) && first == nil {
			first = &Error{Op: "HcsCloseProcess", Code: uint32(hr)}
		}
		p.handle = 0
	}
	dropChannels(p.number)
	p.exitedOnce.Do(func() {
		p.exitCode = -1
		p.waitErr = &Error{Op: "process exit", Code: uint32(windows.ERROR_INVALID_HANDLE), Result: "process closed"}
		close(p.exited)
	})
	return first
}

// makeOpenFiles wraps HCS-created stdio handles in go-winio file objects,
// closing every handle if any wrap fails.
func makeOpenFiles(hs []syscall.Handle) (_ []io.ReadWriteCloser, err error) {
	fs := make([]io.ReadWriteCloser, len(hs))
	for i, h := range hs {
		if h != syscall.Handle(0) {
			if err == nil {
				fs[i], err = winio.NewOpenFile(windows.Handle(h))
			}
			if err != nil {
				syscall.Close(h)
			}
		}
	}
	if err != nil {
		for _, f := range fs {
			if f != nil {
				f.Close()
			}
		}
		return nil, err
	}
	return fs, nil
}
