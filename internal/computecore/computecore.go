//go:build windows

// Package computecore binds computecore.dll, the documented public Host
// Compute System API, for both containers and full VMs -- the one compute
// binding in this tool. It replaces internal/vmcompute (the legacy RPC
// surface) and hcsshim's schema-1 container surface.
//
// The API is operation-based and this package waits synchronously: every call
// makes an HCS_OPERATION, invokes the function, and blocks in
// HcsWaitForOperationResult (or ...AndProcessInfo). There are no notification
// callbacks anywhere -- the operation result IS the completion, which deletes
// the vmcompute binding's entire syscall.NewCallback/channel apparatus.
//
// Measured constraints this package encodes (hcsspike probes/modernlc,
// docs/findings.md 2026-08-25):
//
//   - The shutdown export is HcsShutDownComputeSystem -- capital D. The
//     vmcompute spelling is not in computecore's export table.
//   - A VM shutdown REQUIRES the options document
//     {"Mechanism":"IntegrationService","Type":"Shutdown"}; NULL options fails
//     0x80070032, misdirecting to the missing-Services-section defect. A
//     container shutdown takes NULL options.
//   - A stopped system stays queryable while a handle is open (destroyed on
//     last close), and its stopped property document reports SystemType
//     "Container" even for a VM. Exit detection is Stopped:true in the
//     properties, never properties-stops-answering.
//   - HcsWaitForProcessExit's ProcessStatus carries the real exit code -- no
//     0xFFFFFFFF pre-reap artifact on this route.
//   - Result documents are freed with LocalFree (vmcompute's are CoTaskMemFree).
package computecore

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dll = windows.NewLazySystemDLL("computecore.dll")

	procCreateOperation = dll.NewProc("HcsCreateOperation")
	procCloseOperation  = dll.NewProc("HcsCloseOperation")
	procWaitResult      = dll.NewProc("HcsWaitForOperationResult")
	procWaitResultProc  = dll.NewProc("HcsWaitForOperationResultAndProcessInfo")

	procCreateSystem    = dll.NewProc("HcsCreateComputeSystem")
	procOpenSystem      = dll.NewProc("HcsOpenComputeSystem")
	procCloseSystem     = dll.NewProc("HcsCloseComputeSystem")
	procStartSystem     = dll.NewProc("HcsStartComputeSystem")
	procShutdownSystem  = dll.NewProc("HcsShutDownComputeSystem")
	procTerminateSystem = dll.NewProc("HcsTerminateComputeSystem")
	procPauseSystem     = dll.NewProc("HcsPauseComputeSystem")
	procResumeSystem    = dll.NewProc("HcsResumeComputeSystem")
	procSystemProps     = dll.NewProc("HcsGetComputeSystemProperties")
	procModifySystem    = dll.NewProc("HcsModifyComputeSystem")
	procEnumerate       = dll.NewProc("HcsEnumerateComputeSystems")

	procCreateProcess    = dll.NewProc("HcsCreateProcess")
	procOpenProcess      = dll.NewProc("HcsOpenProcess")
	procCloseProcess     = dll.NewProc("HcsCloseProcess")
	procTerminateProcess = dll.NewProc("HcsTerminateProcess")
	procProcessProps     = dll.NewProc("HcsGetProcessProperties")
	procModifyProcess    = dll.NewProc("HcsModifyProcess")
	procWaitProcessExit  = dll.NewProc("HcsWaitForProcessExit")

	procGrantVmAccess  = dll.NewProc("HcsGrantVmAccess")
	procRevokeVmAccess = dll.NewProc("HcsRevokeVmAccess")
)

// HRESULTs that carry meaning to callers. computecore reports these WITHOUT
// the customer bit vmcompute set (0x8037010E where vmcompute said 0xC037010E
// -- measured), so matching masks that bit.
const (
	hcsNotFound       = 0x8037010E // HCS_E_SYSTEM_NOT_FOUND
	hcsAlreadyStopped = 0x80370110 // HCS_E_VM_ALREADY_STOPPED -- also what a
	// terminate after a completed graceful shutdown returns (measured)

	// severityBit is what separates vmcompute's 0xC037010E from computecore's
	// 0x8037010E for the same condition.
	severityBit = 0x40000000
)

func codeIs(err error, hresult uint32) bool {
	e, ok := err.(*Error)
	return ok && e.Code&^uint32(severityBit) == hresult
}

// Error carries the HRESULT and, when HCS supplied one, the result document.
// The document names the part of the configuration HCS rejected -- the single
// most valuable diagnostic HCS emits. Op is the computecore entry point.
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

// IsNotFound reports whether err is HCS saying the compute system does not
// exist. HCS destroys a system when it exits (once the last handle closes), so
// not-found is the ordinary "stopped" answer, not an anomaly.
func IsNotFound(err error) bool { return codeIs(err, hcsNotFound) }

// IsAlreadyStopped reports whether err is HCS refusing an operation because
// the system has already stopped.
func IsAlreadyStopped(err error) bool { return codeIs(err, hcsAlreadyStopped) }

// -- operations --------------------------------------------------------------------------

func utf16arg(s string) uintptr {
	if s == "" {
		return 0
	}
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0
	}
	return uintptr(unsafe.Pointer(p))
}

// takeLocalString frees with LocalFree -- the computecore contract for result
// documents.
func takeLocalString(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(p)))
	return s
}

func millis(timeout time.Duration) uintptr {
	if timeout <= 0 {
		return uintptr(windows.INFINITE)
	}
	return uintptr(timeout.Milliseconds())
}

func newOp(op string) (uintptr, error) {
	h, _, _ := procCreateOperation.Call(0, 0)
	if h == 0 {
		return 0, &Error{Op: op, Code: uint32(windows.E_FAIL)}
	}
	return h, nil
}

func closeOp(h uintptr) { _, _, _ = procCloseOperation.Call(h) }

// opWait blocks for the operation's result document. A non-zero wait HRESULT
// is the tracked function's failure and is reported under its name.
func opWait(op string, h uintptr, timeout time.Duration) (string, error) {
	var doc *uint16
	hr, _, _ := procWaitResult.Call(h, millis(timeout), uintptr(unsafe.Pointer(&doc)))
	s := takeLocalString(doc)
	if hr != 0 {
		return "", &Error{Op: op, Code: uint32(hr), Result: s}
	}
	return s, nil
}

// operation runs the make-op / call / wait shape shared by every asynchronous
// system call. extra are arguments placed after the operation handle.
func operation(op string, proc *windows.LazyProc, handle uintptr, timeout time.Duration, extra ...uintptr) (string, error) {
	oph, err := newOp(op)
	if err != nil {
		return "", err
	}
	defer closeOp(oph)
	args := append([]uintptr{handle, oph}, extra...)
	hr, _, _ := proc.Call(args...)
	if hr != 0 {
		return "", &Error{Op: op, Code: uint32(hr)}
	}
	return opWait(op, oph, timeout)
}

// -- compute systems ---------------------------------------------------------------------

// System is an open handle to a compute system. No callback is registered;
// there is nothing to unregister at Close.
type System struct {
	ID     string
	handle uintptr
}

// Create makes a compute system from a JSON document string and waits for the
// creation to complete. The document may be schema 2 (argon, VM) or schema 1
// (xenon) -- computecore accepts both (measured).
func Create(id, document string, timeout time.Duration) (*System, error) {
	const op = "HcsCreateComputeSystem"
	oph, err := newOp(op)
	if err != nil {
		return nil, err
	}
	defer closeOp(oph)
	var handle uintptr
	hr, _, _ := procCreateSystem.Call(utf16arg(id), utf16arg(document), oph, 0, uintptr(unsafe.Pointer(&handle)))
	if hr != 0 {
		return nil, &Error{Op: op, Code: uint32(hr)}
	}
	if _, err := opWait(op, oph, timeout); err != nil {
		_, _, _ = procCloseSystem.Call(handle)
		return nil, err
	}
	return &System{ID: id, handle: handle}, nil
}

// Open opens an existing compute system by id. Synchronous -- no operation.
// A system that has exited and dropped its last handle is simply gone:
// IsNotFound on the error is the "stopped" answer.
func Open(id string) (*System, error) {
	const op = "HcsOpenComputeSystem"
	var handle uintptr
	hr, _, _ := procOpenSystem.Call(utf16arg(id), uintptr(windows.GENERIC_ALL), uintptr(unsafe.Pointer(&handle)))
	if hr != 0 {
		return nil, &Error{Op: op, Code: uint32(hr)}
	}
	return &System{ID: id, handle: handle}, nil
}

// Enumerate lists compute systems host-wide as a JSON array. query is an HCS
// query document, or empty for everything.
func Enumerate(query string, timeout time.Duration) (string, error) {
	const op = "HcsEnumerateComputeSystems"
	oph, err := newOp(op)
	if err != nil {
		return "", err
	}
	defer closeOp(oph)
	hr, _, _ := procEnumerate.Call(utf16arg(query), oph)
	if hr != 0 {
		return "", &Error{Op: op, Code: uint32(hr)}
	}
	return opWait(op, oph, timeout)
}

// Start boots the system. For a VM, completion means the firmware runs, not
// that the guest is up; for a container, the guest is ready.
func (s *System) Start(timeout time.Duration) error {
	_, err := operation("HcsStartComputeSystem", procStartSystem, s.handle, timeout, 0)
	return err
}

// Shutdown asks the system to shut down. options is the shutdown options
// document: a container takes "" (measured); a VM requires
// {"Mechanism":"IntegrationService","Type":"Shutdown"} and a guest whose
// shutdown integration service is up.
func (s *System) Shutdown(options string, timeout time.Duration) error {
	_, err := operation("HcsShutDownComputeSystem", procShutdownSystem, s.handle, timeout, utf16arg(options))
	return err
}

// Terminate powers the system off. No guest cooperation.
func (s *System) Terminate(timeout time.Duration) error {
	_, err := operation("HcsTerminateComputeSystem", procTerminateSystem, s.handle, timeout, 0)
	return err
}

// Pause suspends the system. The platform refuses it for process-isolated
// containers (0x80070032); the caller reports that, not this package.
func (s *System) Pause(timeout time.Duration) error {
	_, err := operation("HcsPauseComputeSystem", procPauseSystem, s.handle, timeout, 0)
	return err
}

// Resume continues a paused system.
func (s *System) Resume(timeout time.Duration) error {
	_, err := operation("HcsResumeComputeSystem", procResumeSystem, s.handle, timeout, 0)
	return err
}

// Properties returns the system's property document. query is an HCS property
// query document such as {"PropertyTypes":["Statistics"]}, or empty for the
// default set. A stopped system answers while this handle is open; its
// document says Stopped:true (and SystemType "Container" even for a VM).
func (s *System) Properties(query string, timeout time.Duration) (string, error) {
	return operation("HcsGetComputeSystemProperties", procSystemProps, s.handle, timeout, utf16arg(query))
}

// Modify applies a modification document to the running system.
func (s *System) Modify(settings string, timeout time.Duration) error {
	_, err := operation("HcsModifyComputeSystem", procModifySystem, s.handle, timeout, utf16arg(settings), 0)
	return err
}

// Close releases the handle. It does not stop the system unless the document
// set ShouldTerminateOnLastHandleClosed and this was the last handle.
func (s *System) Close() {
	if s.handle != 0 {
		_, _, _ = procCloseSystem.Call(s.handle)
		s.handle = 0
	}
}

// -- processes ---------------------------------------------------------------------------

// Process is a process in a compute system. The std files are non-nil only for
// pipes requested at CreateProcess; OpenProcess yields none.
type Process struct {
	Pid    uint32
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
	handle uintptr
}

// hcsProcessInformation is HCS_PROCESS_INFORMATION: ProcessId, Reserved, then
// the three std handles.
type hcsProcessInformation struct {
	ProcessId uint32
	_         uint32
	StdInput  windows.Handle
	StdOutput windows.Handle
	StdError  windows.Handle
}

// CreateProcess starts a process in the system from a v2 ProcessParameters
// document and returns its pid and requested std pipes.
func (s *System) CreateProcess(params string, timeout time.Duration) (*Process, error) {
	const op = "HcsCreateProcess"
	oph, err := newOp(op)
	if err != nil {
		return nil, err
	}
	defer closeOp(oph)
	var handle uintptr
	hr, _, _ := procCreateProcess.Call(s.handle, utf16arg(params), oph, 0, uintptr(unsafe.Pointer(&handle)))
	if hr != 0 {
		return nil, &Error{Op: op, Code: uint32(hr)}
	}
	var info hcsProcessInformation
	var doc *uint16
	hr, _, _ = procWaitResultProc.Call(oph, millis(timeout),
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&doc)))
	msg := takeLocalString(doc)
	if hr != 0 {
		_, _, _ = procCloseProcess.Call(handle)
		return nil, &Error{Op: op, Code: uint32(hr), Result: msg}
	}
	p := &Process{Pid: info.ProcessId, handle: handle}
	if info.StdInput != 0 {
		p.Stdin = os.NewFile(uintptr(info.StdInput), "hcs-stdin")
	}
	if info.StdOutput != 0 {
		p.Stdout = os.NewFile(uintptr(info.StdOutput), "hcs-stdout")
	}
	if info.StdError != 0 {
		p.Stderr = os.NewFile(uintptr(info.StdError), "hcs-stderr")
	}
	return p, nil
}

// OpenProcess opens a process in the system by guest pid. Synchronous. The
// std pipes belong to whoever created the process; this handle has none.
func (s *System) OpenProcess(pid uint32) (*Process, error) {
	const op = "HcsOpenProcess"
	var handle uintptr
	hr, _, _ := procOpenProcess.Call(s.handle, uintptr(pid), uintptr(windows.GENERIC_ALL), uintptr(unsafe.Pointer(&handle)))
	if hr != 0 {
		return nil, &Error{Op: op, Code: uint32(hr)}
	}
	return &Process{Pid: pid, handle: handle}, nil
}

// ProcessStatus is HcsWaitForProcessExit's answer. The exit code is real on
// this route -- no pre-reap artifact (measured).
type ProcessStatus struct {
	ProcessID uint32 `json:"ProcessId"`
	Exited    bool   `json:"Exited"`
	ExitCode  int32  `json:"ExitCode"`
}

// WaitExit blocks until the process exits and returns its ProcessStatus
// document.
func (p *Process) WaitExit(timeout time.Duration) (string, error) {
	const op = "HcsWaitForProcessExit"
	var doc *uint16
	hr, _, _ := procWaitProcessExit.Call(p.handle, millis(timeout), uintptr(unsafe.Pointer(&doc)))
	s := takeLocalString(doc)
	if hr != 0 {
		return "", &Error{Op: op, Code: uint32(hr), Result: s}
	}
	return s, nil
}

// Properties returns the process property document (Exited, ExitCode, ...).
func (p *Process) Properties(query string, timeout time.Duration) (string, error) {
	return operation("HcsGetProcessProperties", procProcessProps, p.handle, timeout, utf16arg(query))
}

// Terminate kills the process.
func (p *Process) Terminate(timeout time.Duration) error {
	_, err := operation("HcsTerminateProcess", procTerminateProcess, p.handle, timeout, 0)
	return err
}

// CloseStdin closes the process's stdin on the guest side, the modern
// equivalent of hcsshim's Process.CloseStdin.
func (p *Process) CloseStdin(timeout time.Duration) error {
	const settings = `{"Operation":"CloseHandle","Handle":"StdIn"}`
	_, err := operation("HcsModifyProcess", procModifyProcess, p.handle, timeout, utf16arg(settings))
	return err
}

// Close releases the process handle and any std pipes still open.
func (p *Process) Close() {
	for _, f := range []*os.File{p.Stdin, p.Stdout, p.Stderr} {
		if f != nil {
			_ = f.Close()
		}
	}
	p.Stdin, p.Stdout, p.Stderr = nil, nil, nil
	if p.handle != 0 {
		_, _, _ = procCloseProcess.Call(p.handle)
		p.handle = 0
	}
}

// -- VM disk access grants ---------------------------------------------------------------

// GrantVmAccess adds an ACE for the VM's virtual account on the file. The VM
// worker opens a VHDX chain end to end, so a differencing child AND its parent
// both need the grant.
func GrantVmAccess(vmID, path string) error {
	hr, _, _ := procGrantVmAccess.Call(utf16arg(vmID), utf16arg(path))
	if hr != 0 {
		return &Error{Op: "HcsGrantVmAccess", Code: uint32(hr), Result: path}
	}
	return nil
}

// RevokeVmAccess removes the ACE GrantVmAccess added.
func RevokeVmAccess(vmID, path string) error {
	hr, _, _ := procRevokeVmAccess.Call(utf16arg(vmID), utf16arg(path))
	if hr != 0 {
		return &Error{Op: "HcsRevokeVmAccess", Code: uint32(hr), Result: path}
	}
	return nil
}
