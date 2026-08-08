//go:build windows

// Package vmcompute is a narrow binding to the v2 compute-system API in vmcompute.dll.
//
// # Why this package exists
//
// The repo rule is public hcsshim packages only. hcsshim exports exactly one compute-system
// constructor, `hcsshim.CreateContainer`, and it takes a schema 1 `ContainerConfig`. Schema 1
// cannot express a `VirtualMachine` document, so it cannot express a VHDX boot, a UEFI firmware
// section, a COM port or an HvSocket service table. Everything that can is in hcsshim's
// internal/hcs and internal/uvm, which are not importable.
//
// So this is not a case of leaning on somebody's private helper when a public one exists.
// hcsshim never exported the v2 API to any consumer. The amended rule (issue #34):
//
//	Public hcsshim packages only. Where hcsshim exports no public equivalent -- today, the v2
//	compute-system API -- bind the documented Windows entry point in vmcompute.dll directly.
//	Copying or vendoring hcsshim's internal/ source is still out.
//
// # Shape
//
// Every call is asynchronous. It returns either a terminal HRESULT or ERROR_VMCOMPUTE_OPERATION_PENDING,
// and completion arrives on a registered callback. So a System registers its callback at open
// time and each operation waits on the notification that names it. S_FALSE (1) is a success
// HRESULT, which is why success is a range and not a value.
package vmcompute

import (
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

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
	procProperties = dll.NewProc("HcsGetComputeSystemProperties")
	procModify     = dll.NewProc("HcsModifyComputeSystem")
	procEnumerate  = dll.NewProc("HcsEnumerateComputeSystems")
	procRegister   = dll.NewProc("HcsRegisterComputeSystemCallback")
	procUnregister = dll.NewProc("HcsUnregisterComputeSystemCallback")
	procGrant      = dll.NewProc("GrantVmAccess")

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
	notifyServiceDisconnect = 0x01000000
)

// Error carries the HRESULT and, when HCS supplied one, the result document. The document is
// where HCS says which part of the configuration it disliked, so it is not discarded.
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
		// Buffered, depth 1. A second notification of the same type is dropped rather than
		// blocking a native callback thread inside the VM worker process.
		select {
		case ch <- err:
		default:
		}
	}
	return 0
}

func waitedOn() []uint32 {
	return []uint32{notifyExited, notifyCreateCompleted, notifyStartCompleted, notifyServiceDisconnect}
}

func registerChannels() uintptr {
	callbackOnce.Do(func() { callbackPtr = syscall.NewCallback(watcher) })
	channels := map[uint32]chan error{}
	for _, n := range waitedOn() {
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

// takeString consumes an out-parameter string HCS allocated with CoTaskMemAlloc. Not freeing
// it leaks once per call, so every path that can produce one goes through here.
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

// Start boots the system and waits for the start to complete. Note what this does NOT mean:
// for a VM, start completing is the firmware running, not the guest being up. Guest readiness
// is a separate probe.
func (s *System) Start(timeout time.Duration) error {
	return s.operation(procStart, "HcsStartComputeSystem", "", notifyStartCompleted, timeout)
}

// Shutdown asks the guest to shut down through the integration service, then waits for the
// system to exit. It needs the guest's shutdown IC, so it fails on a guest that lacks one.
func (s *System) Shutdown(timeout time.Duration) error {
	const options = `{"Mechanism":"IntegrationService","Type":"Shutdown"}`
	return s.operation(procShutdown, "HcsShutdownComputeSystem", options, notifyExited, timeout)
}

// Terminate powers the system off. It is the unconditional one: no guest cooperation.
func (s *System) Terminate(timeout time.Duration) error {
	return s.operation(procTerminate, "HcsTerminateComputeSystem", "", notifyExited, timeout)
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
	if !ok(hr) && !isPending(hr) {
		return &Error{Op: name, Code: uint32(hr), Result: doc}
	}
	return s.wait(notification, name, timeout)
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
// it. A VHDX that has never been granted opens as access-denied at start time, and the error
// names the disk rather than the missing ACE -- which is why this is called on every attached
// path rather than only on a newly created one.
//
// It is exported from vmcompute.dll under this bare name, not an Hcs-prefixed one.
func GrantVmAccess(vmID, path string) error {
	hr, _, _ := procGrant.Call(utf16(vmID), utf16(path))
	if !ok(hr) {
		return &Error{Op: "GrantVmAccess", Code: uint32(hr), Result: path}
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
