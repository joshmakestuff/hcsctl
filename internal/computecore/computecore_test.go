//go:build windows

package computecore

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestErrorFormatsCodeAndResult(t *testing.T) {
	e := &Error{Op: "HcsCreateComputeSystem", Code: 0x80070032, Result: `{"Error":-2147024846}`}
	msg := e.Error()
	for _, want := range []string{"HcsCreateComputeSystem", "0x80070032", `{"Error":-2147024846}`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
}

func TestErrorWithoutResultOmitsSuffix(t *testing.T) {
	e := &Error{Op: "HcsStartComputeSystem", Code: 0xC037010E}
	if strings.HasSuffix(e.Error(), ": ") {
		t.Errorf("dangling separator in %q", e.Error())
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(&Error{Op: "x", Code: hcsNotFound}) {
		t.Error("HCS_E_SYSTEM_NOT_FOUND not recognised")
	}
	if IsNotFound(&Error{Op: "x", Code: 0x80070005}) {
		t.Error("access denied misread as not-found")
	}
	if IsNotFound(nil) {
		t.Error("nil misread as not-found")
	}
}

func TestIsAlreadyStopped(t *testing.T) {
	if !IsAlreadyStopped(&Error{Op: "x", Code: hcsAlreadyStopped}) {
		t.Error("HCS_E_VM_ALREADY_STOPPED not recognised")
	}
	if IsAlreadyStopped(&Error{Op: "x", Code: hcsNotFound}) {
		t.Error("not-found misread as already-stopped")
	}
}

func TestProcessStatusParsesMeasuredShape(t *testing.T) {
	// The measured HcsWaitForProcessExit document (cmd /c exit 42).
	const doc = `{"ProcessId":69576,"Exited":true,"ExitCode":42,"LastWaitResult":0}`
	var st ProcessStatus
	if err := json.Unmarshal([]byte(doc), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Exited || st.ExitCode != 42 || st.ProcessID != 69576 {
		t.Errorf("parsed %+v from the measured document", st)
	}
}
