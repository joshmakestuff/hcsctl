//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCurrentLogonIdentityNative(t *testing.T) {
	var stats wnetTokenStatistics
	if unsafe.Sizeof(stats) != 56 || unsafe.Offsetof(stats.AuthenticationID) != 8 || unsafe.Offsetof(stats.ModifiedID) != 48 {
		t.Fatal("TOKEN_STATISTICS layout mismatch")
	}
	first, err := currentLogonIdentity()
	if err != nil || len(first) != 16 {
		t.Fatalf("current logon identity: %q: %v", first, err)
	}
	for i := 0; i < 100; i++ {
		got, err := currentLogonIdentity()
		if err != nil || got != first {
			t.Fatalf("query %d: %q: %v", i, got, err)
		}
	}
}

type fakeWNetStore struct {
	records    map[string]wnetRecord
	failPhase  string
	failDelete bool
}

func (s *fakeWNetStore) get(k string) (wnetRecord, bool, error) {
	r, ok := s.records[k]
	return r, ok, nil
}
func (s *fakeWNetStore) put(r wnetRecord) error {
	if r.Phase == s.failPhase {
		return errors.New("write failed")
	}
	s.records[r.Owner.Key] = r
	return nil
}
func (s *fakeWNetStore) delete(k string) error {
	if s.failDelete {
		return errors.New("delete failed")
	}
	delete(s.records, k)
	return nil
}

type fakeWNet struct {
	connected         bool
	userName          string
	addUser           string
	addErr, cancelErr error
	adds, cancels     int
	queries           int
}

func (a *fakeWNet) user(string) (string, bool, error) {
	a.queries++
	return a.userName, a.connected, nil
}
func (a *fakeWNet) add(_, user, _ string) error {
	a.adds++
	if a.addErr != nil {
		return a.addErr
	}
	a.connected = true
	a.userName = user
	if a.addUser != "" {
		a.userName = a.addUser
	}
	return nil
}
func (a *fakeWNet) cancel(string) error {
	a.cancels++
	if a.cancelErr != nil {
		return a.cancelErr
	}
	a.connected = false
	return nil
}
func TestWNetOwnership(t *testing.T) {
	remote := `\\server\share`
	digest := sha256.Sum256([]byte(strings.ToLower(remote)))
	req := globalRequest{Op: "add", Key: hex.EncodeToString(digest[:]), Token: strings.Repeat("a", 32), Remote: remote, User: "guest", Password: "secret", Port: 445}
	newBackend := func() (wnetBackend, *fakeWNetStore, *fakeWNet) {
		s := &fakeWNetStore{records: map[string]wnetRecord{}}
		a := &fakeWNet{}
		return wnetBackend{s, a, func() (string, string, error) { return "boot", "logon", nil }}, s, a
	}
	t.Run("confirmed lifecycle", func(t *testing.T) {
		b, s, a := newBackend()
		if err := b.run(req); err != nil {
			t.Fatal(err)
		}
		r := s.records[req.Key]
		if r.Phase != "connected" || r.Owner.Password != "" {
			t.Fatal(r)
		}
		x := req
		x.Op = "check"
		if err := b.run(x); err != nil {
			t.Fatal(err)
		}
		x.Op = "remove"
		if err := b.run(x); err != nil || a.cancels != 1 || len(s.records) != 0 {
			t.Fatalf("%v %+v", err, a)
		}
	})
	t.Run("preexisting connection", func(t *testing.T) {
		b, s, a := newBackend()
		a.connected = true
		a.userName = req.User
		if b.run(req) == nil || a.adds != 0 || len(s.records) != 0 {
			t.Fatal("adopted existing connection")
		}
	})
	t.Run("intent write failure prevents add", func(t *testing.T) {
		b, s, a := newBackend()
		s.failPhase = "intent"
		if b.run(req) == nil || a.adds != 0 || len(s.records) != 0 {
			t.Fatal("add proceeded without durable intent")
		}
	})
	t.Run("failed add remains uncertain", func(t *testing.T) {
		b, s, a := newBackend()
		a.addErr = errors.New("already assigned")
		if b.run(req) == nil || s.records[req.Key].Phase != "intent" {
			t.Fatal("missing intent")
		}
		x := req
		x.Op = "remove"
		if b.run(x) != nil || a.cancels != 0 || len(s.records) != 0 {
			t.Fatal("absent connection was not forgotten safely")
		}
	})
	t.Run("connected write failure remains uncertain", func(t *testing.T) {
		b, s, a := newBackend()
		s.failPhase = "connected"
		if b.run(req) == nil || s.records[req.Key].Phase != "intent" || !a.connected {
			t.Fatal("not uncertain")
		}
		x := req
		x.Op = "remove"
		if b.run(x) == nil || a.cancels != 0 {
			t.Fatal("cancelled uncertain connection")
		}
	})
	t.Run("changed logon", func(t *testing.T) {
		b, _, a := newBackend()
		if b.run(req) != nil {
			t.Fatal("add")
		}
		b.identity = func() (string, string, error) { return "boot", "other", nil }
		x := req
		x.Op = "remove"
		if b.run(x) == nil || a.cancels != 0 {
			t.Fatal("cancelled other logon")
		}
	})
	t.Run("failed cancel cannot retry blindly", func(t *testing.T) {
		b, s, a := newBackend()
		if b.run(req) != nil {
			t.Fatal("add")
		}
		a.cancelErr = errors.New("busy")
		x := req
		x.Op = "remove"
		if b.run(x) == nil || s.records[req.Key].Phase != "releasing" {
			t.Fatal("missing release intent")
		}
		a.cancelErr = nil
		if b.run(x) == nil || a.cancels != 1 {
			t.Fatal("repeated uncertain cancel")
		}
	})
	t.Run("nondefault port rejected", func(t *testing.T) {
		b, _, a := newBackend()
		x := req
		x.Port = 1445
		if b.run(x) == nil || a.adds != 0 {
			t.Fatal("accepted port")
		}
	})
	t.Run("canonical identity", func(t *testing.T) {
		b, s, a := newBackend()
		a.addUser = `HOST\guest`
		if err := b.run(req); err != nil {
			t.Fatal(err)
		}
		if s.records[req.Key].ConnectedUser != `HOST\guest` {
			t.Fatal("observed user not saved")
		}
		x := req
		x.Op = "check"
		if err := b.run(x); err != nil {
			t.Fatal(err)
		}
		a.userName = `OTHER\guest`
		x.Op = "remove"
		if b.run(x) == nil || a.cancels != 0 {
			t.Fatal("adopted different canonical identity")
		}
	})
	t.Run("unexpected post-add identity", func(t *testing.T) {
		b, s, a := newBackend()
		a.addUser = `HOST\other`
		if b.run(req) == nil || s.records[req.Key].Phase != "intent" {
			t.Fatal("unexpected identity accepted")
		}
	})
	for _, code := range []error{windows.ERROR_OPEN_FILES, windows.ERROR_DEVICE_IN_USE} {
		t.Run("busy "+code.Error(), func(t *testing.T) {
			b, s, a := newBackend()
			if err := b.run(req); err != nil {
				t.Fatal(err)
			}
			a.cancelErr = code
			x := req
			x.Op = "remove"
			if b.run(x) == nil || s.records[req.Key].Phase != "connected" {
				t.Fatal("busy did not preserve connection")
			}
			a.cancelErr = nil
			if err := b.run(x); err != nil || a.cancels != 2 {
				t.Fatalf("retry: %v", err)
			}
		})
	}
	t.Run("successful cancel and failed delete", func(t *testing.T) {
		b, s, a := newBackend()
		if err := b.run(req); err != nil {
			t.Fatal(err)
		}
		s.failDelete = true
		x := req
		x.Op = "remove"
		if b.run(x) == nil || a.connected || s.records[req.Key].Phase != "releasing" {
			t.Fatal("expected pending delete")
		}
		s.failDelete = false
		if err := b.run(x); err != nil || a.cancels != 1 {
			t.Fatalf("retry: %v", err)
		}
	})
	t.Run("old boot forgets without network query", func(t *testing.T) {
		b, s, a := newBackend()
		if err := b.run(req); err != nil {
			t.Fatal(err)
		}
		b.identity = func() (string, string, error) { return "next boot", "logon", nil }
		queries := a.queries
		x := req
		x.Op = "remove"
		x.Token = strings.Repeat("b", 32)
		if b.run(x) == nil || a.queries != queries || len(s.records) != 1 {
			t.Fatal("accepted wrong token")
		}
		x.Token = req.Token
		if err := b.run(x); err != nil || a.queries != queries || a.cancels != 0 || len(s.records) != 0 {
			t.Fatal("old record not safely forgotten")
		}
	})
}

func TestWNetRecordEncoding(t *testing.T) {
	remote := `\\server\share`
	digest := sha256.Sum256([]byte(strings.ToLower(remote)))
	key := hex.EncodeToString(digest[:])
	record := wnetRecord{Owner: globalRequest{Op: "add", Key: key, Token: strings.Repeat("a", 32), Remote: remote, User: "guest", Password: "sensitive-password", Port: 445}, Boot: "boot", Logon: "logon", Phase: "intent"}
	data, err := encodeWNetRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), record.Owner.Password) {
		t.Fatal("password persisted")
	}
	got, exists, err := decodeWNetRecord(key, data, nil)
	if err != nil || !exists || got.Owner.Password != "" || got.Owner.Op != "remove" || got.Phase != "intent" {
		t.Fatalf("round trip: %+v %v %v", got, exists, err)
	}
	if _, exists, err = decodeWNetRecord(key, nil, windows.ERROR_FILE_NOT_FOUND); err != nil || exists {
		t.Fatalf("empty initialization: %v %v", exists, err)
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		readErr error
		key     string
	}{
		{name: "invalid json", data: []byte(`{"Owner":`), key: key},
		{name: "empty value", data: []byte{}, key: key},
		{name: "wrong key", data: data, key: strings.Repeat("0", 64)},
		{name: "access denied", readErr: windows.ERROR_ACCESS_DENIED, key: key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeWNetRecord(tc.key, tc.data, tc.readErr); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	bad := record
	bad.Phase = "connected"
	bad.ConnectedUser = ""
	if _, err := encodeWNetRecord(bad); err == nil {
		t.Fatal("connected record without observed user")
	}
}
