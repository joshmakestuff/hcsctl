//go:build windows

package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func digestOf(b []byte) string {
	return hex.EncodeToString(func() []byte { s := sha256.Sum256(b); return s[:] }())
}

func TestWriteVerifiedLeavesNoPartialOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	content := []byte("verified-bytes")
	n, err := writeVerified(path, bytes.NewReader(content), digestOf(content))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(content)) {
		t.Fatalf("n = %d, want %d", n, len(content))
	}
	if got, _ := os.ReadFile(path); string(got) != string(content) {
		t.Fatalf("content = %q", got)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "blob.partial-*"))
	if len(matches) != 0 {
		t.Fatalf("partial files left behind: %v", matches)
	}
}

func TestWriteVerifiedCleansTempOnMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	_, err := writeVerified(path, bytes.NewReader([]byte("wrong")), digestOf([]byte("right")))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v, want digest mismatch", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("destination must not exist after a failed verify, statErr = %v", statErr)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "blob.partial-*"))
	if len(matches) != 0 {
		t.Fatalf("partial files left behind: %v", matches)
	}
}

func TestBlobSizeVerified(t *testing.T) {
	dir := t.TempDir()
	content := []byte("blob-content")
	path := filepath.Join(dir, "blob")
	os.WriteFile(path, content, 0o644)

	t.Run("match", func(t *testing.T) {
		n, err := blobSizeVerified(path, digestOf(content))
		if err != nil || n != int64(len(content)) {
			t.Fatalf("n = %d, err = %v", n, err)
		}
	})
	t.Run("mismatch wraps errCorruptBlob", func(t *testing.T) {
		_, err := blobSizeVerified(path, digestOf([]byte("other")))
		if !errors.Is(err, errCorruptBlob) {
			t.Fatalf("err = %v, want errCorruptBlob", err)
		}
	})
	t.Run("missing wraps os.ErrNotExist", func(t *testing.T) {
		_, err := blobSizeVerified(filepath.Join(dir, "absent"), digestOf(content))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want os.ErrNotExist", err)
		}
	})
}

func TestEnsureBlobReusesVerifiedExisting(t *testing.T) {
	dir := t.TempDir()
	content := []byte("already-here")
	path := filepath.Join(dir, "blob")
	os.WriteFile(path, content, 0o644)

	called := 0
	dl := func() (io.ReadCloser, error) {
		called++
		return io.NopCloser(bytes.NewReader(content)), nil
	}
	n, downloaded, err := ensureBlob(path, digestOf(content), dl)
	if err != nil || downloaded || n != int64(len(content)) {
		t.Fatalf("n=%d downloaded=%v err=%v", n, downloaded, err)
	}
	if called != 0 {
		t.Fatalf("download called %d times for a verified blob", called)
	}
}

func TestEnsureBlobRedownloadsCorrupt(t *testing.T) {
	dir := t.TempDir()
	content := []byte("correct-content")
	path := filepath.Join(dir, "blob")
	os.WriteFile(path, []byte("corrupt"), 0o644)

	dl := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(content)), nil }
	n, downloaded, err := ensureBlob(path, digestOf(content), dl)
	if err != nil || !downloaded || n != int64(len(content)) {
		t.Fatalf("n=%d downloaded=%v err=%v", n, downloaded, err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(content) {
		t.Fatalf("corrupt blob not replaced: %q", got)
	}
}

func TestEnsureBlobConcurrentWritersConverge(t *testing.T) {
	dir := t.TempDir()
	content := []byte("same-content-for-every-writer")
	path := filepath.Join(dir, "blob")
	want := digestOf(content)

	const writers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
		defer wg.Done()
			<-start
			dl := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(content)), nil }
			_, _, errs[i] = ensureBlob(path, want, dl)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != string(content) {
		t.Fatalf("converged content = %q", got)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "blob.partial-*"))
	if len(matches) != 0 {
		t.Fatalf("partial files left behind: %v", matches)
	}
}
