//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestRegistryBootID(t *testing.T) {
	if path := os.Getenv("HCS_TEST_BOOT_PATH"); path != "" {
		id, err := registryBootID(registry.CURRENT_USER, path, os.Getenv("HCS_TEST_BOOT_MUTEX"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Print(id)
		return
	}
	id, err := newBootID()
	if err != nil {
		t.Fatal(err)
	}
	path := `Software\hcsctl-boot-test-` + id
	mutex := `Local\hcsctl-boot-test-` + id
	t.Cleanup(func() {
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Error(err)
		}
	})
	const count = 8
	results := make([]string, count)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestRegistryBootID$")
			cmd.Env = append(os.Environ(), "HCS_TEST_BOOT_PATH="+path, "HCS_TEST_BOOT_MUTEX="+mutex)
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("child: %v: %s", err, b)
				return
			}
			results[i] = strings.TrimSuffix(string(b), "PASS\n")
		}(i)
	}
	wg.Wait()
	for _, got := range results {
		if !validBootID(got) || got != results[0] {
			t.Fatalf("inconsistent process IDs: %q", results)
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue("BootID", "invalid"); err != nil {
		t.Fatal(err)
	}
	k.Close()
	if _, err := registryBootID(registry.CURRENT_USER, path, mutex); err == nil {
		t.Fatal("accepted invalid existing record")
	}
	k, err = registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.DeleteValue("BootID"); err != nil {
		t.Fatal(err)
	}
	k.Close()
	if _, err := registryBootID(registry.CURRENT_USER, path, mutex); err == nil {
		t.Fatal("accepted incomplete existing record")
	}
}
