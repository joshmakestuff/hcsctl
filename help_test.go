//go:build windows

package main

import (
	"strings"
	"testing"
)

// acceptedOptions is the recorded inventory of every verb's accepted options, mirroring
// each package's RejectUnknown arguments and the container createOptions slice. A
// verb's help synopsis must name every one of its options; this test fails when executable
// help drifts from the parser.
var acceptedOptions = map[string][]string{
	"image pull":         {"--ref", "--store"},
	"image import":       {"--ref", "--store"},
	"image ls":           {"--store"},
	"image rm":           {"--ref", "--store", "--blobs"},
	"layer mount":        {"--ref", "--id", "--store", "--scratch-size"},
	"layer unmount":      {"--id", "--ref", "--store"},
	"layer ls":           {"--store"},
	"container run":      {"--ref", "--id", "--store", "--cpus", "--memory-mb", "--hostname", "--isolation", "--network", "--dns-search", "--publish", "--acl", "--mount", "--scratch-size", "--cmd", "--label", "--cwd", "--user", "--env", "--timeout", "--keep"},
	"container create":   {"--ref", "--id", "--store", "--cpus", "--memory-mb", "--hostname", "--isolation", "--network", "--dns-search", "--publish", "--acl", "--mount", "--scratch-size", "--cmd", "--label"},
	"container start":    {"--id", "--ref", "--store"},
	"container stop":     {"--id", "--ref", "--store", "--force"},
	"container rm":       {"--id", "--ref", "--store", "--force"},
	"container kill":     {"--id", "--ref", "--store", "--pid"},
	"container logs":     {"--id", "--ref", "--store", "--follow"},
	"container exec":     {"--id", "--ref", "--store", "--cmd", "--cwd", "--user", "--env", "--timeout", "--interactive", "--tty"},
	"container ls":       {"--store"},
	"container stats":    {"--id", "--ref", "--store"},
	"container ps":       {"--id", "--ref", "--store"},
	"container inspect":  {"--id", "--ref", "--store"},
	"container pause":    {"--id", "--ref", "--store"},
	"container resume":   {"--id", "--ref", "--store"},
	"storage setup-base": {"--layer", "--size-gb"},
	"storage mount":      {"--base", "--ref", "--store", "--scratch-dir", "--parent"},
	"storage unmount":    {"--scratch-dir"},
	"storage export":     {"--layer", "--dest", "--parent", "--writable"},
	"storage import":     {"--source", "--layer", "--parent"},
	"storage destroy":    {"--layer"},
	"network ls":         {},
	"network endpoints":  {"--network"},
	"network create":     {"--name", "--type", "--subnet", "--gateway"},
	"network rm":         {"--id", "--name"},
	"network inspect":    {"--id", "--name"},
	"vm create":          {"--id", "--vhdx", "--cpus", "--memory-mb", "--serial-pipe", "--store", "--no-copy-on-write", "--network", "--dns", "--label"},
	"vm start":           {"--id", "--store"},
	"vm stop":            {"--id", "--force", "--store"},
	"vm rm":              {"--id", "--force", "--store"},
	"vm ip":              {"--id", "--timeout", "--store"},
	"vm netconfig":       {"--id", "--store", "--dns", "--interface", "--timeout"},
	"vm console":         {"--id", "--store", "--no-input", "--timeout"},
	"vm ls":              {"--store", "--all"},
	"vm inspect":         {"--id", "--store"},
	"guest info":         {"--vmid", "--timeout"},
	"guest exec":         {"--vmid", "--cmd", "--cwd", "--env", "--timeout"},
	"guest forward":      {"--vmid", "--listen", "--port", "--timeout"},
	"info":               {"--store"},
}

// synopsisBlock returns the help text for verb: from its synopsis line through the following
// continuation/prose lines, stopping at the next top-level (two-space) entry.
func synopsisBlock(verb string) string {
	lines := strings.Split(usageText, "\n")
	var b strings.Builder
	started := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "  "+verb+" ") {
			started = true
			b.WriteString(ln)
			b.WriteString("\n")
			continue
		}
		if !started {
			continue
		}
		// A new top-level entry is two spaces followed by a non-space.
		if len(ln) >= 2 && ln[:2] == "  " && len(ln) > 2 && ln[2] != ' ' {
			break
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

func TestHelpSynopsisListsEveryAcceptedOption(t *testing.T) {
	for verb, opts := range acceptedOptions {
		block := synopsisBlock(verb)
		if block == "" {
			t.Errorf("verb %q has no synopsis block in usageText", verb)
			continue
		}
		for _, opt := range opts {
			if !strings.Contains(block, opt) {
				t.Errorf("verb %q help does not mention %s (accepted by the parser)", verb, opt)
			}
		}
	}
}
