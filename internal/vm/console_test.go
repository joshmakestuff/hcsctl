//go:build windows

package vm

import (
	"os"
	"testing"

	"github.com/joshmakestuff/hcsctl/internal/cli"
)

// The JSON contract is one parseable document on stdout, nothing else. Serial bytes are
// arbitrary guest firmware output; if the console streams them onto stdout under --json, the
// document that follows them is unparsable. The sink per mode is the contract.
func TestConsoleSinkKeepsStdoutForTheJSONDocument(t *testing.T) {
	cases := []struct {
		name string
		mode cli.Emit
	}{
		{"plain", cli.Emit{}},
		{"json", cli.Emit{JSON: true}},
		{"json+stream", cli.Emit{JSON: true, StreamJSON: true}},
		// StreamJSON without JSON has no effect anywhere; the sink is the plain one.
		{"stream alone", cli.Emit{StreamJSON: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink, closer := consoleSink(c.mode)
			defer closer()

			switch {
			case c.mode.JSON && c.mode.StreamJSON:
				if _, ok := sink.(*cli.StreamWriter); !ok {
					t.Fatalf("sink is %T, want *cli.StreamWriter", sink)
				}
			case c.mode.JSON:
				if sink != os.Stderr {
					t.Fatalf("sink is %v, want stderr: console bytes on stdout would corrupt the JSON document", sink)
				}
			default:
				if sink != os.Stdout {
					t.Fatalf("sink is %v, want stdout", sink)
				}
			}
		})
	}
}
