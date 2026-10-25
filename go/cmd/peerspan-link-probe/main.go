// peerspan-link-probe is a state-free signed-object and certificate-path adapter.
// It is not included in installed bundles and never authorizes a mutation.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/peerspan/peerspan/go/internal/linking"
)

func main() {
	stored := flag.Bool("stored-snapshot", false, "verify complete stored catalog snapshots")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(2)
	}
	limit := 2 << 20
	if *stored {
		limit = linking.MaxStoredProbe
	}
	in := bufio.NewReaderSize(os.Stdin, 64<<10)
	out := json.NewEncoder(os.Stdout)
	var line []byte
	overflow := false
	for {
		chunk, e := in.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			overflow = true
			line = nil
		} else if !overflow {
			line = append(line, chunk...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(line) > 0 || overflow {
			var result any = map[string]any{"ok": false, "code": "invalid"}
			if !overflow {
				if *stored {
					result = linking.ProbeStoredSnapshot(line)
				} else {
					result = linking.Probe(line)
				}
			}
			if out.Encode(result) != nil {
				return
			}
		}
		line = nil
		overflow = false
		if e != nil {
			if e != io.EOF {
				os.Exit(1)
			}
			return
		}
	}
}
