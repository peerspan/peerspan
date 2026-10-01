// Package protocol is the byte stream between the host and the guest agent.
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	OpExec    byte = 1
	OpUnmount byte = 2
	OpMount   byte = 3

	MaxArgs   = 256
	MaxArg    = 1 << 20
	MaxOutput = 4 << 20
)

// WriteRequest encodes one agent call.
func WriteRequest(w io.Writer, op byte, argv []string) error {
	var buf bytes.Buffer
	buf.WriteByte(op)
	if op == OpExec {
		if len(argv) > MaxArgs {
			return fmt.Errorf("microvm: too many arguments")
		}
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(argv))); err != nil {
			return err
		}
		for _, arg := range argv {
			if len(arg) > MaxArg {
				return fmt.Errorf("microvm: argument is too long")
			}
			if err := binary.Write(&buf, binary.BigEndian, uint32(len(arg))); err != nil {
				return err
			}
			buf.WriteString(arg)
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// ReadRequest decodes one agent call.
func ReadRequest(r io.Reader) (byte, []string, error) {
	var op [1]byte
	if _, err := io.ReadFull(r, op[:]); err != nil {
		return 0, nil, err
	}
	if op[0] != OpExec {
		return op[0], nil, nil
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	if n > MaxArgs {
		return 0, nil, fmt.Errorf("microvm: too many arguments")
	}
	argv := make([]string, n)
	for i := range argv {
		var ln uint32
		if err := binary.Read(r, binary.BigEndian, &ln); err != nil {
			return 0, nil, err
		}
		if ln > MaxArg {
			return 0, nil, fmt.Errorf("microvm: argument is too long")
		}
		b := make([]byte, ln)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, nil, err
		}
		argv[i] = string(b)
	}
	return op[0], argv, nil
}

// WriteResult encodes the exit code and combined output of one call.
func WriteResult(w io.Writer, code int32, out []byte) error {
	if len(out) > MaxOutput {
		out = out[:MaxOutput]
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, code); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(out))); err != nil {
		return err
	}
	buf.Write(out)
	_, err := w.Write(buf.Bytes())
	return err
}

// ReadResult decodes the exit code and combined output of one call.
func ReadResult(r io.Reader) (int32, []byte, error) {
	var code int32
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &code); err != nil {
		return 0, nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	if n > MaxOutput {
		return 0, nil, fmt.Errorf("microvm: output is too long")
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return 0, nil, err
	}
	return code, out, nil
}
