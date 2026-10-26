package decentralized

import (
	"bufio"
	"encoding/json"
	"io"
)

func probeFailure(e error) any {
	return struct {
		OK   bool     `json:"ok"`
		Code string   `json:"code"`
		IDs  []string `json:"required_ids"`
	}{false, Code(e), RequiredIDs(e)}
}

// Probe is a pure public verifier adapter. A decoder result never claims
// authority, local key ownership, durable consent or actual application.
func Probe(raw []byte) any {
	o, e := parseLimit(raw, MaxProbe)
	if e != nil {
		return probeFailure(e)
	}
	if version(o, 1) != nil {
		return probeFailure(invalid())
	}
	kind, e := text(o, "kind")
	if e != nil {
		return probeFailure(e)
	}
	if kind == "clock" {
		if fields(o, "format kind now clock_guard") != nil {
			return probeFailure(invalid())
		}
		a, e := texts(o, "now", "clock_guard")
		if e != nil {
			return probeFailure(e)
		}
		decision, e := DecisionTime(a[0], a[1])
		if e != nil {
			return probeFailure(e)
		}
		return map[string]any{"ok": true, "decision_time": decision, "next_guard": decision}
	}
	names := map[string]string{"descriptor": "format kind descriptor_base64", "statement": "format kind descriptor_base64 statement_base64", "catalog": "format kind descriptor_base64 catalog_base64"}
	required, ok := names[kind]
	if !ok || fields(o, required) != nil {
		return probeFailure(invalid())
	}
	encoded, e := text(o, "descriptor_base64")
	if e != nil {
		return probeFailure(e)
	}
	descriptorRaw, e := decode(encoded, MaxObject)
	if e != nil {
		return probeFailure(e)
	}
	d, e := ReadDescriptor(descriptorRaw)
	if e != nil {
		return probeFailure(e)
	}
	switch kind {
	case "descriptor":
		return map[string]any{"ok": true, "context_id": d.ContextID, "network_id": d.NetworkID, "genesis_root_public_key": d.GenesisRootPublicKey}
	case "statement":
		encoded, e := text(o, "statement_base64")
		if e != nil {
			return probeFailure(e)
		}
		raw, e := decode(encoded, MaxObject)
		if e != nil {
			return probeFailure(e)
		}
		s, e := ReadStatement(d, raw)
		if e != nil {
			return probeFailure(e)
		}
		type signer struct {
			Role   string `json:"role"`
			Key    string `json:"public_key"`
			Format string `json:"signature_format"`
		}
		signers := []signer{}
		for _, sig := range s.Signatures {
			signers = append(signers, signer{sig.Role, sig.PublicKey, sig.Format})
		}
		return map[string]any{"ok": true, "context_id": d.ContextID, "statement_kind": s.Kind, "statement_id": s.ID, "proof_id": s.ProofID, "payload_base64": b64(s.Payload), "signers": signers}
	case "catalog":
		encoded, e := text(o, "catalog_base64")
		if e != nil {
			return probeFailure(e)
		}
		raw, e := decode(encoded, MaxCatalog)
		if e != nil {
			return probeFailure(e)
		}
		c, e := ReadCatalog(d, raw)
		if e != nil {
			return probeFailure(e)
		}
		return map[string]any{"ok": true, "context_id": d.ContextID, "proof_ids": c.ProofIDs()}
	}
	return probeFailure(invalid())
}

// RunProbe preserves one response per framed line, drains over-limit input,
// and distinguishes internal I/O failures from invalid public vectors.
func RunProbe(input io.Reader, output io.Writer) error {
	in := bufio.NewReaderSize(input, 64<<10)
	var line []byte
	overflow := false
	for {
		chunk, e := in.ReadSlice('\n')
		if len(line)+len(chunk) > MaxProbe {
			overflow = true
			line = nil
		} else if !overflow {
			line = append(line, chunk...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(line) > 0 || overflow {
			var result any
			if overflow {
				result = probeFailure(failure("quota_exceeded"))
			} else {
				result = Probe(line)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				return err
			}
			if len(encoded)+1 > MaxProbe {
				encoded, _ = json.Marshal(probeFailure(failure("quota_exceeded")))
			}
			encoded = append(encoded, '\n')
			if _, err = output.Write(encoded); err != nil {
				return err
			}
		}
		line = nil
		overflow = false
		if e != nil {
			if e == io.EOF {
				return nil
			}
			return e
		}
	}
}
