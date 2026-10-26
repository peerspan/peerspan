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
	names := map[string]string{"descriptor": "format kind descriptor_base64", "statement": "format kind descriptor_base64 statement_base64", "catalog": "format kind descriptor_base64 catalog_base64",
		"projection": "format kind descriptor_base64 prior candidate_catalog_base64 now operation",
		"action":     "format kind descriptor_base64 prior candidate_catalog_base64 now actor action_kind unsigned_payload_base64",
		"activation": "format kind descriptor_base64 prior catalog_base64 activation_base64 now expected",
		"migration":  "format kind descriptor_base64 legacy_prior prior migration_base64 now purpose local_host_public_key"}
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
	case "migration":
		now, e := text(o, "now")
		if e != nil {
			return probeFailure(e)
		}
		purpose, e := text(o, "purpose")
		if e != nil {
			return probeFailure(e)
		}
		host, e := text(o, "local_host_public_key")
		if e != nil {
			return probeFailure(e)
		}
		raw, e := probeBytes(o, "migration_base64", MaxObject)
		if e != nil {
			return probeFailure(e)
		}
		result, e := VerifyMigration(d, o["legacy_prior"], o["prior"], raw, now, purpose, host)
		if e != nil {
			return probeFailure(e)
		}
		return result
	case "projection":
		now, e := text(o, "now")
		if e != nil {
			return probeFailure(e)
		}
		operation, e := text(o, "operation")
		if e != nil {
			return probeFailure(e)
		}
		encoded, e := text(o, "candidate_catalog_base64")
		if e != nil {
			return probeFailure(e)
		}
		candidate := []byte("-")
		if encoded != "-" {
			candidate, e = decode(encoded, MaxCatalog)
			if e != nil {
				return probeFailure(e)
			}
		} else if operation != "read" {
			return probeFailure(invalid())
		}
		result, e := Project(d, o["prior"], candidate, now, operation)
		if e != nil {
			return probeFailure(e)
		}
		return result
	case "action":
		now, e := text(o, "now")
		if e != nil {
			return probeFailure(e)
		}
		actionKind, e := text(o, "action_kind")
		if e != nil {
			return probeFailure(e)
		}
		candidate, e := probeBytes(o, "candidate_catalog_base64", MaxCatalog)
		if e != nil {
			return probeFailure(e)
		}
		unsigned, e := probeBytes(o, "unsigned_payload_base64", MaxPayload)
		if e != nil {
			return probeFailure(e)
		}
		result, e := VerifyActionIntent(d, o["prior"], candidate, o["actor"], unsigned, now, actionKind)
		if e != nil {
			return probeFailure(e)
		}
		return result
	case "activation":
		now, e := text(o, "now")
		if e != nil {
			return probeFailure(e)
		}
		catalog, e := probeBytes(o, "catalog_base64", MaxCatalog)
		if e != nil {
			return probeFailure(e)
		}
		activation, e := probeBytes(o, "activation_base64", MaxObject)
		if e != nil {
			return probeFailure(e)
		}
		result, e := VerifyActivation(d, o["prior"], catalog, activation, o["expected"], now)
		if e != nil {
			return probeFailure(e)
		}
		return result
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
			if n, err := output.Write(encoded); err != nil {
				return err
			} else if n != len(encoded) {
				return io.ErrShortWrite
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

func probeBytes(o Object, name string, max int) ([]byte, error) {
	s, e := text(o, name)
	if e != nil {
		return nil, e
	}
	return decode(s, max)
}
