package host

import (
	"sort"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// The display keys are groups within ONE frozen edit, not full rule keys.
// Derive both spellings from actual fields; never rewrite arbitrary labels.
func decPolicyDropKeys(before, after membership.PolicyBody) map[string]string {
	keys := map[string]string{}
	add := func(canonical, alternate string) {
		keys[canonical] = canonical
		if alternate != "" {
			keys[alternate] = canonical
		}
	}
	for _, r := range after.Rules {
		var old *membership.PolicyRule
		for i := range before.Rules {
			if membership.RuleKey(before.Rules[i]) == membership.RuleKey(r) {
				old = &before.Rules[i]
				break
			}
		}
		if old == nil {
			add("rule "+r.Agent, "")
		}
		for _, principal := range r.Principals {
			if old == nil || !containsString(old.Principals, principal) {
				add("principal "+principal+" in rule "+r.Agent, "principal "+principal+" of rule "+r.Agent)
			}
		}
	}
	for _, r := range after.CapabilityRules {
		var old *membership.CapabilityRule
		for i := range before.CapabilityRules {
			if before.CapabilityRules[i].Capability == r.Capability && before.CapabilityRules[i].Host == r.Host {
				old = &before.CapabilityRules[i]
				break
			}
		}
		if old == nil {
			if len(r.Principals) == 0 {
				add("claim "+r.Capability, "")
			} else {
				add("capability rule "+r.Capability, "")
			}
		}
		for _, principal := range r.Principals {
			if old == nil || !containsString(old.Principals, principal) {
				add("principal "+principal+" in capability rule "+r.Capability, "principal "+principal+" of capability rule "+r.Capability)
			}
		}
	}
	return keys
}

func decPolicyDropSet(before, after membership.PolicyBody, dropped []string) (map[string]bool, error) {
	keys := decPolicyDropKeys(before, after)
	set := map[string]bool{}
	for i, key := range dropped {
		canonical, ok := keys[key]
		if !ok || key == "" || i > 0 && dropped[i-1] >= key || set[canonical] {
			return nil, decStorageError()
		}
		set[canonical] = true
	}
	return set, nil
}

func decCopyPolicyBody(body membership.PolicyBody) membership.PolicyBody {
	return (membership.Policy{Rules: body.Rules, CapabilityRules: body.CapabilityRules, TrustedHosts: body.TrustedHosts, Edits: body.Edits}).Body()
}

// Suppress only frozen LOCAL additions. Removing them from the in-memory O
// leaves independently present S permissions and every B->O withdrawal intact.
func decMergePolicyEdit(before, signed, current membership.PolicyBody, skip map[string]bool) (membership.PolicyBody, []string) {
	filtered := decCopyPolicyBody(signed)
	rules := filtered.Rules[:0]
	for _, r := range filtered.Rules {
		var old *membership.PolicyRule
		for i := range before.Rules {
			if membership.RuleKey(before.Rules[i]) == membership.RuleKey(r) {
				old = &before.Rules[i]
				break
			}
		}
		if old == nil && skip["rule "+r.Agent] {
			continue
		}
		principals := r.Principals[:0]
		for _, principal := range r.Principals {
			if (old == nil || !containsString(old.Principals, principal)) && skip["principal "+principal+" in rule "+r.Agent] {
				continue
			}
			principals = append(principals, principal)
		}
		r.Principals = principals
		rules = append(rules, r)
	}
	filtered.Rules = rules
	capabilities := filtered.CapabilityRules[:0]
	for _, r := range filtered.CapabilityRules {
		var old *membership.CapabilityRule
		for i := range before.CapabilityRules {
			if before.CapabilityRules[i].Capability == r.Capability && before.CapabilityRules[i].Host == r.Host {
				old = &before.CapabilityRules[i]
				break
			}
		}
		marker := "capability rule " + r.Capability
		if len(r.Principals) == 0 {
			marker = "claim " + r.Capability
		}
		if old == nil && skip[marker] {
			continue
		}
		principals := r.Principals[:0]
		for _, principal := range r.Principals {
			if (old == nil || !containsString(old.Principals, principal)) && skip["principal "+principal+" in capability rule "+r.Capability] {
				continue
			}
			principals = append(principals, principal)
		}
		r.Principals = principals
		capabilities = append(capabilities, r)
	}
	filtered.CapabilityRules = capabilities
	result, generated := membership.MergeEdit(before, filtered, current, false, nil)
	// Suppressing every local principal can leave a capability claim in O.
	// Its conflict still names the ORIGINAL frozen nonempty-rule addition.
	for i, marker := range generated {
		for _, original := range signed.CapabilityRules {
			if len(original.Principals) > 0 && marker == "claim "+original.Capability {
				generated[i] = "capability rule " + original.Capability
			}
		}
	}
	return result, generated
}

type decFrozenPolicyEdit struct {
	seq           int64
	start, signed membership.PolicyBody
	skip          map[string]bool
	keys          map[string]string
}

// All rows restart from the same untouched baseline whenever any row discovers
// a new marker. No provisional content escapes before the finite fixed point.
func decMergeFrozenEdits(body membership.PolicyBody, frozen []decFrozenPolicyEdit) (membership.PolicyBody, map[int64][]string, error) {
	work := 0
	for {
		result := membership.CombineDuplicateRules(decCopyPolicyBody(body))
		changed := false
		for _, edit := range frozen {
			work++
			if work > 65536 {
				return body, nil, decFailure("quota_exceeded")
			}
			var generated []string
			result, generated = decMergePolicyEdit(edit.start, edit.signed, result, edit.skip)
			for _, marker := range generated {
				canonical, ok := edit.keys[marker]
				if !ok {
					return result, nil, decStorageError()
				}
				if !edit.skip[canonical] {
					edit.skip[canonical] = true
					changed = true
				}
			}
		}
		if !changed {
			dropped := map[int64][]string{}
			for _, edit := range frozen {
				for marker := range edit.skip {
					dropped[edit.seq] = append(dropped[edit.seq], marker)
				}
				sort.Strings(dropped[edit.seq])
			}
			return result, dropped, nil
		}
	}
}

// Preserve retained spellings byte-for-byte; append only genuinely new groups.
func decAppendPolicyDrops(retained, generated []string, start, signed membership.PolicyBody) ([]string, error) {
	seen, e := decPolicyDropSet(start, signed, retained)
	if e != nil {
		return nil, e
	}
	result := append([]string{}, retained...)
	keys := decPolicyDropKeys(start, signed)
	for _, marker := range generated {
		canonical, ok := keys[marker]
		if !ok {
			return nil, decStorageError()
		}
		if !seen[canonical] {
			result = append(result, canonical)
			seen[canonical] = true
		}
	}
	sort.Strings(result)
	return result, nil
}
