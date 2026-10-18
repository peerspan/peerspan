package membership

import (
	"slices"
)

// Re-applying policy edits (coordination contract, Concurrent edits). An
// edit E has a starting point B and a signed policy O; re-applying it to a
// stored policy S carries O's changes relative to B into S. Content is the
// rules, capability rules, and trusted hosts; the header, validity window,
// and edits are not compared.

// SameContent reports whether two bodies have the same rules, capability
// rules, and trusted hosts, in order.
func SameContent(a, b PolicyBody) bool {
	if len(a.Rules) != len(b.Rules) || len(a.CapabilityRules) != len(b.CapabilityRules) || !sameSet(a.TrustedHosts, b.TrustedHosts) {
		return false
	}
	for i := range a.Rules {
		x, y := a.Rules[i], b.Rules[i]
		if x.Agent != y.Agent || !slices.Equal(x.Principals, y.Principals) || !slices.Equal(x.Actions, y.Actions) || x.MaxMessageBytes != y.MaxMessageBytes || x.MaxArtifactBytes != y.MaxArtifactBytes || x.AllowDisconnected != y.AllowDisconnected {
			return false
		}
	}
	for i := range a.CapabilityRules {
		x, y := a.CapabilityRules[i], b.CapabilityRules[i]
		if x.Host != y.Host || x.Capability != y.Capability || !slices.Equal(x.Principals, y.Principals) || x.MaxInputBytes != y.MaxInputBytes || x.AllowDisconnected != y.AllowDisconnected || x.MaxCallsPerHour != y.MaxCallsPerHour {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// ruleKeys keys rules by agent and settings: a v2 policy holds at most one
// rule per key, so the key identifies a rule across B, O, and S. Changing
// a rule's settings changes its key.
func ruleKeys(rules []PolicyRule) []string {
	keys := make([]string, len(rules))
	for i, r := range rules {
		keys[i] = RuleKey(r)
	}
	return keys
}

func indexOf(keys []string, key string) int {
	return slices.Index(keys, key)
}

func capabilityIndex(rules []CapabilityRule, name string) int {
	for i, r := range rules {
		if r.Capability == name {
			return i
		}
	}
	return -1
}

// mergeMembers applies O's member changes relative to B to S's members.
// removalsOnly skips additions. It returns the members and the additions
// made, in O's order.
func mergeMembers(b, o, s []string, removalsOnly bool, skip func(string) bool) []string {
	out := []string{}
	for _, m := range s {
		if slices.Contains(b, m) && !slices.Contains(o, m) {
			continue // O removed it
		}
		out = append(out, m)
	}
	if removalsOnly {
		return out
	}
	for _, m := range o {
		if !slices.Contains(b, m) && !slices.Contains(out, m) && !skip(m) {
			out = append(out, m)
		}
	}
	return out
}

// mergeInt merges one numeric bound: O's value when S still has B's,
// otherwise the more restrictive, lower value. removalsOnly applies only a
// lowered bound.
func mergeInt(b, o, s int64, removalsOnly bool) int64 {
	if o == b {
		return s
	}
	if removalsOnly {
		if o < b {
			return min(s, o)
		}
		return s
	}
	if s == b {
		return o
	}
	return min(s, o)
}

func mergeBool(b, o, s bool, removalsOnly bool) bool {
	if o == b {
		return s
	}
	if removalsOnly {
		return s && o
	}
	if s == b {
		return o
	}
	return s && o
}

// MergeEdit re-applies an edit, its starting point b and signed policy o, to
// the stored body s, and returns the result and the additions it dropped
// because s removed their rule or bound their capability name to another
// host. dropped additions already recorded are skipped. With removalsOnly,
// only O's withdrawals apply: removed members, rules, and trusted hosts, and
// lowered bounds. The result keeps s's edits.
func MergeEdit(b, o, s PolicyBody, removalsOnly bool, skip []string) (PolicyBody, []string) {
	out := Policy{Rules: s.Rules, CapabilityRules: s.CapabilityRules, TrustedHosts: s.TrustedHosts, Edits: s.Edits}.Body()
	var dropped []string
	skipped := func(item string) bool { return slices.Contains(skip, item) }
	drop := func(item string) {
		if !slices.Contains(dropped, item) && !skipped(item) {
			dropped = append(dropped, item)
		}
	}

	// Rules, keyed by agent and settings; their members are principals,
	// and their bounds, part of the key, are never merged.
	bKeys, oKeys := ruleKeys(b.Rules), ruleKeys(o.Rules)
	sKeys := ruleKeys(out.Rules)
	removed := map[string]bool{}
	for i, key := range bKeys {
		j := indexOf(oKeys, key)
		k := indexOf(sKeys, key)
		if j < 0 {
			removed[key] = true // O removed the rule, or changed its settings
			continue
		}
		br, or := b.Rules[i], o.Rules[j]
		if k < 0 {
			// S removed the rule: O's additions to it are dropped.
			if !removalsOnly {
				for _, m := range or.Principals {
					if !slices.Contains(br.Principals, m) {
						drop("principal " + m + " in rule " + or.Agent)
					}
				}
			}
			continue
		}
		sr := &out.Rules[k]
		sr.Principals = mergeMembers(br.Principals, or.Principals, sr.Principals, removalsOnly, func(m string) bool { return skipped("principal " + m + " in rule " + or.Agent) })
	}
	if !removalsOnly {
		for j, key := range oKeys {
			if indexOf(bKeys, key) >= 0 {
				continue
			}
			or := o.Rules[j]
			if k := indexOf(sKeys, key); k >= 0 {
				// S added the same rule concurrently: the two combine.
				sr := &out.Rules[k]
				sr.Principals = mergeMembers(nil, or.Principals, sr.Principals, false, func(m string) bool { return skipped("principal " + m + " in rule " + or.Agent) })
				continue
			}
			if skipped("rule " + or.Agent) {
				continue
			}
			or.Principals = append([]string{}, or.Principals...)
			or.Actions = append([]string{}, or.Actions...)
			out.Rules = append(out.Rules, or)
			sKeys = append(sKeys, key)
		}
	}
	kept := []PolicyRule{}
	for k, r := range out.Rules {
		// A rule left without principals is removed.
		if removed[sKeys[k]] || len(r.Principals) == 0 {
			continue
		}
		kept = append(kept, r)
	}
	out.Rules = kept

	// Capability rules, keyed by capability name; a rule binds its name to
	// its host.
	capRemoved := map[string]string{}
	for _, br := range b.CapabilityRules {
		j := capabilityIndex(o.CapabilityRules, br.Capability)
		k := capabilityIndex(out.CapabilityRules, br.Capability)
		if j < 0 || o.CapabilityRules[j].Host != br.Host {
			// O removed the rule; S loses it only where it still names
			// that host.
			if k >= 0 && out.CapabilityRules[k].Host == br.Host {
				capRemoved[br.Capability] = br.Host
			}
			continue
		}
		or := o.CapabilityRules[j]
		if k < 0 || out.CapabilityRules[k].Host != br.Host {
			if !removalsOnly {
				for _, m := range or.Principals {
					if !slices.Contains(br.Principals, m) {
						drop("principal " + m + " in capability rule " + or.Capability)
					}
				}
			}
			continue
		}
		sr := &out.CapabilityRules[k]
		sr.Principals = mergeMembers(br.Principals, or.Principals, sr.Principals, removalsOnly, func(m string) bool {
			return skipped("principal " + m + " in capability rule " + or.Capability)
		})
		sr.MaxInputBytes = mergeInt(br.MaxInputBytes, or.MaxInputBytes, sr.MaxInputBytes, removalsOnly)
		sr.MaxCallsPerHour = mergeInt(br.MaxCallsPerHour, or.MaxCallsPerHour, sr.MaxCallsPerHour, removalsOnly)
		sr.AllowDisconnected = mergeBool(br.AllowDisconnected, or.AllowDisconnected, sr.AllowDisconnected, removalsOnly)
	}
	if !removalsOnly {
		for _, or := range o.CapabilityRules {
			if j := capabilityIndex(b.CapabilityRules, or.Capability); j >= 0 && b.CapabilityRules[j].Host == or.Host {
				continue
			}
			item := "capability rule " + or.Capability
			if len(or.Principals) == 0 {
				item = "claim " + or.Capability
			}
			k := capabilityIndex(out.CapabilityRules, or.Capability)
			switch {
			case k >= 0 && out.CapabilityRules[k].Host != or.Host:
				// S binds the name to another host: the rule, or claim, is
				// dropped.
				drop(item)
			case k >= 0:
				sr := &out.CapabilityRules[k]
				sr.Principals = mergeMembers(nil, or.Principals, sr.Principals, false, func(m string) bool {
					return skipped("principal " + m + " in capability rule " + or.Capability)
				})
				sr.MaxInputBytes = min(sr.MaxInputBytes, or.MaxInputBytes)
				sr.MaxCallsPerHour = min(sr.MaxCallsPerHour, or.MaxCallsPerHour)
				sr.AllowDisconnected = sr.AllowDisconnected && or.AllowDisconnected
			case !skipped(item):
				or.Principals = append([]string{}, or.Principals...)
				out.CapabilityRules = append(out.CapabilityRules, or)
			}
		}
	}
	capKept := []CapabilityRule{}
	for _, r := range out.CapabilityRules {
		// A capability rule left without principals stays as a claim.
		if host, ok := capRemoved[r.Capability]; !ok || host != r.Host {
			capKept = append(capKept, r)
		}
	}
	out.CapabilityRules = capKept

	// Trusted hosts are set members of the policy.
	out.TrustedHosts = mergeMembers(b.TrustedHosts, o.TrustedHosts, out.TrustedHosts, removalsOnly, func(string) bool { return false })
	return out, dropped
}
