package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/peerspan/peerspan/go/internal/host"
)

// Resource bounds on the owner's CLI: --bound, the guided share's prompt,
// and the review's bounds block and reach statement.

// parseBound reads one --bound value, KEY=VALUE[,KEY=VALUE...], as a
// combination.
func parseBound(value string) (host.BoundCombination, error) {
	combo := host.BoundCombination{}
	for _, part := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--bound %q: each part is KEY=VALUE", value)
		}
		if _, dup := combo[key]; dup {
			return nil, fmt.Errorf("--bound %q names %s twice", value, key)
		}
		combo[key] = val
	}
	return combo, nil
}

func parseBounds(values []string) (host.CapabilityBounds, error) {
	var b host.CapabilityBounds
	for _, v := range values {
		combo, err := parseBound(v)
		if err != nil {
			return b, err
		}
		b.Arguments = append(b.Arguments, combo)
	}
	return b, nil
}

// boundsBlock is the review's bounds block for a bounded capability.
func boundsBlock(c capabilityRecord, server sourceServer) []string {
	if !c.Bounds.Set() {
		return nil
	}
	lines := []string{"Bounds: " + host.BoundsAllowedText(c.Bounds)}
	bound := map[string]bool{}
	allRepo := true
	for _, combo := range c.Bounds.Arguments {
		if _, ok := combo["repo"]; !ok {
			allRepo = false
		}
		for k := range combo {
			bound[k] = true
		}
	}
	if c.Source.Agent == "builtin" && allRepo {
		lines = append(lines, "  Every gh operation names its repository in repo, so Peerspan checks every call.")
	} else {
		var parts []string
		for _, op := range c.Operations {
			var names []string
			for _, t := range server.Tools {
				if t.Name != op {
					continue
				}
				var schema struct {
					Properties map[string]json.RawMessage `json:"properties"`
				}
				_ = json.Unmarshal(t.InputSchema, &schema)
				for name := range schema.Properties {
					if !bound[name] {
						names = append(names, name)
					}
				}
			}
			sort.Strings(names)
			if len(names) > 0 {
				parts = append(parts, op+": "+strings.Join(names, ", "))
			}
		}
		if len(parts) == 0 {
			lines = append(lines, "  Peerspan checks every argument of these operations.")
		} else {
			lines = append(lines, "  Not checked by Peerspan: "+strings.Join(parts, "; ")+".")
		}
	}
	if len(c.Resources) > 0 && string(c.Resources) != "null" {
		lines = append(lines, "  The bound does not apply to read, which is limited to the capability's resources.")
	}
	return lines
}

// reachStatement is the review's reach line, and shares' reach.
func reachStatement(principal string, c capabilityRecord, reach *host.GHReach, account *string) string {
	gh := c.Source.Agent == "builtin"
	switch {
	case c.Bounds.Set() && gh:
		return principal + " can use these operations only where " + host.BoundsAllowedText(c.Bounds) + "; Peerspan refuses other calls. The credential reaches more than the bound. " + reachSentence(reach, account)
	case c.Bounds.Set():
		return principal + " can use these operations only where " + host.BoundsAllowedText(c.Bounds) + "; Peerspan refuses other calls. Arguments Peerspan does not check can still reach anything the credentials they run with on this host can reach."
	case gh:
		return principal + " can use these operations with the credentials they run with on this host. " + reachSentence(reach, account) + " No resource bound."
	}
	return principal + " can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, " + principal + " can too. No resource bound."
}

// builtinSource finds a built-in source in the listing.
func builtinSource(listing sourcesListing, name string) *builtinSourcesView {
	for i := range listing.Builtin {
		if listing.Builtin[i].Name == name {
			return &listing.Builtin[i]
		}
	}
	return nil
}

// askBounds is the guided share's bound prompt at a terminal.
func askBounds(errOut interface{ Write([]byte) (int, error) }, gh bool) (host.CapabilityBounds, error) {
	var b host.CapabilityBounds
	if gh {
		fmt.Fprint(errOut, "Limit which repositories? Enter OWNER/REPO, several separated by spaces, or leave empty for no limit: ")
		for _, word := range strings.Fields(readLine()) {
			b.Arguments = append(b.Arguments, host.BoundCombination{"repo": word})
		}
		return b, nil
	}
	fmt.Fprint(errOut, "Limit by argument values? Enter KEY=VALUE[,KEY=VALUE] combinations separated by spaces, or leave empty for no limit: ")
	words := strings.Fields(readLine())
	if len(words) == 0 {
		return b, nil
	}
	b, err := parseBounds(words)
	if err != nil {
		return b, errors.New(strings.Replace(err.Error(), "--bound", "bound", 1))
	}
	return b, nil
}
