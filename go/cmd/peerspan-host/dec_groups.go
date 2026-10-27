package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Group display needs only the pure current read, never a selected signer or
// a legacy policy/group projection. The original signed envelope stays exact.
func runDecGroups(ctx context.Context, client host.Client, network string, out io.Writer) (bool, error) {
	n, e := decLinkNetwork(ctx, client, network)
	if errors.Is(e, errNotJoined) {
		return false, nil
	}
	if e != nil {
		return true, e
	}
	d, e := decLinkDescriptor(n)
	if e != nil {
		return true, e
	}
	raw, e := client.Call(ctx, "GET", decNetworkPath(n.ID)+"/groups", nil)
	if e != nil {
		return true, e
	}
	var response host.DecGroupsView
	if len(raw) > 32<<20 || dec.ReadPrivateRecord(raw, "context_id groups", &response) != nil || response.Context != d.ContextID || response.Groups == nil || len(response.Groups) > 4096 {
		return true, errors.New("invalid complete current group view")
	}
	type group struct {
		Name      string   `json:"name"`
		Members   []string `json:"members"`
		Version   uint64   `json:"version"`
		Statement string   `json:"statement_id"`
	}
	groups := []group{}
	previous := ""
	for _, row := range response.Groups {
		if !membership.ValidGroupName(row.Name) || row.Name <= previous || len(row.Body) > base64.StdEncoding.EncodedLen(dec.MaxObject) {
			return true, errors.New("invalid ordered current group")
		}
		body, e := base64.StdEncoding.Strict().DecodeString(row.Body)
		if e != nil || len(body) > dec.MaxObject || base64.StdEncoding.EncodeToString(body) != row.Body {
			return true, errors.New("invalid exact current group envelope")
		}
		statement, e := dec.ReadStatement(d, body)
		if e != nil {
			return true, e
		}
		var name string
		var members []string
		if statement.ID != row.Statement || statement.Kind != "group" || statement.Access == nil || json.Unmarshal(statement.Body["name"], &name) != nil || name != row.Name || json.Unmarshal(statement.Body["members"], &members) != nil || members == nil {
			return true, errors.New("group display changes the exact signed name, members or statement")
		}
		groups = append(groups, group{row.Name, members, statement.Access.Sequence, statement.ID})
		previous = row.Name
	}
	return true, printJSON(out, groups)
}
