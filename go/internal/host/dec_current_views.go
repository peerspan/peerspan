package host

import (
	"encoding/base64"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type DecPersonView struct {
	Person   string `json:"person_public_key"`
	Member   string `json:"member"`
	Lease    string `json:"person_lease_id"`
	NotAfter string `json:"not_after"`
}

type DecPolicyStatementView struct {
	Statement string `json:"statement_id"`
	Body      string `json:"statement_base64"`
}

func decCurrentPersons(p *dec.Projection) ([]DecPersonView, error) {
	people := []DecPersonView{}
	for _, stream := range p.Streams {
		if len(stream.Stream) != 2 || stream.Stream[0] != "person" {
			continue
		}
		statement, path, e := p.Current(stream.Stream)
		if e != nil {
			if dec.Code(e) == "proof_required" || dec.Code(e) == "state_conflict" {
				return nil, e
			}
			continue
		}
		people = append(people, DecPersonView{statement.Lease.Subject.Person, statement.Lease.Subject.Member, statement.ID, path.NotAfter})
	}
	if len(people) > 4096 {
		return nil, decFailure("quota_exceeded")
	}
	sort.Slice(people, func(a, b int) bool { return people[a].Person < people[b].Person })
	return people, nil
}

func decCurrentPolicyStatement(p *dec.Projection, person string) (DecPolicyStatementView, error) {
	if !dec.ValidPublicKey(person) {
		return DecPolicyStatementView{}, decFailure("invalid")
	}
	known := false
	for _, stream := range p.Streams {
		if len(stream.Stream) == 2 && stream.Stream[0] == "policy" && stream.Stream[1] == person && len(stream.HeadIDs) != 0 {
			known = true
			break
		}
	}
	if !known {
		return DecPolicyStatementView{}, ErrNotFound
	}
	statement, _, e := p.Current([]string{"policy", person})
	if e != nil {
		switch dec.Code(e) {
		case "expired", "forbidden", "authority_expired", "device_revoked", "not_yet_valid", "not_found":
			return DecPolicyStatementView{}, ErrNotFound
		default:
			return DecPolicyStatementView{}, e
		}
	}
	return DecPolicyStatementView{statement.ID, base64.StdEncoding.EncodeToString(statement.Raw)}, nil
}
