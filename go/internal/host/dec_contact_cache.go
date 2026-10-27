package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decContactRecord struct {
	Format     uint64   `json:"format"`
	Hashes     []string `json:"message_hashes"`
	Conflicted bool     `json:"conflicted"`
	Contacts   []string `json:"contacts_base64"`
}

// Contacts update only transport hints and semantic equivocation guards. They
// never create an authority row, consent, provider or decision-clock update.
func (s *Store) observeDecContacts(ctx context.Context, tx *sql.Tx, p *decPending, now string) error {
	keys := []string{}
	for key := range p.Frames {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		frame := p.Frames[key]
		plain, e := decOpenPendingFrame(*p, frame)
		if e != nil {
			return e
		}
		for _, body := range plain.Contacts {
			c, e := dec.ReadContact(body)
			if e != nil {
				return e
			}
			if c.Host != frame.Writer {
				continue
			}
			network := "-"
			if c.Context != "-" {
				contexts, e := decPendingDescriptors(*p)
				if e != nil {
					return e
				}
				descriptor, ok := contexts[c.Context]
				if !ok {
					continue
				}
				network = descriptor.NetworkID
			}
			record, e := cacheDecContact(ctx, tx, network, c)
			if e != nil {
				return e
			}
			carriers := []decCarrier{}
			for _, carrier := range p.Record.Carriers {
				if carrier.Kind != "participant" || carrier.Key != c.Host {
					carriers = append(carriers, carrier)
				}
			}
			p.Record.Carriers = carriers
			if !record.Conflicted {
				for _, saved := range record.Contacts {
					raw, e := decBytes(saved, dec.MaxContact)
					if e != nil {
						return e
					}
					current, e := dec.ReadContact(raw)
					if e != nil {
						return e
					}
					if current.Current(now) != nil {
						continue
					}
					for _, address := range current.Addresses.Bootstrap {
						addDecCarriers(p, decCarrier{"participant", address, current.Host})
					}
				}
			}
		}
	}
	return nil
}

func cacheDecContact(ctx context.Context, tx *sql.Tx, network string, c *dec.Contact) (decContactRecord, error) {
	record := decContactRecord{1, []string{}, false, []string{}}
	var version any
	var raw string
	e := tx.QueryRowContext(ctx, `SELECT sequence,record FROM dec_contacts WHERE network_id=? AND context_id=? AND host_key=?`, network, c.Context, c.Host).Scan(&version, &raw)
	sequence := c.Sequence
	if e == nil {
		previous, e := decVersion(version, true)
		if e != nil {
			return record, e
		}
		if dec.ReadPrivateRecord([]byte(raw), "format message_hashes conflicted contacts_base64", &record) != nil || record.Format != 1 || record.Hashes == nil || len(record.Hashes) < 1 || len(record.Hashes) > 2 || record.Contacts == nil || len(record.Contacts) > 2 || record.Conflicted != (len(record.Hashes) == 2) {
			return record, decStorageError()
		}
		for i, h := range record.Hashes {
			b, e := hex.DecodeString(h)
			if e != nil || len(b) != 32 || hex.EncodeToString(b) != h || i > 0 && record.Hashes[i-1] >= h {
				return record, decStorageError()
			}
		}
		for _, encoded := range record.Contacts {
			body, e := decBytes(encoded, dec.MaxContact)
			if e != nil {
				return record, e
			}
			old, e := dec.ReadContact(body)
			if e != nil {
				return record, e
			}
			hash := sha256.Sum256(old.Message)
			if old.Host != c.Host || old.Context != c.Context || old.Sequence != previous || !containsString(record.Hashes, hex.EncodeToString(hash[:])) {
				return record, decStorageError()
			}
		}
		if previous > sequence {
			return record, nil
		}
		if previous < sequence {
			record = decContactRecord{1, []string{}, false, []string{}}
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return record, e
	}
	hash := sha256.Sum256(c.Message)
	messageHash := hex.EncodeToString(hash[:])
	if containsString(record.Hashes, messageHash) {
		return record, nil
	}
	if len(record.Hashes) < 2 {
		record.Hashes = append(record.Hashes, messageHash)
		sort.Strings(record.Hashes)
		record.Contacts = append(record.Contacts, base64.StdEncoding.EncodeToString(c.Raw))
		sort.Slice(record.Contacts, func(i, j int) bool {
			a := sha256.Sum256(mustDecBytes(record.Contacts[i]))
			b := sha256.Sum256(mustDecBytes(record.Contacts[j]))
			return hex.EncodeToString(a[:]) < hex.EncodeToString(b[:])
		})
	}
	record.Conflicted = len(record.Hashes) == 2
	stored, _ := json.Marshal(record)
	_, e = tx.ExecContext(ctx, `INSERT INTO dec_contacts(network_id,context_id,host_key,sequence,record) VALUES(?,?,?,?,?) ON CONFLICT(network_id,context_id,host_key) DO UPDATE SET sequence=excluded.sequence,record=excluded.record`, network, c.Context, c.Host, linkVersionValue(sequence), string(stored))
	return record, e
}
