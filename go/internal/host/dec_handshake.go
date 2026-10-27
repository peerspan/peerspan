package host

import (
	"sync"
)

// Unknown direct handshakes and provisional relay routes share this ONE host
// budget. A claimed peer digest is never one of its source identities.
type decHandshakeBudget struct {
	mu      sync.Mutex
	total   int
	sources map[string]int
}

func (s *Store) decHandshakeBudget() *decHandshakeBudget {
	s.decTransport.mu.Lock()
	defer s.decTransport.mu.Unlock()
	if s.decTransport.Handshakes == nil {
		s.decTransport.Handshakes = &decHandshakeBudget{sources: map[string]int{}}
	}
	return s.decTransport.Handshakes
}

func (b *decHandshakeBudget) reserve(sources ...string) (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := make([]string, 0, len(sources))
	for _, source := range sources {
		if source == "" {
			return nil, false
		}
		duplicate := false
		for _, old := range keys {
			duplicate = duplicate || old == source
		}
		if !duplicate {
			if b.sources[source] >= 16 {
				return nil, false
			}
			keys = append(keys, source)
		}
	}
	if b.total >= 128 || len(keys) == 0 {
		return nil, false
	}
	b.total++
	for _, key := range keys {
		b.sources[key]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.total--
			for _, key := range keys {
				b.sources[key]--
				if b.sources[key] == 0 {
					delete(b.sources, key)
				}
			}
		})
	}, true
}
