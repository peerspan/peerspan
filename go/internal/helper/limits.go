package helper

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

func sourceBucket(address net.Addr) (string, error) {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String(), nil
	}
	return netip.PrefixFrom(ip, 64).Masked().String(), nil
}

type bucket struct {
	updated, seen time.Time
	tokens        float64
}

type byteWindow struct {
	second int64
	bytes  int64
}

type rateState struct {
	bucket
	window [61]byteWindow
}

type limits struct {
	mu       sync.Mutex
	rates    map[string]*rateState
	swept    time.Time
	origin   time.Time
	receive  int64
	response int64
	relay    int64
	requests int
	hosts    map[string]int
	sources  map[string]int
}

func newLimits() *limits {
	return &limits{rates: map[string]*rateState{}, origin: time.Now(), hosts: map[string]int{}, sources: map[string]int{}}
}

func (l *limits) beginRequest(peer transportPeer) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.requests >= 128 || l.hosts[peer.key] >= 4 || l.sources[peer.source] >= 16 {
		return false
	}
	l.requests++
	l.hosts[peer.key]++
	l.sources[peer.source]++
	return true
}

func (l *limits) endRequest(peer transportPeer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests--
	l.hosts[peer.key]--
	if l.hosts[peer.key] == 0 {
		delete(l.hosts, peer.key)
	}
	l.sources[peer.source]--
	if l.sources[peer.source] == 0 {
		delete(l.sources, peer.source)
	}
}

func resourceKeys(key, source, account string) []string {
	keys := []string{"key:" + key, "source:" + source}
	if account != "" {
		keys = append(keys, "account:"+account)
	}
	return keys
}

// Counters belong to actual transport principals, never to a socket lifetime.
// Monotonic time controls refill and the rolling transport byte window.
func (l *limits) allow(kind string, keys []string, rate, burst float64, bytes int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.swept) > 2*time.Second {
		for key, state := range l.rates {
			if now.Sub(state.seen) > 65*time.Second {
				delete(l.rates, key)
			}
		}
		l.swept = now
	}
	allowed := true
	second := int64(now.Sub(l.origin) / time.Second)
	for _, principal := range keys {
		name := kind + ":" + principal
		state, exists := l.rates[name]
		if !exists {
			if len(l.rates) >= 16384 {
				allowed = false
				continue
			}
			state = &rateState{bucket: bucket{updated: now, seen: now, tokens: burst}}
			l.rates[name] = state
		}
		state.tokens = min(burst, state.tokens+now.Sub(state.updated).Seconds()*rate)
		state.updated, state.seen = now, now
		if state.tokens < 1 {
			allowed = false
		} else {
			state.tokens--
		}
		if bytes > 0 {
			var sum int64
			for i := range state.window {
				if state.window[i].second >= second-60 {
					sum += state.window[i].bytes
				}
			}
			if sum+bytes > 32<<20 {
				allowed = false
			} else {
				index := second % 61
				if state.window[index].second != second {
					state.window[index] = byteWindow{second: second}
				}
				state.window[index].bytes += bytes
			}
		}
	}
	return allowed
}

func (l *limits) reserve(kind string, amount int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	used := l.counter(kind)
	if amount < 0 || *used+amount > 64<<20 {
		return false
	}
	*used += amount
	return true
}

func (l *limits) release(kind string, amount int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*l.counter(kind) -= amount
}

func (l *limits) counter(kind string) *int64 {
	switch kind {
	case "receive":
		return &l.receive
	case "response":
		return &l.response
	default:
		return &l.relay
	}
}
