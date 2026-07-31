// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// localDNSSECProofCacheSize is the number of revisions retained independently
// for each zone and source namespace.
const localDNSSECProofCacheSize = 64

const localDNSSECProofCacheZoneLimit = 64

type localDNSSECProofCacheKey struct {
	instance  uint64
	revision  uint64
	zone      string
	handshake bool
}

type localDNSSECProofCacheZoneKey struct {
	zone      string
	handshake bool
}

type localDNSSECProofCacheEntry struct {
	key     localDNSSECProofCacheKey
	records []dns.RR
}

type localDNSSECProofCacheZone struct {
	entries map[localDNSSECProofCacheKey]*list.Element
	lru     *list.List
	global  *list.Element
}

type localDNSSECProofCache struct {
	mu      sync.Mutex
	zones   map[localDNSSECProofCacheZoneKey]*localDNSSECProofCacheZone
	zoneLRU *list.List
	flight  singleflight.Group
}

var localProofCache = localDNSSECProofCache{
	zones:   make(map[localDNSSECProofCacheZoneKey]*localDNSSECProofCacheZone),
	zoneLRU: list.New(),
}

func (k localDNSSECProofCacheKey) zoneKey() localDNSSECProofCacheZoneKey {
	return localDNSSECProofCacheZoneKey{
		zone:      k.zone,
		handshake: k.handshake,
	}
}

func (k localDNSSECProofCacheKey) flightKey() string {
	return fmt.Sprintf(
		"%d\x00%d\x00%s\x00%t",
		k.instance,
		k.revision,
		k.zone,
		k.handshake,
	)
}

func (c *localDNSSECProofCache) cached(
	key localDNSSECProofCacheKey,
) ([]dns.RR, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	zone := c.zones[key.zoneKey()]
	if zone == nil {
		return nil, false
	}
	if zone.global != nil {
		c.zoneLRU.MoveToFront(zone.global)
	}
	element := zone.entries[key]
	if element == nil {
		return nil, false
	}
	zone.lru.MoveToFront(element)
	return element.Value.(localDNSSECProofCacheEntry).records, true
}

func (c *localDNSSECProofCache) store(
	key localDNSSECProofCacheKey,
	records []dns.RR,
) []dns.RR {
	c.mu.Lock()
	defer c.mu.Unlock()
	zoneKey := key.zoneKey()
	zone := c.zones[zoneKey]
	if zone == nil {
		if c.zoneLRU.Len() >= localDNSSECProofCacheZoneLimit {
			oldest := c.zoneLRU.Back()
			if oldest != nil {
				delete(c.zones, oldest.Value.(localDNSSECProofCacheZoneKey))
				c.zoneLRU.Remove(oldest)
			}
		}
		zone = &localDNSSECProofCacheZone{
			entries: make(map[localDNSSECProofCacheKey]*list.Element),
			lru:     list.New(),
		}
		zone.global = c.zoneLRU.PushFront(zoneKey)
		c.zones[zoneKey] = zone
	} else if zone.global != nil {
		c.zoneLRU.MoveToFront(zone.global)
	}
	if existing := zone.entries[key]; existing != nil {
		zone.lru.MoveToFront(existing)
		return existing.Value.(localDNSSECProofCacheEntry).records
	}
	element := zone.lru.PushFront(localDNSSECProofCacheEntry{
		key:     key,
		records: records,
	})
	zone.entries[key] = element
	if zone.lru.Len() > localDNSSECProofCacheSize {
		oldest := zone.lru.Back()
		if oldest != nil {
			delete(zone.entries, oldest.Value.(localDNSSECProofCacheEntry).key)
			zone.lru.Remove(oldest)
		}
	}
	return records
}

func lookupCachedLocalZoneDNSSECRecords(
	zone string,
	fromHandshake bool,
) ([]dns.RR, error) {
	instance, revision, err := state.GetState().DNSSECRevision(fromHandshake)
	if err != nil {
		return nil, err
	}
	key := localDNSSECProofCacheKey{
		instance:  instance,
		revision:  revision,
		zone:      canonicalDNSName(zone),
		handshake: fromHandshake,
	}
	if records, ok := localProofCache.cached(key); ok {
		return records, nil
	}
	result, err, _ := localProofCache.flight.Do(
		key.flightKey(),
		func() (any, error) {
			if records, ok := localProofCache.cached(key); ok {
				return records, nil
			}
			records, err := lookupLocalZoneDNSSECRecordsUncached(
				zone,
				fromHandshake,
			)
			if err != nil {
				return nil, err
			}
			return localProofCache.store(key, records), nil
		},
	)
	if err != nil {
		return nil, err
	}
	return result.([]dns.RR), nil
}
