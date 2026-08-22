// Package transport locates and connects to domain controllers.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// DC is a domain controller candidate discovered from a DNS SRV record.
type DC struct {
	Host     string
	Port     uint16
	Priority uint16
	Weight   uint16
}

// Resolver is the subset of *net.Resolver that DiscoverDCs needs, so tests
// can supply recorded answers instead of touching the network.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// ErrNoDCs reports that DNS answered but listed no domain controllers.
// Callers must be able to tell "this domain has no DCs" from "DNS is
// broken", so this is a sentinel and resolver failures are wrapped.
var ErrNoDCs = errors.New("transport: no domain controllers in SRV answer")

// DiscoverDCs queries _ldap._tcp.dc._msdcs.<domain> and returns DCs in
// deterministic selection order: priority ascending, then weight
// descending, then host ascending. Hostnames have the trailing dot
// stripped.
//
// The order is stable for identical input by design: §4.1 requires LDAP
// and SMB to pin to the same DC, so RFC 2782 weighted-random selection is
// deliberately not used.
//
// It returns ErrNoDCs for an empty answer, and a wrapped resolver error if
// the lookup itself failed.
func DiscoverDCs(ctx context.Context, r Resolver, domain string) ([]DC, error) {
	_, answers, err := r.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return nil, fmt.Errorf("discovering DCs for %s: %w", domain, err)
	}
	dcs := make([]DC, 0, len(answers))
	for _, a := range answers {
		dcs = append(dcs, DC{
			Host:     strings.TrimSuffix(a.Target, "."),
			Port:     a.Port,
			Priority: a.Priority,
			Weight:   a.Weight,
		})
	}
	if len(dcs) == 0 {
		return nil, ErrNoDCs
	}
	slices.SortFunc(dcs, func(a, b DC) int {
		if a.Priority != b.Priority {
			return int(a.Priority) - int(b.Priority)
		}
		if a.Weight != b.Weight {
			return int(b.Weight) - int(a.Weight)
		}
		return strings.Compare(a.Host, b.Host)
	})
	return dcs, nil
}
