// Package dnsresolver resolves hostnames into IPv4 addresses.
package dnsresolver

import (
	"context"
	"fmt"
	"net"
)

// Resolver resolves hostnames using the default system resolver.
type Resolver struct {
	resolver *net.Resolver
}

// New creates a Resolver backed by the default system resolver.
func New() *Resolver {
	return &Resolver{resolver: net.DefaultResolver}
}

// LookupIPv4 returns the first IPv4 address found for host.
// Host may be a DNS name or an IPv4 literal.
func (r *Resolver) LookupIPv4(ctx context.Context, host string) (net.IP, error) {
	ips, err := r.resolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no ipv4 address found", host)
	}
	return ips[0], nil
}
