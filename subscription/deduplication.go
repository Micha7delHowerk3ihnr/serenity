package subscription

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/task"
)

func Deduplication(ctx context.Context, servers []option.Outbound) []option.Outbound {
	resolveCtx := &resolveContext{
		ctx:      ctx,
		resolver: net.DefaultResolver,
	}

	uniqueServers := make([]netip.AddrPort, len(servers))
	var (
		resolveGroup task.Group
		resultAccess sync.Mutex
	)
	for index, server := range servers {
		currentIndex := index
		currentServer := server
		resolveGroup.Append0(func(ctx context.Context) error {
			destination := resolveDestination(resolveCtx, currentServer)
			if destination.IsValid() {
				resultAccess.Lock()
				uniqueServers[currentIndex] = destination
				resultAccess.Unlock()
			}
			return nil
		})
	}
	resolveGroup.Concurrency(5)
	_ = resolveGroup.Run(ctx)
	uniqueServerMap := make(map[netip.AddrPort]bool)
	var newServers []option.Outbound
	for index, server := range servers {
		destination := uniqueServers[index]
		if destination.IsValid() {
			if uniqueServerMap[destination] {
				continue
			}
			uniqueServerMap[destination] = true
		}
		newServers = append(newServers, server)
	}
	return newServers
}

type resolveContext struct {
	ctx      context.Context
	resolver *net.Resolver
}

func resolveDestination(ctx *resolveContext, server option.Outbound) netip.AddrPort {
	serverOptionsWrapper, loaded := server.Options.(option.ServerOptionsWrapper)
	if !loaded {
		return netip.AddrPort{}
	}
	serverOptions := serverOptionsWrapper.TakeServerOptions().Build()
	if serverOptions.IsIP() {
		return serverOptions.AddrPort()
	}
	if serverOptions.IsFqdn() {
		addresses, lookupErr := ctx.resolver.LookupNetIP(ctx.ctx, "ip", serverOptions.Fqdn)
		if lookupErr == nil && len(addresses) > 0 {
			return netip.AddrPortFrom(addresses[0], serverOptions.Port)
		}
	}
	return netip.AddrPort{}
}
