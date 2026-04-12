package parser

import (
	"context"
	stdjson "encoding/json"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// nonProxyTypes are outbound types that should be filtered out when parsing subscriptions.
// These are either utility types or types removed/deprecated in newer sing-box versions.
var nonProxyTypes = map[string]bool{
	C.TypeDirect:   true,
	C.TypeBlock:    true,
	C.TypeDNS:      true,
	C.TypeSelector: true,
	C.TypeURLTest:  true,
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	// Stage 1: Use standard encoding/json to extract outbounds and filter by type.
	// This avoids sing-box's strict deserializer rejecting deprecated types (e.g. dns outbound
	// removed in 1.13.0) before we can filter them out.
	var raw struct {
		Outbounds []stdjson.RawMessage `json:"outbounds"`
	}
	if err := stdjson.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}

	var proxyOutbounds []stdjson.RawMessage
	for _, rawOutbound := range raw.Outbounds {
		var peek struct {
			Type string `json:"type"`
		}
		if err := stdjson.Unmarshal(rawOutbound, &peek); err != nil {
			continue
		}
		if nonProxyTypes[peek.Type] {
			continue
		}
		proxyOutbounds = append(proxyOutbounds, rawOutbound)
	}

	if len(proxyOutbounds) == 0 {
		return nil, E.New("no servers found")
	}

	// Stage 2: Reconstruct a minimal JSON containing only proxy outbounds,
	// then pass to sing-box's context-aware deserializer.
	filtered, err := stdjson.Marshal(struct {
		Outbounds []stdjson.RawMessage `json:"outbounds"`
	}{Outbounds: proxyOutbounds})
	if err != nil {
		return nil, err
	}

	options, err := json.UnmarshalExtendedContext[option.Options](ctx, filtered)
	if err != nil {
		return nil, err
	}

	return options.Outbounds, nil
}
