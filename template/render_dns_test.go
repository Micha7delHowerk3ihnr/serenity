package template

import (
	"context"
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestRenderDNSFakeIPGeoIPResponseMatching(t *testing.T) {
	template := &Template{}
	template.EnableFakeIP = true
	var options option.Options
	require.NoError(t, template.renderDNS(context.Background(), M.Metadata{}, &options))

	require.Len(t, options.DNS.Servers, 3)
	require.Equal(t, C.DNSTypeTLS, options.DNS.Servers[0].Type)
	require.Equal(t, C.DNSTypeHTTPS, options.DNS.Servers[1].Type)
	require.Equal(t, C.DNSTypeFakeIP, options.DNS.Servers[2].Type)
	require.True(t, hasDNSAction(options.DNS.Rules, C.RuleActionTypeEvaluate))
	require.True(t, hasGeoIPResponseMatch(options.DNS.Rules))
	require.True(t, hasFakeIPQueryRule(options.DNS.Rules))
	require.False(t, hasDNSRouteStrategy(options.DNS.Rules))
}

func hasDNSAction(rules []option.DNSRule, action string) bool {
	for _, rule := range rules {
		if rule.Type == C.RuleTypeDefault && rule.DefaultOptions.Action == action {
			return true
		}
		if rule.Type == C.RuleTypeLogical && hasDNSAction(rule.LogicalOptions.Rules, action) {
			return true
		}
	}
	return false
}

func hasGeoIPResponseMatch(rules []option.DNSRule) bool {
	for _, rule := range rules {
		if rule.Type == C.RuleTypeDefault && rule.DefaultOptions.MatchResponse != nil && rule.DefaultOptions.MatchResponse.Enabled {
			return true
		}
		if rule.Type == C.RuleTypeLogical && hasGeoIPResponseMatch(rule.LogicalOptions.Rules) {
			return true
		}
	}
	return false
}

func hasFakeIPQueryRule(rules []option.DNSRule) bool {
	for _, rule := range rules {
		if rule.Type == C.RuleTypeDefault && rule.DefaultOptions.Action == C.RuleActionTypeRoute && rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag && len(rule.DefaultOptions.QueryType) == 2 {
			return true
		}
		if rule.Type == C.RuleTypeLogical && hasFakeIPQueryRule(rule.LogicalOptions.Rules) {
			return true
		}
	}
	return false
}

func hasDNSRouteStrategy(rules []option.DNSRule) bool {
	for _, rule := range rules {
		if rule.Type == C.RuleTypeDefault && rule.DefaultOptions.RouteOptions.Strategy != 0 {
			return true
		}
		if rule.Type == C.RuleTypeLogical {
			if rule.LogicalOptions.RouteOptions.Strategy != 0 || hasDNSRouteStrategy(rule.LogicalOptions.Rules) {
				return true
			}
		}
	}
	return false
}
