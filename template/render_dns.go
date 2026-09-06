package template

import (
	"context"
	"net/netip"

	M "github.com/sagernet/serenity/common/metadata"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
)

func (t *Template) renderDNS(_ context.Context, metadata M.Metadata, options *option.Options) error {
	domainStrategy := t.dnsStrategy()
	domainStrategyLocal := t.localDNSStrategy()
	if domainStrategyLocal == domainStrategy {
		domainStrategyLocal = option.DomainStrategy(C.DomainStrategyAsIS)
	}
	options.DNS = &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			ReverseMapping:   !t.DisableTrafficBypass && metadata.Platform != M.PlatformUnknown && !metadata.Platform.IsApple(),
			DNSClientOptions: option.DNSClientOptions{Strategy: domainStrategy},
		},
	}

	dnsDefault := t.DNS
	if dnsDefault == "" {
		dnsDefault = DefaultDNS
	}
	dnsLocal := t.DNSLocal
	if dnsLocal == "" {
		dnsLocal = DefaultDNSLocal
	}
	defaultTag := t.DefaultTag
	if defaultTag == "" {
		defaultTag = DefaultDefaultTag
	}

	defaultDNSOptions, _, err := buildDNSServer(dnsDefault, dnsServerBuildOptions{
		Tag:              DNSDefaultTag,
		Detour:           defaultTag,
		DomainResolver:   DNSLocalTag,
		ResolverStrategy: domainStrategyLocal,
	})
	if err != nil {
		return E.Cause(err, "build default DNS server")
	}
	options.DNS.Servers = append(options.DNS.Servers, defaultDNSOptions)

	localDNSAddress := dnsLocal
	if t.DisableTrafficBypass {
		localDNSAddress = "local"
	}
	localDNSOptions, localDNSIsDomain, err := buildDNSServer(localDNSAddress, dnsServerBuildOptions{
		Tag:              DNSLocalTag,
		DomainResolver:   DNSLocalSetupTag,
		ResolverStrategy: domainStrategyLocal,
	})
	if err != nil {
		return E.Cause(err, "build local DNS server")
	}
	options.DNS.Servers = append(options.DNS.Servers, localDNSOptions)
	if localDNSIsDomain {
		options.DNS.Servers = append(options.DNS.Servers, option.DNSServerOptions{
			Type:    C.DNSTypeLocal,
			Tag:     DNSLocalSetupTag,
			Options: &option.LocalDNSServerOptions{},
		})
	}

	if t.EnableFakeIP {
		var inet4Range, inet6Range *badoption.Prefix
		if t.CustomFakeIP != nil {
			inet4Range = t.CustomFakeIP.Inet4Range
			inet6Range = t.CustomFakeIP.Inet6Range
		} else {
			inet4Range = (*badoption.Prefix)(common.Ptr(netip.MustParsePrefix("198.18.0.0/15")))
			if !t.DisableIPv6() {
				inet6Range = (*badoption.Prefix)(common.Ptr(netip.MustParsePrefix("fc00::/18")))
			}
		}
		options.DNS.Servers = append(options.DNS.Servers, option.DNSServerOptions{
			Tag:  DNSFakeIPTag,
			Type: C.DNSTypeFakeIP,
			Options: &option.FakeIPDNSServerOptions{
				Inet4Range: inet4Range,
				Inet6Range: inet6Range,
			},
		})
	}
	options.DNS.Servers = append(options.DNS.Servers, t.DNSServers...)

	clashModeRule := t.ClashModeRule
	if clashModeRule == "" {
		clashModeRule = "Rule"
	}
	clashModeGlobal := t.ClashModeGlobal
	if clashModeGlobal == "" {
		clashModeGlobal = "Global"
	}
	clashModeDirect := t.ClashModeDirect
	if clashModeDirect == "" {
		clashModeDirect = "Direct"
	}
	if !t.DisableClashMode {
		options.DNS.Rules = append(options.DNS.Rules,
			dnsRouteRule(option.RawDefaultDNSRule{ClashMode: clashModeGlobal}, DNSDefaultTag),
			dnsRouteRule(option.RawDefaultDNSRule{ClashMode: clashModeDirect}, DNSLocalTag),
		)
	}
	options.DNS.Rules = append(options.DNS.Rules, t.PreDNSRules...)
	if len(t.CustomDNSRules) == 0 {
		if !t.DisableTrafficBypass {
			options.DNS.Rules = append(options.DNS.Rules,
				dnsRouteRule(option.RawDefaultDNSRule{RuleSet: []string{"geosite-geolocation-cn"}}, DNSLocalTag),
			)
			if !t.DisableDNSLeak {
				options.DNS.Rules = append(options.DNS.Rules,
					dnsRouteRule(option.RawDefaultDNSRule{ClashMode: clashModeRule}, DNSDefaultTag),
					dnsEvaluateRule(),
					dnsGeoIPCNRule(),
				)
			}
		}
	} else {
		options.DNS.Rules = append(options.DNS.Rules, t.CustomDNSRules...)
	}
	if t.EnableFakeIP {
		options.DNS.Rules = append(options.DNS.Rules, dnsRouteRule(option.RawDefaultDNSRule{
			QueryType: []option.DNSQueryType{option.DNSQueryType(mDNS.TypeA), option.DNSQueryType(mDNS.TypeAAAA)},
		}, DNSFakeIPTag))
	}
	return nil
}

func dnsRouteRule(rule option.RawDefaultDNSRule, server string) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: rule,
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: server},
			},
		},
	}
}

func dnsEvaluateRule() option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				QueryType: []option.DNSQueryType{option.DNSQueryType(mDNS.TypeA), option.DNSQueryType(mDNS.TypeAAAA)},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:          C.RuleActionTypeEvaluate,
				EvaluateOptions: option.DNSEvaluateActionOptions{Server: DNSDefaultTag},
			},
		},
	}
}

func dnsGeoIPCNRule() option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalDNSRule{
			RawLogicalDNSRule: option.RawLogicalDNSRule{
				Mode: C.LogicalTypeAnd,
				Rules: []option.DNSRule{
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{
							RuleSet:       []string{"geoip-cn"},
							MatchResponse: &option.DNSRuleMatchResponse{Enabled: true},
						}},
					},
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{
							RuleSet: []string{"geosite-geolocation-!cn"},
							Invert:  true,
						}},
					},
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: DNSLocalTag},
			},
		},
	}
}
