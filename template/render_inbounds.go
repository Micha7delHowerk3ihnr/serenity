package template

import (
	"context"
	"net/netip"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

func (t *Template) renderInbounds(metadata M.Metadata, options *option.Options) error {
	options.Inbounds = t.Inbounds
	autoRedirect := t.AutoRedirect &&
		!metadata.Platform.IsApple() &&
		(metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.10.0-alpha.2")))
	disableTun := t.DisableTUN && !metadata.Platform.TunOnly()
	if !disableTun {
		options.Route.AutoDetectInterface = true
		address := []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}
		if !t.DisableIPv6() {
			address = append(address, netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
		}
		tunOptions := &option.TunInboundOptions{
			AutoRoute: true,
			Address:   address,
		}
		tunInbound := option.Inbound{
			Type:    C.TypeTun,
			Options: tunOptions,
		}
		if autoRedirect {
			tunOptions.AutoRedirect = true
			if !t.DisableTrafficBypass && metadata.Platform == "" {
				tunOptions.RouteExcludeAddressSet = []string{"geoip-cn"}
			}
		}
		if metadata.Platform == M.PlatformUnknown {
			tunOptions.StrictRoute = true
		}
		if !t.DisableSystemProxy && metadata.Platform != M.PlatformUnknown {
			var httpPort uint16
			if t.CustomMixed != nil {
				httpPort = t.CustomMixed.Value.ListenPort
			}
			if httpPort == 0 {
				httpPort = DefaultMixedPort
			}
			tunOptions.Platform = &option.TunPlatformOptions{
				HTTPProxy: &option.HTTPProxyOptions{
					Enabled: true,
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: httpPort,
					},
				},
			}
		}
		if t.CustomTUN != nil {
			newTUNOptions, err := badjson.MergeFromDestination(context.Background(), tunOptions, t.CustomTUN.Message, true)
			if err != nil {
				return E.Cause(err, "merge custom tun options")
			}
			tunInbound.Options = newTUNOptions
		}
		options.Inbounds = append(options.Inbounds, tunInbound)
	}
	if disableTun || !t.DisableSystemProxy {
		mixedOptions := &option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))),
				ListenPort: DefaultMixedPort,
			},
			SetSystemProxy: metadata.Platform == M.PlatformUnknown && disableTun && !t.DisableSystemProxy,
		}
		mixedInbound := option.Inbound{
			Type:    C.TypeMixed,
			Options: mixedOptions,
		}
		if t.CustomMixed != nil {
			newMixedOptions, err := badjson.MergeFromDestination(context.Background(), mixedOptions, t.CustomMixed.Message, true)
			if err != nil {
				return E.Cause(err, "merge custom mixed options")
			}
			mixedInbound.Options = newMixedOptions
		}
		options.Inbounds = append(options.Inbounds, mixedInbound)
	}
	return nil
}
