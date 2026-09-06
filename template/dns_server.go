package template

import (
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type dnsServerBuildOptions struct {
	Tag              string
	Detour           string
	DomainResolver   string
	ResolverStrategy option.DomainStrategy
}

func (t *Template) dnsStrategy() option.DomainStrategy {
	if t.DomainStrategy != option.DomainStrategy(C.DomainStrategyAsIS) {
		return t.DomainStrategy
	}
	if t.EnableFakeIP {
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	}
	return option.DomainStrategy(C.DomainStrategyIPv4Only)
}

func (t *Template) localDNSStrategy() option.DomainStrategy {
	if t.DomainStrategyLocal != option.DomainStrategy(C.DomainStrategyAsIS) {
		return t.DomainStrategyLocal
	}
	return option.DomainStrategy(C.DomainStrategyPreferIPv4)
}

func buildDNSServer(address string, buildOptions dnsServerBuildOptions) (option.DNSServerOptions, bool, error) {
	result := option.DNSServerOptions{Tag: buildOptions.Tag}
	switch address {
	case "local":
		result.Type = C.DNSTypeLocal
		result.Options = &option.LocalDNSServerOptions{}
		return result, false, nil
	case "fakeip":
		return result, false, E.New("fakeip must be configured as a typed fakeip DNS server")
	}

	var serverURL *url.URL
	var serverType string
	if strings.Contains(address, "://") {
		var err error
		serverURL, err = url.Parse(address)
		if err != nil {
			return result, false, E.Cause(err, "parse DNS server address")
		}
		serverType = strings.ToLower(serverURL.Scheme)
	} else {
		serverType = C.DNSTypeUDP
	}

	if serverType == C.DNSTypeDHCP {
		dhcpOptions := &option.DHCPDNSServerOptions{}
		if serverURL != nil && serverURL.Host != "" && serverURL.Host != "auto" {
			dhcpOptions.Interface = serverURL.Host
		}
		result.Type = C.DNSTypeDHCP
		result.Options = dhcpOptions
		return result, false, nil
	}

	switch serverType {
	case C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeQUIC, C.DNSTypeHTTPS, C.DNSTypeHTTP3:
	default:
		if serverType == "rcode" {
			return result, false, E.New("rcode DNS servers were removed in sing-box 1.14; use a DNS rule with action=predefined instead")
		}
		return result, false, E.New("unsupported DNS server scheme: ", serverType)
	}

	serverAddress := address
	if serverURL != nil {
		serverAddress = serverURL.Host
	}
	socksaddr := M.ParseSocksaddr(serverAddress)
	if !socksaddr.IsValid() {
		return result, false, E.New("invalid DNS server address: ", serverAddress)
	}
	host := socksaddr.AddrString()
	isDomain := M.IsDomainName(host)

	var defaultPort uint16
	switch serverType {
	case C.DNSTypeUDP, C.DNSTypeTCP:
		defaultPort = 53
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		defaultPort = 853
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		defaultPort = 443
	}
	serverPort := socksaddr.Port
	if serverPort == defaultPort {
		serverPort = 0
	}

	dialerOptions := option.DialerOptions{Detour: buildOptions.Detour}
	if isDomain && buildOptions.DomainResolver != "" {
		dialerOptions.DomainResolver = &option.DomainResolveOptions{
			Server:   buildOptions.DomainResolver,
			Strategy: buildOptions.ResolverStrategy,
		}
	}
	remoteOptions := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialerOptions},
		DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: host, ServerPort: serverPort},
	}
	result.Type = serverType
	switch serverType {
	case C.DNSTypeUDP, C.DNSTypeTCP:
		result.Options = &remoteOptions
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		result.Options = &option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remoteOptions}
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		httpsOptions := &option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remoteOptions},
		}
		if serverURL != nil && serverURL.Path != "" && serverURL.Path != "/dns-query" {
			httpsOptions.Path = serverURL.Path
		}
		result.Options = httpsOptions
	}
	return result, isDomain, nil
}
