package template

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestBuildDNSServer(t *testing.T) {
	testCases := []struct {
		address    string
		serverType string
		server     string
		serverPort uint16
		isDomain   bool
	}{
		{"8.8.8.8", C.DNSTypeUDP, "8.8.8.8", 0, false},
		{"8.8.8.8:5353", C.DNSTypeUDP, "8.8.8.8", 5353, false},
		{"udp://8.8.8.8", C.DNSTypeUDP, "8.8.8.8", 0, false},
		{"tcp://8.8.8.8", C.DNSTypeTCP, "8.8.8.8", 0, false},
		{"tls://8.8.8.8", C.DNSTypeTLS, "8.8.8.8", 0, false},
		{"quic://1.1.1.1", C.DNSTypeQUIC, "1.1.1.1", 0, false},
		{"https://1.1.1.1/dns-query", C.DNSTypeHTTPS, "1.1.1.1", 0, false},
		{"https://dns.google/dns-query", C.DNSTypeHTTPS, "dns.google", 0, true},
		{"h3://1.1.1.1/dns-query", C.DNSTypeHTTP3, "1.1.1.1", 0, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.address, func(t *testing.T) {
			server, isDomain, err := buildDNSServer(testCase.address, dnsServerBuildOptions{
				Tag:              "test",
				Detour:           "proxy",
				DomainResolver:   DNSLocalTag,
				ResolverStrategy: option.DomainStrategy(C.DomainStrategyPreferIPv4),
			})
			require.NoError(t, err)
			require.Equal(t, testCase.serverType, server.Type)
			require.Equal(t, testCase.isDomain, isDomain)
			remoteOptions := dnsRemoteOptions(t, server)
			require.Equal(t, testCase.server, remoteOptions.Server)
			require.Equal(t, testCase.serverPort, remoteOptions.ServerPort)
			require.Equal(t, "proxy", remoteOptions.Detour)
			if testCase.isDomain {
				require.NotNil(t, remoteOptions.DomainResolver)
				require.Equal(t, DNSLocalTag, remoteOptions.DomainResolver.Server)
			}
		})
	}

	local, isDomain, err := buildDNSServer("local", dnsServerBuildOptions{Tag: "local"})
	require.NoError(t, err)
	require.False(t, isDomain)
	require.Equal(t, C.DNSTypeLocal, local.Type)

	dhcp, isDomain, err := buildDNSServer("dhcp://eth0", dnsServerBuildOptions{Tag: "dhcp"})
	require.NoError(t, err)
	require.False(t, isDomain)
	require.Equal(t, C.DNSTypeDHCP, dhcp.Type)
	require.Equal(t, "eth0", dhcp.Options.(*option.DHCPDNSServerOptions).Interface)

	_, _, err = buildDNSServer("fakeip", dnsServerBuildOptions{})
	require.Error(t, err)
}

func dnsRemoteOptions(t *testing.T, server option.DNSServerOptions) option.RemoteDNSServerOptions {
	t.Helper()
	switch options := server.Options.(type) {
	case *option.RemoteDNSServerOptions:
		return *options
	case *option.RemoteTLSDNSServerOptions:
		return options.RemoteDNSServerOptions
	case *option.RemoteHTTPSDNSServerOptions:
		return options.RemoteDNSServerOptions
	default:
		t.Fatalf("unexpected DNS server options type %T", server.Options)
		return option.RemoteDNSServerOptions{}
	}
}
