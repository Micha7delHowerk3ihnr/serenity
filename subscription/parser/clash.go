package parser

import (
	"context"
	"math"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/metacubex/mihomo/adapter"
	clash_outbound "github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
)

func ParseClashSubscription(_ context.Context, content string) ([]option.Outbound, error) {
	config, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return nil, E.Cause(err, "parse clash config")
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	var outbounds []option.Outbound
	for i, proxyMapping := range config.Proxy {
		proxy, err := adapter.ParseProxy(proxyMapping)
		if err != nil {
			return nil, E.Cause(err, "parse proxy ", i)
		}
		var outbound option.Outbound
		outbound.Tag = proxy.Name()
		switch proxy.Type() {
		case constant.Shadowsocks:
			ssOption := &clash_outbound.ShadowSocksOption{}
			err = decoder.Decode(proxyMapping, ssOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeShadowsocks
			outbound.Options = &option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     ssOption.Server,
					ServerPort: uint16(ssOption.Port),
				},
				Password:      ssOption.Password,
				Method:        clashShadowsocksCipher(ssOption.Cipher),
				Plugin:        clashPluginName(ssOption.Plugin),
				PluginOptions: clashPluginOptions(ssOption.Plugin, ssOption.PluginOpts),
				Network:       clashNetworks(ssOption.UDP),
			}
		// case constant.ShadowsocksR:
		// 	ssrOption := &clash_outbound.ShadowSocksROption{}
		// 	err = decoder.Decode(proxyMapping, ssrOption)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	outbound.Type = C.TypeShadowsocksR
		// 	outbound.Options = &option.ShadowsocksROutboundOptions{
		// 		ServerOptions: option.ServerOptions{
		// 			Server:     ssrOption.Server,
		// 			ServerPort: uint16(ssrOption.Port),
		// 		},
		// 		Password:      ssrOption.Password,
		// 		Method:        clashShadowsocksCipher(ssrOption.Cipher),
		// 		Protocol:      ssrOption.Protocol,
		// 		ProtocolParam: ssrOption.ProtocolParam,
		// 		Obfs:          ssrOption.Obfs,
		// 		ObfsParam:     ssrOption.ObfsParam,
		// 		Network:       clashNetworks(ssrOption.UDP),
		// 	}
		case constant.Trojan:
			trojanOption := &clash_outbound.TrojanOption{}
			err = decoder.Decode(proxyMapping, trojanOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeTrojan
			tlsOptions := buildTLSOptions(true, trojanOption.SNI, trojanOption.SkipCertVerify, trojanOption.ALPN, trojanOption.Fingerprint, trojanOption.ECHOpts, &trojanOption.RealityOpts, false)
			if trojanOption.ClientFingerprint != "" {
				if tlsOptions == nil {
					tlsOptions = &option.OutboundTLSOptions{Enabled: true}
				}
				tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: trojanOption.ClientFingerprint}
			}
			outbound.Options = &option.TrojanOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     trojanOption.Server,
					ServerPort: uint16(trojanOption.Port),
				},
				Password:                    trojanOption.Password,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
				Transport:                   clashTransport(trojanOption.Network, clash_outbound.HTTPOptions{}, clash_outbound.HTTP2Options{}, trojanOption.GrpcOpts, trojanOption.WSOpts),
				Network:                     clashNetworks(trojanOption.UDP),
			}
		case constant.Vmess:
			vmessOption := &clash_outbound.VmessOption{}
			err = decoder.Decode(proxyMapping, vmessOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeVMess
			tlsOptions := buildTLSOptions(vmessOption.TLS, vmessOption.ServerName, vmessOption.SkipCertVerify, vmessOption.ALPN, vmessOption.Fingerprint, vmessOption.ECHOpts, &vmessOption.RealityOpts, false)
			if vmessOption.ClientFingerprint != "" {
				if tlsOptions == nil {
					tlsOptions = &option.OutboundTLSOptions{Enabled: vmessOption.TLS}
				}
				tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: vmessOption.ClientFingerprint}
			}
			outbound.Options = &option.VMessOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     vmessOption.Server,
					ServerPort: uint16(vmessOption.Port),
				},
				UUID:                        vmessOption.UUID,
				Security:                    vmessOption.Cipher,
				AlterId:                     vmessOption.AlterID,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
				Transport:                   clashTransport(vmessOption.Network, vmessOption.HTTPOpts, vmessOption.HTTP2Opts, vmessOption.GrpcOpts, vmessOption.WSOpts),
				Network:                     clashNetworks(vmessOption.UDP),
			}
		case constant.Vless:
			vlessOption := &clash_outbound.VlessOption{}
			err = decoder.Decode(proxyMapping, vlessOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeVLESS
			tlsOptions := buildTLSOptions(vlessOption.TLS, vlessOption.ServerName, vlessOption.SkipCertVerify, vlessOption.ALPN, vlessOption.Fingerprint, vlessOption.ECHOpts, &vlessOption.RealityOpts, false)
			if vlessOption.ClientFingerprint != "" {
				if tlsOptions == nil {
					tlsOptions = &option.OutboundTLSOptions{Enabled: vlessOption.TLS}
				}
				tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: vlessOption.ClientFingerprint}
			}
			vlessOutbound := &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     vlessOption.Server,
					ServerPort: uint16(vlessOption.Port),
				},
				UUID:                        vlessOption.UUID,
				Flow:                        vlessOption.Flow,
				Network:                     clashNetworks(vlessOption.UDP),
				Transport:                   clashTransport(vlessOption.Network, vlessOption.HTTPOpts, vlessOption.HTTP2Opts, vlessOption.GrpcOpts, vlessOption.WSOpts),
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
			}
			if vlessOption.PacketEncoding != "" {
				packetEncoding := vlessOption.PacketEncoding
				vlessOutbound.PacketEncoding = &packetEncoding
			}
			outbound.Options = vlessOutbound
		case constant.Hysteria2:
			hysteriaOption := &clash_outbound.Hysteria2Option{}
			err = decoder.Decode(proxyMapping, hysteriaOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeHysteria2
			tlsOptions := buildTLSOptions(true, hysteriaOption.SNI, hysteriaOption.SkipCertVerify, hysteriaOption.ALPN, hysteriaOption.Fingerprint, hysteriaOption.ECHOpts, nil, false)
			hysteriaOutbound := &option.Hysteria2OutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     hysteriaOption.Server,
					ServerPort: uint16(hysteriaOption.Port),
				},
				ServerPorts:                 parseClashPortList(hysteriaOption.Ports),
				HopInterval:                 durationFromSeconds(hysteriaOption.HopInterval),
				UpMbps:                      parseBandwidthToMbps(hysteriaOption.Up),
				DownMbps:                    parseBandwidthToMbps(hysteriaOption.Down),
				Password:                    hysteriaOption.Password,
				Obfs:                        buildHysteria2Obfs(hysteriaOption.Obfs, hysteriaOption.ObfsPassword),
				Network:                     option.NetworkList(""),
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
			}
			outbound.Options = hysteriaOutbound
		case constant.Tuic:
			tuicOption := &clash_outbound.TuicOption{}
			err = decoder.Decode(proxyMapping, tuicOption)
			if err != nil {
				return nil, err
			}
			outbound.Type = C.TypeTUIC
			tlsOptions := buildTLSOptions(true, tuicOption.SNI, tuicOption.SkipCertVerify, tuicOption.ALPN, tuicOption.Fingerprint, tuicOption.ECHOpts, nil, tuicOption.DisableSni)
			password := tuicOption.Password
			if password == "" {
				password = tuicOption.Token
			}
			tuicOutbound := &option.TUICOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     tuicOption.Server,
					ServerPort: uint16(tuicOption.Port),
				},
				UUID:                        tuicOption.UUID,
				Password:                    password,
				CongestionControl:           tuicOption.CongestionController,
				UDPRelayMode:                tuicOption.UdpRelayMode,
				UDPOverStream:               tuicOption.UDPOverStream,
				ZeroRTTHandshake:            tuicOption.ReduceRtt,
				Heartbeat:                   durationFromSeconds(tuicOption.HeartbeatInterval),
				Network:                     option.NetworkList(""),
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
			}
			outbound.Options = tuicOutbound
		case constant.Socks5:
			socks5Option := &clash_outbound.Socks5Option{}
			err = decoder.Decode(proxyMapping, socks5Option)
			if err != nil {
				return nil, err
			}

			if socks5Option.TLS {
				// TODO: print warning
				continue
			}

			outbound.Type = C.TypeSOCKS
			outbound.Options = &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     socks5Option.Server,
					ServerPort: uint16(socks5Option.Port),
				},
				Username: socks5Option.UserName,
				Password: socks5Option.Password,
				Network:  clashNetworks(socks5Option.UDP),
			}
		case constant.Http:
			httpOption := &clash_outbound.HttpOption{}
			err = decoder.Decode(proxyMapping, httpOption)
			if err != nil {
				return nil, err
			}

			if httpOption.TLS {
				continue
			}

			outbound.Type = C.TypeHTTP
			outbound.Options = &option.HTTPOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     httpOption.Server,
					ServerPort: uint16(httpOption.Port),
				},
				Username: httpOption.UserName,
				Password: httpOption.Password,
			}
		}
		outbounds = append(outbounds, outbound)
	}
	if len(outbounds) > 0 {
		return outbounds, nil
	}
	return nil, E.New("no servers found")
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	}
	return plugin
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, format.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		options["tls"] = opts["tls"]
		options["host"] = opts["host"]
		options["path"] = opts["path"]
	}
	return options.Build()
}

func buildTLSOptions(enabled bool, serverName string, skipVerify bool, alpn []string, fingerprint string, echOpts clash_outbound.ECHOptions, realityOpts *clash_outbound.RealityOptions, disableSNI bool) *option.OutboundTLSOptions {
	realityEnabled := realityOpts != nil && realityOpts.PublicKey != ""
	if !enabled && serverName == "" && !skipVerify && len(alpn) == 0 && fingerprint == "" && !echOpts.Enable && !realityEnabled && !disableSNI {
		return nil
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    enabled || realityEnabled,
		ServerName: serverName,
		Insecure:   skipVerify,
		DisableSNI: disableSNI,
	}
	if len(alpn) > 0 {
		copied := append([]string(nil), alpn...)
		tlsOptions.ALPN = badoption.Listable[string](copied)
	}
	if fingerprint != "" {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}
	}
	if echOpts.Enable {
		tlsOptions.ECH = &option.OutboundECHOptions{Enabled: true}
		configString := strings.TrimSpace(echOpts.Config)
		if configString != "" {
			tlsOptions.ECH.Config = badoption.Listable[string]{configString}
		}
	}
	if realityEnabled {
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: realityOpts.PublicKey,
			ShortID:   realityOpts.ShortID,
		}
	}
	return tlsOptions
}

func parseClashPortList(ports string) badoption.Listable[string] {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return nil
	}
	items := strings.Split(ports, ",")
	var result []string
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return badoption.Listable[string](result)
}

func parseBandwidthToMbps(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	bps := clash_outbound.StringToBps(strings.ToUpper(value))
	if bps == 0 {
		return 0
	}
	if bps > math.MaxInt64/8 {
		return math.MaxInt
	}
	mbps := (bps*8 + 1_000_000 - 1) / 1_000_000
	if mbps > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(mbps)
}

func durationFromSeconds(seconds int) badoption.Duration {
	if seconds <= 0 {
		return 0
	}
	return badoption.Duration(time.Duration(seconds) * time.Second)
}

func buildHysteria2Obfs(obfsType, password string) *option.Hysteria2Obfs {
	obfsType = strings.TrimSpace(obfsType)
	if obfsType == "" {
		return nil
	}
	return &option.Hysteria2Obfs{
		Type:     obfsType,
		Password: password,
	}
}

func clashTransport(network string, httpOpts clash_outbound.HTTPOptions, h2Opts clash_outbound.HTTP2Options, grpcOpts clash_outbound.GrpcOptions, wsOpts clash_outbound.WSOptions) *option.V2RayTransportOptions {
	switch network {
	case "http":
		var headers map[string]badoption.Listable[string]
		for key, values := range httpOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = values
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
			},
		}
	case "ws":
		var headers map[string]badoption.Listable[string]
		for key, value := range wsOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = []string{value}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	default:
		return nil
	}
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}
