package parser

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/stretchr/testify/require"
)

func TestParseSubscriptionAcceptsSingBoxJSONOnly(t *testing.T) {
	ctx := include.Context(context.Background())
	servers, err := ParseSubscription(ctx, `{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "1.1.1.1",
      "server_port": 443,
      "method": "aes-128-gcm",
      "password": "password"
    }
  ]
}`)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.Equal(t, "shadowsocks", servers[0].Type)
}

func TestParseSubscriptionRejectsOtherFormats(t *testing.T) {
	ctx := include.Context(context.Background())
	for name, content := range map[string]string{
		"Clash YAML": "proxies:\n  - name: proxy\n    type: ss\n    server: 1.1.1.1\n",
		"SIP008":     `{"version":1,"servers":[]}`,
		"proxy link": "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.1.1.1:443#proxy",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSubscription(ctx, content)
			require.Error(t, err)
		})
	}
}
