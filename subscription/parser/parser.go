package parser

import (
	"context"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	servers, err := ParseBoxSubscription(ctx, content)
	if err != nil {
		return nil, E.Cause(err, "parse sing-box subscription")
	}
	return servers, nil
}
