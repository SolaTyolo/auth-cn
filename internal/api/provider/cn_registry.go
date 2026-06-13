package provider

import (
	"context"

	"github.com/supabase/auth/internal/conf"
)

type CNOAuthResolver func(ctx context.Context, config *conf.GlobalConfiguration, scopes string) (OAuthProvider, conf.OAuthProviderConfiguration, error)

var cnOAuthProviders = map[string]CNOAuthResolver{}

func RegisterCNOAuthProvider(name string, resolver CNOAuthResolver) {
	cnOAuthProviders[name] = resolver
}

func ResolveCNOAuthProvider(ctx context.Context, name string, config *conf.GlobalConfiguration, scopes string) (OAuthProvider, conf.OAuthProviderConfiguration, error, bool) {
	resolver, ok := cnOAuthProviders[name]
	if !ok {
		return nil, conf.OAuthProviderConfiguration{}, nil, false
	}

	p, pConfig, err := resolver(ctx, config, scopes)
	return p, pConfig, err, true
}
