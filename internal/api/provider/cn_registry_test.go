package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestResolveCNOAuthRegisteredProviders(t *testing.T) {
	config := &conf.GlobalConfiguration{}

	for _, name := range []string{"line", "douyin", "wechat", "wechat_work"} {
		_, _, _, ok := ResolveCNOAuthProvider(t.Context(), name, config, "")
		require.True(t, ok, "expected oauth provider %q to be registered", name)
	}

	_, _, _, ok := ResolveCNOAuthProvider(t.Context(), "unknown", config, "")
	require.False(t, ok)
}
