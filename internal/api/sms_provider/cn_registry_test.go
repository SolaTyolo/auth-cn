package sms_provider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestResolveCNSMSRegisteredProviders(t *testing.T) {
	config := conf.GlobalConfiguration{}

	for _, name := range []string{"tencent", "aliyun"} {
		_, _, ok := ResolveCNSMSProvider(config, name)
		require.True(t, ok, "expected sms provider %q to be registered", name)
	}

	_, _, ok := ResolveCNSMSProvider(config, "unknown")
	require.False(t, ok)
}
