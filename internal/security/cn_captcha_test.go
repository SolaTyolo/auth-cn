package security

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTencentCaptchaHelpers(t *testing.T) {
	require.True(t, isSupportedCNCaptchaProvider("tencent"))

	captchaURL, ok := getCNCaptchaURL("tencent")
	require.True(t, ok)
	require.Equal(t, "https://ssl.captcha.qq.com/ticket/verify", captchaURL)

	data, err := buildTencentCaptchaRequest(`{"ticket":"t1","randstr":"r1"}`, "secret", "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "t1", data.Get("Ticket"))
	require.Equal(t, "r1", data.Get("Randstr"))

	response, err := decodeTencentCaptchaResponse([]byte(`{"response":1}`))
	require.NoError(t, err)
	require.True(t, response.Success)
}

func TestIsSupportedCaptchaProvider(t *testing.T) {
	require.True(t, IsSupportedCaptchaProvider("hcaptcha"))
	require.True(t, IsSupportedCaptchaProvider("turnstile"))
	require.True(t, IsSupportedCaptchaProvider("tencent"))
	require.False(t, IsSupportedCaptchaProvider("unknown"))
}
