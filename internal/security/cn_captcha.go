package security

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/utilities"
)

const tencentCaptchaProvider = "tencent"

func isSupportedCNCaptchaProvider(name string) bool {
	return name == tencentCaptchaProvider
}

func getCNCaptchaURL(providerName string) (string, bool) {
	if providerName == tencentCaptchaProvider {
		return "https://ssl.captcha.qq.com/ticket/verify", true
	}
	return "", false
}

func verifyTencentCaptchaCode(ctx context.Context, client *http.Client, secret, token, clientIP, captchaURL string) (*VerificationResponse, error) {
	data, err := buildTencentCaptchaRequest(token, secret, clientIP)
	if err != nil {
		return nil, err
	}

	r, err := http.NewRequestWithContext(ctx, "POST", captchaURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "couldn't initialize request object for captcha check")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := client.Do(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify captcha response")
	}
	defer utilities.SafeClose(res.Body)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read captcha response body")
	}

	return decodeTencentCaptchaResponse(body)
}

func buildTencentCaptchaRequest(token, secretKey, clientIP string) (url.Values, error) {
	data := url.Values{}

	var tencentToken struct {
		Ticket  string `json:"ticket"`
		Randstr string `json:"randstr"`
		Aid     string `json:"aid,omitempty"`
	}

	if err := json.Unmarshal([]byte(token), &tencentToken); err != nil {
		parts := strings.Split(token, ":")
		switch len(parts) {
		case 2:
			tencentToken.Ticket = parts[0]
			tencentToken.Randstr = parts[1]
		case 3:
			tencentToken.Aid = parts[0]
			tencentToken.Ticket = parts[1]
			tencentToken.Randstr = parts[2]
		default:
			return nil, errors.Wrap(err, "failed to parse tencent captcha token")
		}
	}

	if tencentToken.Ticket == "" || tencentToken.Randstr == "" {
		return nil, errors.New("tencent captcha token missing ticket or randstr")
	}

	if tencentToken.Aid != "" {
		data.Set("aid", tencentToken.Aid)
	}
	data.Set("AppSecretKey", secretKey)
	data.Set("Ticket", tencentToken.Ticket)
	data.Set("Randstr", tencentToken.Randstr)
	data.Set("UserIP", clientIP)

	return data, nil
}

func decodeTencentCaptchaResponse(body []byte) (*VerificationResponse, error) {
	var tencentResponse struct {
		Response int    `json:"response"`
		ErrMsg   string `json:"err_msg,omitempty"`
	}
	if err := json.Unmarshal(body, &tencentResponse); err != nil {
		return nil, errors.Wrap(err, "failed to decode tencent captcha response: not JSON")
	}

	verificationResponse := &VerificationResponse{
		Success: tencentResponse.Response == 1,
	}
	if !verificationResponse.Success {
		verificationResponse.ErrorCodes = []string{tencentResponse.ErrMsg}
	}

	return verificationResponse, nil
}
