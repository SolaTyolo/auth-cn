package security

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pkg/errors"
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

func buildCNCaptchaRequest(token, secretKey, clientIP, providerName string) (url.Values, bool, error) {
	if providerName != tencentCaptchaProvider {
		return nil, false, nil
	}

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
			return nil, true, errors.Wrap(err, "failed to parse tencent captcha token")
		}
	}

	if tencentToken.Ticket == "" || tencentToken.Randstr == "" {
		return nil, true, errors.New("tencent captcha token missing ticket or randstr")
	}

	if tencentToken.Aid != "" {
		data.Set("aid", tencentToken.Aid)
	}
	data.Set("AppSecretKey", secretKey)
	data.Set("Ticket", tencentToken.Ticket)
	data.Set("Randstr", tencentToken.Randstr)
	data.Set("UserIP", clientIP)

	return data, true, nil
}

func decodeCNCaptchaResponse(body []byte, providerName string) (*VerificationResponse, bool, error) {
	if providerName != tencentCaptchaProvider {
		return nil, false, nil
	}

	var tencentResponse struct {
		Response int    `json:"response"`
		ErrMsg   string `json:"err_msg,omitempty"`
	}
	if err := json.Unmarshal(body, &tencentResponse); err != nil {
		return nil, true, errors.Wrap(err, "failed to decode tencent captcha response: not JSON")
	}

	verificationResponse := &VerificationResponse{
		Success: tencentResponse.Response == 1,
	}
	if !verificationResponse.Success {
		verificationResponse.ErrorCodes = []string{tencentResponse.ErrMsg}
	}

	return verificationResponse, true, nil
}
