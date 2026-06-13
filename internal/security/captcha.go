package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

type VerificationResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
}

// CaptchaVerifier abstracts CAPTCHA verification for different providers (hCaptcha, Cloudflare Turnstile, etc.)
// and allows for mocking in tests.
type CaptchaVerifier interface {
	Verify(ctx context.Context, token, clientIP string) (*VerificationResponse, error)
}

// HTTPCaptchaVerifier is the default implementation that calls out to hCaptcha / Turnstile.
type HTTPCaptchaVerifier struct {
	client   *http.Client
	secret   string
	provider string
}

func NewCaptchaVerifier(cfg *conf.CaptchaConfiguration) *HTTPCaptchaVerifier {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &HTTPCaptchaVerifier{
		client:   &http.Client{Timeout: timeout},
		secret:   strings.TrimSpace(cfg.Secret),
		provider: cfg.Provider,
	}
}

func (v *HTTPCaptchaVerifier) Verify(ctx context.Context, token, clientIP string) (*VerificationResponse, error) {
	captchaURL, err := getCaptchaURL(v.provider)
	if err != nil {
		return nil, err
	}

	return verifyCaptchaCode(captchaResponse, secretKey, clientIP, captchaURL, captchaProvider)
}

// buildCaptchaRequestData builds request data for different captcha providers
func buildCaptchaRequestData(token, secretKey, clientIP, captchaProvider string) (url.Values, error) {
	switch captchaProvider {
	case "tencent":
		return buildTencentCaptchaData(token, secretKey, clientIP)
	case "hcaptcha", "turnstile":
		return buildStandardCaptchaData(token, secretKey, clientIP), nil
	default:
		return nil, fmt.Errorf("unsupported captcha provider: %s", captchaProvider)
	}
}

// buildTencentCaptchaData builds request data for Tencent captcha
func buildTencentCaptchaData(token, secretKey, clientIP string) (url.Values, error) {
	data := url.Values{}

	// Tencent captcha requires different parameters
	// Token format: JSON string with ticket, randstr, and optionally aid
	var tencentToken struct {
		Ticket  string `json:"ticket"`
		Randstr string `json:"randstr"`
		Aid     string `json:"aid,omitempty"`
	}

	if err := json.Unmarshal([]byte(token), &tencentToken); err != nil {
		// Try parsing as colon-separated format: ticket:randstr or aid:ticket:randstr
		parts := strings.Split(token, ":")
		if len(parts) == 2 {
			tencentToken.Ticket = parts[0]
			tencentToken.Randstr = parts[1]
		} else if len(parts) == 3 {
			tencentToken.Aid = parts[0]
			tencentToken.Ticket = parts[1]
			tencentToken.Randstr = parts[2]
		} else {
			return nil, errors.Wrap(err, "failed to parse tencent captcha token")
		}
	}

	if tencentToken.Ticket == "" || tencentToken.Randstr == "" {
		return nil, errors.New("tencent captcha token missing ticket or randstr")
	}

	// Tencent captcha API parameters
	if tencentToken.Aid != "" {
		data.Set("aid", tencentToken.Aid)
	}
	data.Set("AppSecretKey", secretKey)
	data.Set("Ticket", tencentToken.Ticket)
	data.Set("Randstr", tencentToken.Randstr)
	data.Set("UserIP", clientIP)

	return data, nil
}

// buildStandardCaptchaData builds request data for standard captcha providers (hcaptcha, turnstile)
func buildStandardCaptchaData(token, secretKey, clientIP string) url.Values {
	data := url.Values{}
	data.Set("secret", v.secret)
	data.Set("response", token)
	data.Set("remoteip", clientIP)
	// TODO (darora): pipe through sitekey
	return data
}

func verifyCaptchaCode(token, secretKey, clientIP, captchaURL, captchaProvider string) (VerificationResponse, error) {
	data, err := buildCaptchaRequestData(token, secretKey, clientIP, captchaProvider)
	if err != nil {
		return VerificationResponse{}, err
	}

	r, err := http.NewRequestWithContext(ctx, "POST", captchaURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "couldn't initialize request object for captcha check")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := v.client.Do(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify captcha response")
	}
	defer utilities.SafeClose(res.Body)

	var verificationResponse VerificationResponse

	if captchaProvider == "tencent" {
		// Tencent captcha returns different response format
			Response int    `json:"response"`
			ErrMsg   string `json:"err_msg,omitempty"`
		}
		if err := json.NewDecoder(res.Body).Decode(&tencentResponse); err != nil {
			return VerificationResponse{}, errors.Wrap(err, "failed to decode tencent captcha response: not JSON")
		}
		// Tencent captcha: response == 1 means success
		verificationResponse.Success = tencentResponse.Response == 1
		if !verificationResponse.Success {
			verificationResponse.ErrorCodes = []string{tencentResponse.ErrMsg}
		}
	} else {
		// Standard captcha providers (hcaptcha, turnstile)
		if err := json.NewDecoder(res.Body).Decode(&verificationResponse); err != nil {
			return VerificationResponse{}, errors.Wrap(err, "failed to decode captcha response: not JSON")
		}
	}
	if err := json.NewDecoder(res.Body).Decode(&verificationResponse); err != nil {
		return nil, errors.Wrap(err, "failed to decode captcha response: not JSON")
}

func getCaptchaURL(captchaProvider string) (string, error) {
	switch captchaProvider {
	case "hcaptcha":
		return "https://hcaptcha.com/siteverify", nil
	case "turnstile":
		return "https://challenges.cloudflare.com/turnstile/v0/siteverify", nil
	case "tencent":
		return "https://ssl.captcha.qq.com/ticket/verify", nil
	default:
		return "", fmt.Errorf("captcha Provider %q could not be found", captchaProvider)
	}
}
