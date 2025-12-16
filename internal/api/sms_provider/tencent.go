package sms_provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	defaultTencentApiBase = "https://sms.tencentcloudapi.com"
)

type TencentProvider struct {
	Config  *conf.TencentProviderConfiguration
	APIPath string
}

type TencentResponse struct {
	Response struct {
		SendStatusSet []struct {
			SerialNo     string `json:"SerialNo"`
			PhoneNumber  string `json:"PhoneNumber"`
			Fee          int    `json:"Fee"`
			SessionContext string `json:"SessionContext"`
			Code         string `json:"Code"`
			Message      string `json:"Message"`
			IsoCode      string `json:"IsoCode"`
		} `json:"SendStatusSet"`
		RequestId string `json:"RequestId"`
	} `json:"Response"`
}

// Creates a SmsProvider with the Tencent Config
func NewTencentProvider(config conf.TencentProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultTencentApiBase
	return &TencentProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *TencentProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Tencent", channel)
	}
}

// Send an SMS containing the OTP with Tencent's API
func (t *TencentProvider) SendSms(phone string, message string) (string, error) {
	// Tencent Cloud SMS API requires signature v3 authentication
	// This is a simplified implementation - in production, you may want to use the official SDK
	timestamp := time.Now().Unix()
	date := time.Now().UTC().Format("2006-01-02")

	// Prepare request parameters
	params := map[string]string{
		"Action":          "SendSms",
		"Version":         "2021-01-11",
		"Region":          t.Config.Region,
		"PhoneNumberSet.0": phone,
		"TemplateID":      t.Config.TemplateID,
		"SmsSdkAppId":     t.Config.SmsSdkAppId,
		"TemplateParamSet.0": message,
		"Timestamp":       fmt.Sprintf("%d", timestamp),
		"Nonce":           fmt.Sprintf("%d", timestamp),
	}

	// Build canonical query string
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalQuery strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalQuery.WriteString("&")
		}
		canonicalQuery.WriteString(url.QueryEscape(k))
		canonicalQuery.WriteString("=")
		canonicalQuery.WriteString(url.QueryEscape(params[k]))
	}

	// Build canonical request
	canonicalRequest := fmt.Sprintf("POST\n/\n%s\nhost:%s\n\nhost\n", canonicalQuery.String(), "sms.tencentcloudapi.com")

	// Build string to sign
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s/sms/tc3_request\n%s",
		timestamp, date, sha256Hash(canonicalRequest))

	// Calculate signature
	secretDate := hmacSha256(date, "TC3"+t.Config.SecretKey)
	secretService := hmacSha256("sms", secretDate)
	secretSigning := hmacSha256("tc3_request", secretService)
	signature := hexEncode(hmacSha256(stringToSign, secretSigning))

	// Build authorization header
	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s/sms/tc3_request, SignedHeaders=host, Signature=%s",
		t.Config.SecretId, date, signature)

	// Build request body
	body := url.Values{}
	for k, v := range params {
		body.Set(k, v)
	}

	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Host", "sms.tencentcloudapi.com")
	req.Header.Set("X-TC-Action", "SendSms")
	req.Header.Set("X-TC-Version", "2021-01-11")
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-TC-Region", t.Config.Region)

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	resp := &TencentResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	if len(resp.Response.SendStatusSet) == 0 {
		return "", fmt.Errorf("tencent error: no response data")
	}

	status := resp.Response.SendStatusSet[0]
	if status.Code != "Ok" {
		return status.SerialNo, fmt.Errorf("tencent error: %s (code: %s) for message %s", status.Message, status.Code, status.SerialNo)
	}

	return status.SerialNo, nil
}

func (t *TencentProvider) VerifyOTP(phone, code string) error {
	return fmt.Errorf("VerifyOTP is not supported for Tencent")
}

// Helper functions for Tencent Cloud signature
func sha256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hmacSha256(data, key string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexEncode(data []byte) string {
	return fmt.Sprintf("%x", data)
}

