package sms_provider

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
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
	defaultAliyunApiBase = "https://dysmsapi.aliyuncs.com"
)

type AliyunProvider struct {
	Config  *conf.AliyunProviderConfiguration
	APIPath string
}

type AliyunResponse struct {
	RequestId string `json:"RequestId"`
	BizId     string `json:"BizId"`
	Code      string `json:"Code"`
	Message   string `json:"Message"`
}

// Creates a SmsProvider with the Aliyun Config
func NewAliyunProvider(config conf.AliyunProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultAliyunApiBase
	return &AliyunProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (a *AliyunProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return a.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Aliyun", channel)
	}
}

// Send an SMS containing the OTP with Aliyun's API
func (a *AliyunProvider) SendSms(phone string, message string) (string, error) {
	// Aliyun SMS API uses signature method v1
	params := map[string]string{
		"Action":        "SendSms",
		"Version":       "2017-05-25",
		"AccessKeyId":   a.Config.AccessKeyId,
		"Format":        "JSON",
		"SignatureMethod": "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce": fmt.Sprintf("%d", time.Now().UnixNano()),
		"Timestamp":     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"PhoneNumbers":  phone,
		"SignName":      a.Config.SignName,
		"TemplateCode":  a.Config.TemplateCode,
		"TemplateParam": fmt.Sprintf(`{"code":"%s"}`, message),
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
		canonicalQuery.WriteString(percentEncode(k))
		canonicalQuery.WriteString("=")
		canonicalQuery.WriteString(percentEncode(params[k]))
	}

	// Build string to sign
	stringToSign := fmt.Sprintf("POST&%s&%s", percentEncode("/"), percentEncode(canonicalQuery.String()))

	// Calculate signature
	signature := hmacSha1(stringToSign, a.Config.AccessKeySecret+"&")
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Add signature to params
	params["Signature"] = signatureBase64

	// Build request body
	body := url.Values{}
	for k, v := range params {
		body.Set(k, v)
	}

	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest("POST", a.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	resp := &AliyunResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	if resp.Code != "OK" {
		return resp.BizId, fmt.Errorf("aliyun error: %s (code: %s) requestId: %s", resp.Message, resp.Code, resp.RequestId)
	}

	return resp.BizId, nil
}

func (a *AliyunProvider) VerifyOTP(phone, code string) error {
	return fmt.Errorf("VerifyOTP is not supported for Aliyun")
}

// Helper functions for Aliyun signature
func hmacSha1(data, key string) []byte {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

func percentEncode(s string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(
					strings.ReplaceAll(url.QueryEscape(s), "+", "%20"),
					"*", "%2A"),
				"%7E", "~"),
			"%2F", "/"),
		"%3A", ":")
}

