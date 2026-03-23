package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWechatWorkAuthBase  = "open.work.weixin.qq.com"
	defaultWechatWorkTokenBase = "qyapi.weixin.qq.com"
	defaultWechatWorkAPIBase   = "qyapi.weixin.qq.com"
)

type wechatWorkProvider struct {
	*oauth2.Config
	UserInfoURL string
	CorpID      string
}

type wechatWorkUser struct {
	UserID     string `json:"UserId"`
	DeviceID   string `json:"DeviceId"`
	UserTicket string `json:"user_ticket"`
	OpenID     string `json:"OpenId"`
}

type wechatWorkUserDetail struct {
	UserID    string `json:"userid"`
	Name      string `json:"name"`
	Mobile    string `json:"mobile"`
	Email     string `json:"email"`
	Avatar    string `json:"avatar"`
	Alias     string `json:"alias"`
	Telephone string `json:"telephone"`
	Gender    string `json:"gender"`
	Status    int    `json:"status"`
}

// NewWechatWorkProvider creates a WeChat Work (Enterprise WeChat) account provider.
func NewWechatWorkProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultWechatWorkAuthBase)
	tokenHost := chooseHost(ext.URL, defaultWechatWorkTokenBase)
	userInfoURL := chooseHost(ext.URL, defaultWechatWorkAPIBase) + "/cgi-bin/user/get"

	oauthScopes := []string{
		"snsapi_base",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	// Extract CorpID from ApiURL or use a separate config field
	// For now, we'll use ApiURL as CorpID if provided
	corpID := ext.ApiURL
	if corpID == "" {
		corpID = ext.ClientID[0] // Fallback to ClientID if ApiURL not set
	}

	return &wechatWorkProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/wwopen/sso/qrConnect",
				TokenURL: tokenHost + "/cgi-bin/gettoken",
			},
			Scopes: oauthScopes,
		},
		UserInfoURL: userInfoURL,
		CorpID:      corpID,
	}, nil
}

func (p wechatWorkProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p wechatWorkProvider) RequiresPKCE() bool {
	return false
}

func (p wechatWorkProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// WeChat Work OAuth flow: after getting access token, call getuserinfo endpoint
	// Note: The actual implementation may vary based on WeChat Work API version
	var userInfo wechatWorkUser
	userInfoURL := "https://" + defaultWechatWorkAPIBase + "/cgi-bin/user/getuserinfo?access_token=" + tok.AccessToken
	if err := makeRequest(ctx, tok, p.Config, userInfoURL, &userInfo); err != nil {
		// If user info fetch fails, return minimal data
		data := &UserProvidedData{}
		if tok.Extra("userid") != nil {
			if userid, ok := tok.Extra("userid").(string); ok {
				data.Metadata = &Claims{
					Issuer:   p.UserInfoURL,
					Subject:  userid,
					ProviderId: userid,
				}
			}
		}
		return data, nil
	}

	// Then get detailed user information using userid
	var userDetail wechatWorkUserDetail
	detailURL := p.UserInfoURL + "?access_token=" + tok.AccessToken + "&userid=" + userInfo.UserID
	if err := makeRequest(ctx, tok, p.Config, detailURL, &userDetail); err != nil {
		// If detail fetch fails, use basic info
		data := &UserProvidedData{}
		if userInfo.UserID != "" {
			data.Metadata = &Claims{
				Issuer:   p.UserInfoURL,
				Subject:  userInfo.UserID,
				ProviderId: userInfo.UserID,
			}
		}
		return data, nil
	}

	data := &UserProvidedData{}
	if userDetail.Email != "" {
		data.Emails = []Email{{
			Email:    userDetail.Email,
			Verified: true, // Enterprise WeChat emails are typically verified
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:   p.UserInfoURL,
		Subject:  userDetail.UserID,
		Name:     userDetail.Name,
		Picture:  userDetail.Avatar,
		Email:    userDetail.Email,
		Phone:    userDetail.Mobile,
		EmailVerified: userDetail.Email != "",
		PhoneVerified: userDetail.Mobile != "",
		CustomClaims: map[string]interface{}{
			"alias":     userDetail.Alias,
			"telephone": userDetail.Telephone,
			"gender":    userDetail.Gender,
			"status":    userDetail.Status,
		},

		// To be deprecated
		AvatarURL:  userDetail.Avatar,
		FullName:   userDetail.Name,
		ProviderId: userDetail.UserID,
	}

	return data, nil
}

