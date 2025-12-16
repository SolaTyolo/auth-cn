package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWechatAuthBase  = "open.weixin.qq.com"
	defaultWechatTokenBase = "api.weixin.qq.com"
	defaultWechatAPIBase   = "api.weixin.qq.com"
)

type wechatProvider struct {
	*oauth2.Config
	UserInfoURL string
}

type wechatUser struct {
	OpenID     string `json:"openid"`
	UnionID    string `json:"unionid"`
	Nickname   string `json:"nickname"`
	HeadImgURL string `json:"headimgurl"`
	Sex        int    `json:"sex"`
	Province   string `json:"province"`
	City       string `json:"city"`
	Country    string `json:"country"`
	Privilege  []string `json:"privilege"`
}

// NewWechatProvider creates a WeChat (regular WeChat) account provider.
func NewWechatProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultWechatAuthBase)
	tokenHost := chooseHost(ext.URL, defaultWechatTokenBase)
	userInfoURL := chooseHost(ext.URL, defaultWechatAPIBase) + "/sns/userinfo"

	oauthScopes := []string{
		"snsapi_login",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &wechatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/connect/qrconnect",
				TokenURL: tokenHost + "/sns/oauth2/access_token",
			},
			Scopes: oauthScopes,
		},
		UserInfoURL: userInfoURL,
	}, nil
}

func (p wechatProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p wechatProvider) RequiresPKCE() bool {
	return false
}

func (p wechatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// WeChat OAuth flow: after getting access token, call userinfo endpoint
	// Note: WeChat requires openid and access_token as query parameters
	// The openid is returned in the token response and stored in tok.Extra("openid")
	var u wechatUser
	openid := ""
	if tok.Extra("openid") != nil {
		if id, ok := tok.Extra("openid").(string); ok {
			openid = id
		}
	}
	
	// If openid is not in token extra, we need to get it from the token response
	// For now, we'll construct the URL with access_token only and let the API handle it
	// In practice, you may need to parse the token response to get openid
	userInfoURL := p.UserInfoURL + "?access_token=" + tok.AccessToken
	if openid != "" {
		userInfoURL += "&openid=" + openid
	}
	
	if err := makeRequest(ctx, tok, p.Config, userInfoURL, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	// WeChat doesn't provide email in user info endpoint by default
	// You may need to request additional scopes or use a different endpoint

	data.Metadata = &Claims{
		Issuer:   p.UserInfoURL,
		Subject:  u.OpenID,
		Name:     u.Nickname,
		Picture:  u.HeadImgURL,
		Locale:   u.Country,
		CustomClaims: map[string]interface{}{
			"unionid":  u.UnionID,
			"province": u.Province,
			"city":     u.City,
			"country":  u.Country,
			"sex":      u.Sex,
			"privilege": u.Privilege,
		},

		// To be deprecated
		AvatarURL:  u.HeadImgURL,
		FullName:   u.Nickname,
		ProviderId: u.OpenID,
	}

	return data, nil
}
