package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultDouyinAuthBase  = "open.douyin.com"
	defaultDouyinTokenBase = "open.douyin.com"
	defaultDouyinAPIBase   = "open.douyin.com"
)

type douyinProvider struct {
	*oauth2.Config
	UserInfoURL string
}

type douyinUser struct {
	OpenID      string `json:"open_id"`
	UnionID     string `json:"union_id"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	City        string `json:"city"`
	Province    string `json:"province"`
	Country     string `json:"country"`
	Gender      int    `json:"gender"`
	EAccountRole string `json:"e_account_role"`
}

type douyinUserInfoResponse struct {
	Data struct {
		ErrorCode   int       `json:"error_code"`
		Description string    `json:"description"`
		User        douyinUser `json:"user"`
	} `json:"data"`
}

// NewDouyinProvider creates a Douyin (TikTok) account provider.
func NewDouyinProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultDouyinAuthBase)
	tokenHost := chooseHost(ext.URL, defaultDouyinTokenBase)
	userInfoURL := chooseHost(ext.URL, defaultDouyinAPIBase) + "/oauth/userinfo/"

	oauthScopes := []string{
		"user_info",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &douyinProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/platform/oauth/connect/",
				TokenURL: tokenHost + "/oauth/access_token/",
			},
			Scopes: oauthScopes,
		},
		UserInfoURL: userInfoURL,
	}, nil
}

func (p douyinProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p douyinProvider) RequiresPKCE() bool {
	return false
}

func (p douyinProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var resp douyinUserInfoResponse
	if err := makeRequest(ctx, tok, p.Config, p.UserInfoURL, &resp); err != nil {
		return nil, err
	}

	if resp.Data.ErrorCode != 0 {
		return nil, httpError(400, resp.Data.Description)
	}

	u := resp.Data.User

	data := &UserProvidedData{}

	// Douyin doesn't provide email in user info endpoint
	// You may need to request additional scopes or use a different endpoint

	data.Metadata = &Claims{
		Issuer:   p.UserInfoURL,
		Subject:  u.OpenID,
		Name:     u.Nickname,
		Picture:  u.Avatar,
		Locale:   u.Country,
		CustomClaims: map[string]interface{}{
			"union_id":      u.UnionID,
			"city":          u.City,
			"province":      u.Province,
			"country":       u.Country,
			"gender":        u.Gender,
			"e_account_role": u.EAccountRole,
		},

		// To be deprecated
		AvatarURL:  u.Avatar,
		FullName:   u.Nickname,
		ProviderId: u.OpenID,
	}

	return data, nil
}

