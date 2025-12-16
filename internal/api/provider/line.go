package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLineAuthBase  = "access.line.me"
	defaultLineTokenBase = "api.line.me"
	defaultLineAPIBase   = "api.line.me"
)

type lineProvider struct {
	*oauth2.Config
	ProfileURL string
}

type lineUser struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	PictureURL  string `json:"pictureUrl"`
	Email       string `json:"email"`
	StatusMessage string `json:"statusMessage"`
}

// NewLineProvider creates a LINE account provider.
func NewLineProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultLineAuthBase)
	tokenHost := chooseHost(ext.URL, defaultLineTokenBase)
	profileURL := chooseHost(ext.URL, defaultLineAPIBase) + "/v2/profile"

	oauthScopes := []string{
		"profile",
		"openid",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &lineProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/v2.1/authorize",
				TokenURL: tokenHost + "/oauth2/v2.1/token",
			},
			Scopes: oauthScopes,
		},
		ProfileURL: profileURL,
	}, nil
}

func (p lineProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p lineProvider) RequiresPKCE() bool {
	return false
}

func (p lineProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u lineUser
	if err := makeRequest(ctx, tok, p.Config, p.ProfileURL, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: true, // LINE emails are typically verified
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:   p.ProfileURL,
		Subject:  u.UserID,
		Name:     u.DisplayName,
		Picture:  u.PictureURL,
		Email:    u.Email,
		EmailVerified: u.Email != "",

		// To be deprecated
		AvatarURL:  u.PictureURL,
		FullName:   u.DisplayName,
		ProviderId: u.UserID,
	}

	return data, nil
}

