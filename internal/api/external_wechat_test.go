package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	wechatUser        string = `{"openid":"wechatTestId","unionid":"union123","nickname":"WeChat Test","headimgurl":"http://example.com/avatar","sex":1,"province":"Beijing","city":"Beijing","country":"CN","privilege":[]}`
	wechatUserNoEmail string = `{"openid":"wechatTestId","unionid":"union123","nickname":"WeChat Test","headimgurl":"http://example.com/avatar","sex":1,"province":"Beijing","city":"Beijing","country":"CN"}`
)

func (ts *ExternalTestSuite) TestSignupExternalWechat() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=wechat", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Wechat.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Wechat.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("wechat", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func WechatTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sns/oauth2/access_token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Wechat.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			// WeChat returns openid in token response
			fmt.Fprint(w, `{"access_token":"wechat_token","expires_in":100000,"openid":"wechatTestId"}`)
		case "/sns/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown wechat oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Wechat.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalWechat_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.Config.External.Wechat.EmailOptional = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, wechatUser)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	// WeChat doesn't provide email by default, so we use empty email with EmailOptional
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "WeChat Test", "wechatTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	ts.Config.External.Wechat.EmailOptional = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, wechatUser)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatDisableSignupSuccessWithProviderId() {
	ts.Config.DisableSignup = true
	ts.Config.External.Wechat.EmailOptional = true

	ts.createUserWithIdentity("wechat", "wechatTestId", "", "WeChat Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, wechatUser)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "WeChat Test", "wechatTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalWechatSuccessWhenMatchingToken() {
	ts.Config.External.Wechat.EmailOptional = true
	ts.createUserWithIdentity("wechat", "wechatTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, wechatUser)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "WeChat Test", "wechatTestId", "http://example.com/avatar")
}

