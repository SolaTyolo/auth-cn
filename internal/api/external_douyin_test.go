package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	douyinUser        string = `{"data":{"error_code":0,"description":"success","user":{"open_id":"douyinTestId","union_id":"union123","nickname":"Douyin Test","avatar":"http://example.com/avatar","city":"Beijing","province":"Beijing","country":"CN","gender":1,"e_account_role":"EAccountM"}}}`
	douyinUserNoEmail string = `{"data":{"error_code":0,"description":"success","user":{"open_id":"douyinTestId","union_id":"union123","nickname":"Douyin Test","avatar":"http://example.com/avatar","city":"Beijing","province":"Beijing","country":"CN","gender":1}}}`
)

func (ts *ExternalTestSuite) TestSignupExternalDouyin() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=douyin", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Douyin.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Douyin.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("douyin", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func DouyinTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/access_token/":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Douyin.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"douyin_token","expires_in":100000}`)
		case "/oauth/userinfo/":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown douyin oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Douyin.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalDouyin_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.Config.External.Douyin.EmailOptional = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := DouyinTestSignupSetup(ts, &tokenCount, &userCount, code, douyinUser)
	defer server.Close()

	u := performAuthorization(ts, "douyin", code, "")

	// Douyin doesn't provide email, so we use empty email with EmailOptional
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "Douyin Test", "douyinTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalDouyinDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	ts.Config.External.Douyin.EmailOptional = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := DouyinTestSignupSetup(ts, &tokenCount, &userCount, code, douyinUser)
	defer server.Close()

	u := performAuthorization(ts, "douyin", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalDouyinDisableSignupSuccessWithProviderId() {
	ts.Config.DisableSignup = true
	ts.Config.External.Douyin.EmailOptional = true

	ts.createUserWithIdentity("douyin", "douyinTestId", "", "Douyin Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := DouyinTestSignupSetup(ts, &tokenCount, &userCount, code, douyinUser)
	defer server.Close()

	u := performAuthorization(ts, "douyin", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "Douyin Test", "douyinTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalDouyinSuccessWhenMatchingToken() {
	ts.Config.External.Douyin.EmailOptional = true
	ts.createUserWithIdentity("douyin", "douyinTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := DouyinTestSignupSetup(ts, &tokenCount, &userCount, code, douyinUser)
	defer server.Close()

	u := performAuthorization(ts, "douyin", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "Douyin Test", "douyinTestId", "http://example.com/avatar")
}

