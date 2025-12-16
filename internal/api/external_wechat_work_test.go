package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	wechatWorkUser        string = `{"UserId":"wechatWorkTestId","DeviceId":"device123","OpenId":"openid123","user_ticket":"ticket123"}`
	wechatWorkUserDetail  string = `{"userid":"wechatWorkTestId","name":"WeChat Work Test","mobile":"13800138000","email":"wechatwork@example.com","avatar":"http://example.com/avatar","alias":"test","telephone":"010-12345678","gender":"1","status":1}`
	wechatWorkUserNoEmail string = `{"userid":"wechatWorkTestId","name":"WeChat Work Test","mobile":"13800138000","avatar":"http://example.com/avatar","alias":"test","telephone":"010-12345678","gender":"1","status":1}`
)

func (ts *ExternalTestSuite) TestSignupExternalWechatWork() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=wechat_work", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.WechatWork.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.WechatWork.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("wechat_work", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func WechatWorkTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, userInfo string, userDetail string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.WechatWork.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"wechatwork_token","expires_in":100000}`)
		case "/cgi-bin/user/getuserinfo":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, userInfo)
		case "/cgi-bin/user/get":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, userDetail)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown wechat_work oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.WechatWork.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalWechatWork_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatWorkTestSignupSetup(ts, &tokenCount, &userCount, code, wechatWorkUser, wechatWorkUserDetail)
	defer server.Close()

	u := performAuthorization(ts, "wechat_work", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "wechatwork@example.com", "WeChat Work Test", "wechatWorkTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatWorkDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatWorkTestSignupSetup(ts, &tokenCount, &userCount, code, wechatWorkUser, wechatWorkUserDetail)
	defer server.Close()

	u := performAuthorization(ts, "wechat_work", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "wechatwork@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatWorkDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("wechatWorkTestId", "wechatwork@example.com", "WeChat Work Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatWorkTestSignupSetup(ts, &tokenCount, &userCount, code, wechatWorkUser, wechatWorkUserDetail)
	defer server.Close()

	u := performAuthorization(ts, "wechat_work", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "wechatwork@example.com", "WeChat Work Test", "wechatWorkTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalWechatWorkSuccessWhenMatchingToken() {
	ts.createUser("wechatWorkTestId", "wechatwork@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := WechatWorkTestSignupSetup(ts, &tokenCount, &userCount, code, wechatWorkUser, wechatWorkUserDetail)
	defer server.Close()

	u := performAuthorization(ts, "wechat_work", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "wechatwork@example.com", "WeChat Work Test", "wechatWorkTestId", "http://example.com/avatar")
}

