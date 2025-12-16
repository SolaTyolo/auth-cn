package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	lineUser        string = `{"userId":"lineTestId","displayName":"Line Test","pictureUrl":"http://example.com/avatar","email":"line@example.com","statusMessage":"Hello"}`
	lineUserNoEmail string = `{"userId":"lineTestId","displayName":"Line Test","pictureUrl":"http://example.com/avatar","statusMessage":"Hello"}`
)

func (ts *ExternalTestSuite) TestSignupExternalLine() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=line", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Line.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Line.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("line", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func LineTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v2.1/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Line.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"line_token","expires_in":100000}`)
		case "/v2/profile":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown line oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Line.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalLine_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "lineTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "line@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("lineTestId", "line@example.com", "Line Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "lineTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineSuccessWhenMatchingToken() {
	ts.createUser("lineTestId", "line@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "lineTestId", "http://example.com/avatar")
}

