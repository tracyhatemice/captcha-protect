package captcha_protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSessionVerificationSeparatesClientsSharingIP(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "site"
	config.SecretKey = "secret"
	config.CaptchaProvider = "poj"
	config.VerificationMode = "session"
	config.ProtectRoutes = []string{"/"}

	bc, err := NewCaptchaProtect(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), config, "test-middleware")
	if err != nil {
		t.Fatal(err)
	}
	bc.goodBotLookup = func(context.Context, string, []string) bool { return false }

	get := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
		req.RemoteAddr = "203.0.113.1:1234"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rw := httptest.NewRecorder()
		bc.ServeHTTP(rw, req)
		return rw
	}

	if got := get(nil).Code; got != http.StatusFound {
		t.Fatalf("unverified browser status = %d, want redirect", got)
	}
	form := url.Values{"poj-captcha-response": {"solved"}, "destination": {"/private"}}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.1:1234"
	rw := httptest.NewRecorder()
	bc.ServeHTTP(rw, req)
	if rw.Code != http.StatusFound {
		t.Fatalf("challenge status = %d, want redirect", rw.Code)
	}
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("verification cookie attributes = %+v", cookies)
	}
	if got := get(cookies[0]).Code; got != http.StatusNoContent {
		t.Errorf("verified browser status = %d, want pass", got)
	}
	if got := get(nil).Code; got != http.StatusFound {
		t.Errorf("second browser on same IP status = %d, want challenge", got)
	}
	if got := get(&http.Cookie{Name: cookies[0].Name, Value: "unknown"}).Code; got != http.StatusFound {
		t.Errorf("unknown session status = %d, want challenge", got)
	}
}

func TestInvalidVerificationMode(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "site"
	config.SecretKey = "secret"
	config.ProtectRoutes = []string{"/"}
	config.VerificationMode = "invalid"
	if _, err := NewCaptchaProtect(context.Background(), nil, config, "test"); err == nil {
		t.Fatal("expected invalid verification mode error")
	}
}
