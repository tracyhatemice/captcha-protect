package captcha_protect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newCapTestConfig(capURL, capVerifyURL string) *Config {
	config := CreateConfig()
	config.SiteKey = "test-site"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "cap"
	config.CapURL = capURL
	config.CapVerifyURL = capVerifyURL
	config.EnableCommonCrawlIPCheck = "false"
	return config
}

func TestCapConfigValidation(t *testing.T) {
	tests := []struct {
		name         string
		capURL       string
		capVerifyURL string
		expectError  string
	}{
		{"missing capURL", "", "http://cap:3000/cap", "capURL is required"},
		{"capURL without leading slash", "cap", "http://cap:3000/cap", "capURL must be a root-relative path or an absolute http(s) URL"},
		{"protocol-relative capURL", "//evil.example/cap", "http://cap:3000/cap", "capURL must be a root-relative path or an absolute http(s) URL"},
		{"non-http capURL", "ftp://example.com/cap", "http://cap:3000/cap", "capURL must be a root-relative path or an absolute http(s) URL"},
		{"capURL with query", "/cap?x=1", "http://cap:3000/cap", "capURL must be a root-relative path or an absolute http(s) URL"},
		{"relative capURL without capVerifyURL", "/cap", "", "capVerifyURL is required when capURL is a relative path"},
		{"relative capVerifyURL", "/cap", "/cap", "capVerifyURL must be an absolute http(s) URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig(tt.capURL, tt.capVerifyURL), "test")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectError)
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Fatalf("expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestCapProviderConfig(t *testing.T) {
	tests := []struct {
		name         string
		capURL       string
		capVerifyURL string
		wantCapURL   string
		wantValidate string
		wantHealth   string
	}{
		{
			name:         "relative capURL with internal verify URL",
			capURL:       "/cap/",
			capVerifyURL: "http://cap:3000/cap/",
			wantCapURL:   "/cap",
			wantValidate: "http://cap:3000/cap/test-site/siteverify",
			wantHealth:   "http://cap:3000/cap/assets/widget.js",
		},
		{
			name:         "absolute capURL defaults verify URL",
			capURL:       "https://example.com/cap",
			capVerifyURL: "",
			wantCapURL:   "https://example.com/cap",
			wantValidate: "https://example.com/cap/test-site/siteverify",
			wantHealth:   "https://example.com/cap/assets/widget.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig(tt.capURL, tt.capVerifyURL), "test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if bc.captchaConfig.js != capJSPath {
				t.Errorf("js = %q, want %q", bc.captchaConfig.js, capJSPath)
			}
			if bc.captchaConfig.key != "cap" {
				t.Errorf("key = %q, want %q", bc.captchaConfig.key, "cap")
			}
			if bc.captchaConfig.validate != tt.wantValidate {
				t.Errorf("validate = %q, want %q", bc.captchaConfig.validate, tt.wantValidate)
			}
			if got := bc.captchaConfig.healthCheckURL(); got != tt.wantHealth {
				t.Errorf("healthCheckURL() = %q, want %q", got, tt.wantHealth)
			}
			if bc.config.CapURL != tt.wantCapURL {
				t.Errorf("config.CapURL = %q, want %q", bc.config.CapURL, tt.wantCapURL)
			}
		})
	}
}

func TestStaticProvidersHealthCheckTheirScript(t *testing.T) {
	for _, provider := range []string{"turnstile", "recaptcha", "hcaptcha"} {
		c := getCaptchaConfig(provider)
		if c.healthCheckURL() != c.js {
			t.Errorf("%s: healthCheckURL() = %q, want js %q", provider, c.healthCheckURL(), c.js)
		}
	}
}

func TestCapHealthCheckTargetsWidgetAsset(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := newCapTestConfig("/cap", server.URL+"/cap")
	config.PeriodSeconds = 3600
	config.FailureThreshold = 1

	bc, err := NewCaptchaProtect(t.Context(), nil, config, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bc.recordHealthCheckFailure() // threshold 1: opens the circuit
	bc.performHealthCheck()

	if got := <-requests; got != "HEAD /cap/assets/widget.js" {
		t.Fatalf("health check request = %q, want %q", got, "HEAD /cap/assets/widget.js")
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if bc.circuitState != circuitClosed {
		t.Fatalf("expected circuit closed after healthy check, got %v", bc.circuitState)
	}
}

func TestServeCapJS(t *testing.T) {
	bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), newCapTestConfig("/cap", "http://cap:3000/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rr := httptest.NewRecorder()
	bc.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, capJSPath, nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}
	if !strings.Contains(rr.Body.String(), `var CAP_URL = "/cap";`) {
		t.Errorf("expected adapter script with CAP_URL, got:\n%s", rr.Body.String())
	}
}

func TestCapJSNotServedForOtherProviders(t *testing.T) {
	config := newCapTestConfig("", "")
	config.CaptchaProvider = "turnstile"
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	})
	bc, err := NewCaptchaProtect(t.Context(), next, config, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bc.goodBotLookup = func(context.Context, string, []string) bool { return false }

	rr := httptest.NewRecorder()
	bc.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, capJSPath, nil))

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want request passed to next handler (418)", rr.Code)
	}
}

func TestCapChallengePageUsesAdapter(t *testing.T) {
	bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), newCapTestConfig("/cap", "http://cap:3000/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rr := httptest.NewRecorder()
	bc.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/challenge?destination=%2F", nil))

	body := rr.Body.String()
	for _, want := range []string{`src="/captcha-protect-cap.js"`, `class="cap"`, `data-sitekey="test-site"`} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %q:\n%s", want, body)
		}
	}
}

type capSiteverifyCall struct {
	method      string
	path        string
	contentType string
	body        map[string]string
}

func newCapSiteverifyServer(t *testing.T, status int, response string) (*httptest.Server, chan capSiteverifyCall) {
	t.Helper()
	calls := make(chan capSiteverifyCall, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls <- capSiteverifyCall{method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"), body: body}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	return server, calls
}

func postCapChallenge(bc *CaptchaProtect, form url.Values) (*httptest.ResponseRecorder, int) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	status := bc.verifyChallengePage(rr, req, "1.2.3.4")
	return rr, status
}

func TestCapVerifySendsJSONToSiteverify(t *testing.T) {
	server, calls := newCapSiteverifyServer(t, http.StatusOK, `{"success":true}`)
	bc, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig("/cap", server.URL+"/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rr, status := postCapChallenge(bc, url.Values{"cap-response": {"test-site:abc:def"}, "destination": {"/protected"}})

	if status != http.StatusFound {
		t.Fatalf("status = %d, want 302", status)
	}
	if loc := rr.Header().Get("Location"); loc != "/protected" {
		t.Errorf("Location = %q, want /protected", loc)
	}
	call := <-calls
	if call.method != http.MethodPost || call.path != "/cap/test-site/siteverify" {
		t.Errorf("siteverify request = %s %s, want POST /cap/test-site/siteverify", call.method, call.path)
	}
	if call.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", call.contentType)
	}
	if call.body["secret"] != "test-secret" || call.body["response"] != "test-site:abc:def" {
		t.Errorf("siteverify body = %v, want secret/response", call.body)
	}
	if _, ok := bc.verifiedCache.Get("1.2.3.4"); !ok {
		t.Error("expected client IP to be marked verified")
	}
}

func TestCapVerifyRejectsUnknownToken(t *testing.T) {
	server, _ := newCapSiteverifyServer(t, http.StatusNotFound, `{"success":false,"error":"Token not found"}`)
	bc, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig("/cap", server.URL+"/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, status := postCapChallenge(bc, url.Values{"cap-response": {"test-site:bogus:token"}})

	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	if _, ok := bc.verifiedCache.Get("1.2.3.4"); ok {
		t.Error("client IP must not be marked verified")
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if bc.healthCheckFailureCount != 0 {
		t.Errorf("a 404 token rejection must not count as a health failure, got %d", bc.healthCheckFailureCount)
	}
}

func TestCapVerifyServerErrorCountsAsHealthFailure(t *testing.T) {
	server, _ := newCapSiteverifyServer(t, http.StatusInternalServerError, `{"success":false}`)
	bc, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig("/cap", server.URL+"/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, status := postCapChallenge(bc, url.Values{"cap-response": {"test-site:abc:def"}})

	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if bc.healthCheckFailureCount != 1 {
		t.Errorf("healthCheckFailureCount = %d, want 1", bc.healthCheckFailureCount)
	}
}

func TestCapVerifyRequiresCapResponse(t *testing.T) {
	bc, err := NewCaptchaProtect(t.Context(), nil, newCapTestConfig("/cap", "http://cap:3000/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, status := postCapChallenge(bc, url.Values{"cf-turnstile-response": {"x"}})

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}
