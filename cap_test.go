package captcha_protect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
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
	var mu sync.Mutex
	var heads []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware also GETs the widget in the background to version its URL.
		if r.Method == http.MethodHead {
			mu.Lock()
			heads = append(heads, r.URL.Path)
			mu.Unlock()
		}
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

	mu.Lock()
	got := heads
	mu.Unlock()
	if len(got) != 1 || got[0] != "/cap/assets/widget.js" {
		t.Fatalf("health check HEAD requests = %q, want [/cap/assets/widget.js]", got)
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
		if r.Method == http.MethodGet && r.URL.Path == "/cap/assets/widget.js" {
			// the background widget version fetch, not a siteverify call
			http.NotFound(w, r)
			return
		}
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

// fakeCapAssets serves a Cap widget script whose status and body a test can change.
type fakeCapAssets struct {
	mu     sync.Mutex
	status int
	body   string
	gets   int
}

func (f *fakeCapAssets) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

// widgetGets returns how many times the widget has been downloaded.
func (f *fakeCapAssets) widgetGets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets
}

func (f *fakeCapAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/cap/assets/widget.js" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	w.WriteHeader(f.status)
	_, _ = w.Write([]byte(f.body))
}

func capAdapter(t *testing.T, bc *CaptchaProtect) string {
	t.Helper()
	rr := httptest.NewRecorder()
	bc.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, capJSPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("adapter status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}

// waitForCapAdapter waits for the startup fetch to put want into the adapter.
func waitForCapAdapter(t *testing.T, bc *CaptchaProtect, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(capAdapter(t, bc), want) {
		if time.Now().After(deadline) {
			t.Fatalf("adapter never contained %q:\n%s", want, capAdapter(t, bc))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Hashes are the first 16 hex characters of sha256sum over the fixture bodies.
const (
	capWidgetV1     = "cap widget v1\n"
	capWidgetV1Hash = "37a5d4c1917cf499"
	capWidgetV2     = "cap widget v2\n"
	capWidgetV2Hash = "33de2f23e1772c2a"
)

func TestCapAdapterVersionsAssetsByWidgetHash(t *testing.T) {
	assets := &fakeCapAssets{status: http.StatusOK, body: capWidgetV1}
	server := httptest.NewServer(assets)
	defer server.Close()

	bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), newCapTestConfig("/cap", server.URL+"/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waitForCapAdapter(t, bc, `var WIDGET_URL = "/cap/assets/widget.js?v=`+capWidgetV1Hash+`";`)
	js := capAdapter(t, bc)
	for _, want := range []string{
		`var WASM_URL = "/cap/assets/cap_wasm_bg.wasm?v=` + capWidgetV1Hash + `";`,
		`var HASHWX_URL = "/cap/assets/hashwx.wasm?v=` + capWidgetV1Hash + `";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected the WASM URLs to carry the widget hash, missing %q:\n%s", want, js)
		}
	}

	assets.set(http.StatusOK, capWidgetV2)
	bc.refreshCapWidgetVersion(t.Context())

	js = capAdapter(t, bc)
	for _, want := range []string{
		`var WIDGET_URL = "/cap/assets/widget.js?v=` + capWidgetV2Hash + `";`,
		`var WASM_URL = "/cap/assets/cap_wasm_bg.wasm?v=` + capWidgetV2Hash + `";`,
		`var HASHWX_URL = "/cap/assets/hashwx.wasm?v=` + capWidgetV2Hash + `";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("after the widget changed, expected adapter to contain %q:\n%s", want, js)
		}
	}
}

func TestCapAdapterKeepsVersionWhenWidgetFetchFails(t *testing.T) {
	tests := []struct {
		name string
		fail func(assets *fakeCapAssets, server *httptest.Server)
	}{
		{"error status", func(assets *fakeCapAssets, _ *httptest.Server) { assets.set(http.StatusBadGateway, "bad gateway") }},
		{"unreachable", func(_ *fakeCapAssets, server *httptest.Server) { server.Close() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := &fakeCapAssets{status: http.StatusOK, body: capWidgetV1}
			server := httptest.NewServer(assets)
			defer server.Close()

			bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), newCapTestConfig("/cap", server.URL+"/cap"), "test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := `var WIDGET_URL = "/cap/assets/widget.js?v=` + capWidgetV1Hash + `";`
			waitForCapAdapter(t, bc, want)

			tt.fail(assets, server)
			bc.refreshCapWidgetVersion(t.Context())

			if js := capAdapter(t, bc); !strings.Contains(js, want) {
				t.Fatalf("expected the last good version to be kept, got:\n%s", js)
			}
		})
	}
}

func TestCapAdapterUnversionedUntilWidgetFetched(t *testing.T) {
	assets := &fakeCapAssets{status: http.StatusServiceUnavailable, body: "starting"}
	server := httptest.NewServer(assets)
	defer server.Close()

	bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), newCapTestConfig("/cap", server.URL+"/cap"), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bc.refreshCapWidgetVersion(t.Context())

	js := capAdapter(t, bc)
	for _, want := range []string{
		`var WIDGET_URL = "/cap/assets/widget.js";`,
		`var WASM_URL = "/cap/assets/cap_wasm_bg.wasm";`,
		`var HASHWX_URL = "/cap/assets/hashwx.wasm";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected adapter to contain %q:\n%s", want, js)
		}
	}
}

func TestCapWidgetVersionLoopFetchesOnceWithoutPeriod(t *testing.T) {
	for _, period := range []time.Duration{0, -time.Second} {
		t.Run(period.String(), func(t *testing.T) {
			assets := &fakeCapAssets{status: http.StatusServiceUnavailable, body: "starting"}
			server := httptest.NewServer(assets)
			defer server.Close()

			// A canceled context stops the loop New starts, so only the one below fetches.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			bc, err := NewCaptchaProtect(ctx, http.NotFoundHandler(), newCapTestConfig("/cap", server.URL+"/cap"), "test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			done := make(chan struct{})
			go func() {
				bc.capWidgetVersionLoop(t.Context(), period)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("expected the loop to return after one fetch")
			}

			if got := assets.widgetGets(); got != 1 {
				t.Fatalf("widget fetched %d times, want 1", got)
			}
			assets.set(http.StatusOK, capWidgetV1)
			if js := capAdapter(t, bc); !strings.Contains(js, `var WIDGET_URL = "/cap/assets/widget.js";`) {
				t.Fatalf("expected the adapter to stay unversioned after a failed fetch, got:\n%s", js)
			}
		})
	}
}

func TestCapWidgetRehashedEveryPeriodSeconds(t *testing.T) {
	assets := &fakeCapAssets{status: http.StatusServiceUnavailable, body: "starting"}
	server := httptest.NewServer(assets)
	defer server.Close()

	config := newCapTestConfig("/cap", server.URL+"/cap")
	config.PeriodSeconds = 1
	config.FailureThreshold = 0 // versioning does not depend on the circuit breaker

	bc, err := NewCaptchaProtect(t.Context(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Let the fetch at load fail before Cap comes up.
	deadline := time.Now().Add(5 * time.Second)
	for assets.widgetGets() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the widget was never fetched at load")
		}
		time.Sleep(10 * time.Millisecond)
	}
	assets.set(http.StatusOK, capWidgetV1)
	waitForCapAdapter(t, bc, `var WIDGET_URL = "/cap/assets/widget.js?v=`+capWidgetV1Hash+`";`)

	assets.set(http.StatusOK, capWidgetV2)
	waitForCapAdapter(t, bc, `var WIDGET_URL = "/cap/assets/widget.js?v=`+capWidgetV2Hash+`";`)
}
