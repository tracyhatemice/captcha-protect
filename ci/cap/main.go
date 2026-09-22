// Command cap runs the self-hosted Cap end-to-end test: Traefik + captcha-protect + Cap + a real browser.
// Run it from the ci/ directory: go run ./cap
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	composeFile  = "docker-compose.cap.yml"
	dynamicDir   = "tmp/cap"
	siteIP       = "203.0.113.10"
	app2IP       = "203.0.113.11"
	app3IP       = "203.0.113.14"
	bogusTokenIP = "203.0.113.12"
	breakerIP    = "203.0.113.13"
)

var (
	baseURL  = "http://localhost:" + envOr("CAP_E2E_PORT", "8880")
	adminKey = envOr("CAP_ADMIN_KEY", "captcha-protect-ci-admin-key")
)

// The cap router matches /cap and /cap/..., not PathPrefix(`/cap`): a bare prefix also matches
// /captcha-protect-cap.js and /captcha-protect-poj.js, which the middleware must serve.
const routingConfig = `http:
  routers:
    cap:
      entryPoints: [http]
      rule: "Path(` + "`/cap`" + `) || PathPrefix(` + "`/cap/`" + `)"
      service: cap
  services:
    cap:
      loadBalancer:
        servers:
          - url: "http://cap:3000"
`

const protectedConfig = `http:
  routers:
    cap:
      entryPoints: [http]
      rule: "Path(` + "`/cap`" + `) || PathPrefix(` + "`/cap/`" + `)"
      service: cap
    site:
      entryPoints: [http]
      rule: "PathPrefix(` + "`/`" + `)"
      service: nginx
      middlewares: [captcha-cap]
    app2:
      entryPoints: [http]
      rule: "PathPrefix(` + "`/app2`" + `)"
      service: nginx2
      middlewares: [captcha-cap-hidden]
    app3:
      entryPoints: [http]
      rule: "PathPrefix(` + "`/app3`" + `)"
      service: nginx2
      middlewares: [captcha-cap-click]
  services:
    cap:
      loadBalancer:
        servers:
          - url: "http://cap:3000"
    nginx:
      loadBalancer:
        servers:
          - url: "http://nginx:80"
    nginx2:
      loadBalancer:
        servers:
          - url: "http://nginx2:80"
  middlewares:
    captcha-cap:
      plugin:
        captcha-protect:
          captchaProvider: cap
          siteKey: "{{SITE_KEY}}"
          secretKey: "{{SECRET_KEY}}"
          capURL: /cap
          capVerifyURL: http://cap:3000/cap
          window: 120
          ipForwardedHeader: X-Forwarded-For
          logLevel: DEBUG
          protectRoutes: ["/"]
          goodBots: []
          enableCommonCrawlIPCheck: "false"
          periodSeconds: 2
          failureThreshold: 2
    captcha-cap-hidden:
      plugin:
        captcha-protect:
          captchaProvider: cap
          siteKey: "{{SITE_KEY}}"
          secretKey: "{{SECRET_KEY}}"
          capURL: /cap
          capVerifyURL: http://cap:3000/cap
          window: 120
          ipForwardedHeader: X-Forwarded-For
          logLevel: DEBUG
          protectRoutes: ["/app2"]
          goodBots: []
          enableCommonCrawlIPCheck: "false"
          challengeURL: /app2/challenge
          challengeTmpl: /etc/traefik/templates/interaction-only.tmpl.html
    captcha-cap-click:
      plugin:
        captcha-protect:
          captchaProvider: cap
          siteKey: "{{SITE_KEY}}"
          secretKey: "{{SECRET_KEY}}"
          capURL: /cap
          capVerifyURL: http://cap:3000/cap
          window: 120
          ipForwardedHeader: X-Forwarded-For
          logLevel: DEBUG
          protectRoutes: ["/app3"]
          goodBots: []
          enableCommonCrawlIPCheck: "false"
          challengeURL: /app3/challenge
          challengeTmpl: /etc/traefik/templates/click-to-verify.tmpl.html
`

func main() {
	compose("--profile", "browser", "down", "-v", "--remove-orphans")
	if err := os.MkdirAll(dynamicDir, 0o755); err != nil {
		fatal("create dynamic config dir", "err", err)
	}
	writeDynamicConfig(routingConfig)

	fmt.Println("Bringing cap/traefik/nginx online (building cap from", envOr("CAP_BUILD_CONTEXT", "github main"), ")")
	compose("--profile", "browser", "build", "cap", "browser")
	compose("up", "-d", "valkey", "cap", "nginx", "nginx2", "traefik")
	waitForStatus(baseURL+"/cap/", http.StatusOK)
	waitForStatus(baseURL+"/cap/assets/widget.js", http.StatusOK)

	siteKey, secretKey := createSiteKey()
	fmt.Println("Created cap site key", siteKey)
	writeDynamicConfig(strings.NewReplacer("{{SITE_KEY}}", siteKey, "{{SECRET_KEY}}", secretKey).Replace(protectedConfig))
	waitForRedirect(siteIP, baseURL+"/", "/challenge?destination=%2F")

	fmt.Println("Checking challenge wiring over HTTP...")
	assertHTTPChallenge(siteKey)
	assertTraefikPluginLogsClean()

	fmt.Println("Solving challenges in a real browser...")
	compose("--profile", "browser", "run", "--rm", "browser", "visible")
	compose("--profile", "browser", "run", "--rm", "browser", "hidden")
	compose("--profile", "browser", "run", "--rm", "browser", "click")

	fmt.Println("Checking circuit-breaker fallback to proof-of-javascript...")
	compose("stop", "cap")
	waitForBodyContains(breakerIP, baseURL+"/challenge?destination=%2F", "/captcha-protect-poj.js")
	assertTraefikPluginLogsClean()

	if os.Getenv("CAP_E2E_KEEP") == "" {
		compose("--profile", "browser", "down", "-v", "--remove-orphans")
	}
	fmt.Println("✓ Cap end-to-end test passed")
}

func assertHTTPChallenge(siteKey string) {
	_, body := request(siteIP, http.MethodGet, baseURL+"/challenge?destination=%2F", nil)
	for _, want := range []string{`src="/captcha-protect-cap.js"`, `class="cap"`, fmt.Sprintf(`data-sitekey="%s"`, siteKey)} {
		if !strings.Contains(body, want) {
			fatal("challenge page is missing expected markup", "want", want, "body", body)
		}
	}

	resp, js := request(siteIP, http.MethodGet, baseURL+"/captcha-protect-cap.js", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/javascript" || !strings.Contains(js, `var CAP_URL = "/cap";`) {
		fatal("adapter script not served", "status", resp.StatusCode, "contentType", resp.Header.Get("Content-Type"))
	}

	resp, _ = request(siteIP, http.MethodGet, baseURL+"/cap/assets/widget.js", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		fatal("cap widget asset must be reachable without a challenge", "status", resp.StatusCode, "location", resp.Header.Get("Location"))
	}

	form := url.Values{"cap-response": {siteKey + ":bogus:token"}, "destination": {"/"}}
	resp, _ = request(bogusTokenIP, http.MethodPost, baseURL+"/challenge", form)
	if resp.StatusCode != http.StatusForbidden {
		fatal("bogus cap token must be rejected", "status", resp.StatusCode)
	}

	waitForRedirect(app2IP, baseURL+"/app2/", "/app2/challenge?destination=%2Fapp2%2F")

	waitForRedirect(app3IP, baseURL+"/app3/", "/app3/challenge?destination=%2Fapp3%2F")
	_, clickPage := request(app3IP, http.MethodGet, baseURL+"/app3/challenge?destination=%2Fapp3%2F", nil)
	if !strings.Contains(clickPage, `data-execution="execute"`) {
		fatal("click-to-verify challenge page is missing data-execution", "body", clickPage)
	}
}

func createSiteKey() (string, string) {
	var login struct {
		Success      bool   `json:"success"`
		SessionToken string `json:"session_token"`
		HashedToken  string `json:"hashed_token"`
	}
	postJSON(baseURL+"/cap/auth/login", "", map[string]string{"admin_key": adminKey}, &login)
	if !login.Success {
		fatal("cap admin login failed")
	}

	session, err := json.Marshal(map[string]string{"token": login.SessionToken, "hash": login.HashedToken})
	if err != nil {
		fatal("encode session", "err", err)
	}
	var key struct {
		SiteKey   string `json:"siteKey"`
		SecretKey string `json:"secretKey"`
	}
	postJSON(baseURL+"/cap/server/keys", "Bearer "+base64.StdEncoding.EncodeToString(session), map[string]string{"name": "captcha-protect-e2e"}, &key)
	if key.SiteKey == "" || key.SecretKey == "" {
		fatal("cap did not return a site key")
	}
	return key.SiteKey, key.SecretKey
}

func postJSON(target, authorization string, payload any, out any) {
	body, err := json.Marshal(payload)
	if err != nil {
		fatal("encode request", "url", target, "err", err)
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		fatal("build request", "url", target, "err", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "192.0.2.50")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fatal("request failed", "url", target, "err", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		fatal("decode response", "url", target, "status", resp.StatusCode, "err", err)
	}
}

// request sends a request with a spoofed client IP and never follows redirects.
func request(ip, method, target string, form url.Values) (*http.Response, string) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		fatal("build request", "url", target, "err", err)
	}
	req.Header.Set("X-Forwarded-For", ip)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		fatal("request failed", "url", target, "err", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("read body", "url", target, "err", err)
	}
	return resp, string(data)
}

func waitForStatus(target string, status int) {
	waitFor(fmt.Sprintf("%s to return %d", target, status), func() bool {
		resp, err := http.Get(target) // #nosec G107 -- e2e test only calls fixed localhost URLs.
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == status
	})
}

func waitForRedirect(ip, target, location string) {
	waitFor(fmt.Sprintf("%s to redirect to %s", target, location), func() bool {
		resp, _ := request(ip, http.MethodGet, target, nil)
		return resp.StatusCode == http.StatusFound && resp.Header.Get("Location") == location
	})
}

func waitForBodyContains(ip, target, want string) {
	waitFor(fmt.Sprintf("%s to contain %q", target, want), func() bool {
		_, body := request(ip, http.MethodGet, target, nil)
		return strings.Contains(body, want)
	})
}

func waitFor(what string, ok func() bool) {
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		fmt.Println("waiting for", what)
		time.Sleep(2 * time.Second)
	}
	fatal("timed out waiting", "for", what)
}

func writeDynamicConfig(content string) {
	tmp := filepath.Join(dynamicDir, "dynamic.yml.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil { // #nosec G306 -- read by the Traefik container.
		fatal("write dynamic config", "err", err)
	}
	if err := os.Rename(tmp, filepath.Join(dynamicDir, "dynamic.yml")); err != nil {
		fatal("install dynamic config", "err", err)
	}
}

func assertTraefikPluginLogsClean() {
	output := composeOutput("logs", "--no-color", "traefik")
	for _, failure := range []string{
		"Plugins are disabled",
		"failed to create Yaegi interpreter",
		"failed to import plugin code",
		"failed to eval New",
		"cannot use type",
		"cannot define new methods",
		"capURL is required",
		"capURL must be",
		"capVerifyURL is required",
		"capVerifyURL must be",
	} {
		if strings.Contains(output, failure) {
			fatal("Traefik plugin failure detected", "failure", failure, "logs", output)
		}
	}
}

func compose(args ...string) {
	cmd := exec.Command("docker", append([]string{"compose", "-f", composeFile}, args...)...) // #nosec G204 -- fixed docker compose commands.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("docker compose failed", "args", args, "err", err)
	}
}

func composeOutput(args ...string) string {
	cmd := exec.Command("docker", append([]string{"compose", "-f", composeFile}, args...)...) // #nosec G204 -- fixed docker compose commands.
	output, err := cmd.CombinedOutput()
	if err != nil {
		fatal("docker compose failed", "args", args, "err", err, "output", string(output))
	}
	return string(output)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
