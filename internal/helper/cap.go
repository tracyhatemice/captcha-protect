package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GetCapJS returns the adapter script that mounts a self-hosted Cap widget into the
// challenge template's [data-callback] element. capURL is the Cap base URL as the
// browser sees it, without a trailing slash. A non-empty version is added to the
// widget and both WASM URLs as ?v=, so browsers fetch them again whenever it changes.
func GetCapJS(capURL, version string) string {
	query := ""
	if version != "" {
		query = "?v=" + url.QueryEscape(version)
	}
	return "// Cap adapter for captcha-protect\n(function() {\n" +
		"    var CAP_URL = " + jsString(capURL) + ";\n" +
		"    var WIDGET_URL = " + jsString(capURL+"/assets/widget.js"+query) + ";\n" +
		"    var WASM_URL = " + jsString(capURL+"/assets/cap_wasm_bg.wasm"+query) + ";\n" +
		"    var HASHWX_URL = " + jsString(capURL+"/assets/hashwx.wasm"+query) + ";\n" +
		capJSBody
}

// jsString returns s as a JavaScript string literal.
func jsString(s string) string {
	// json.Marshal escapes quotes and <, >, & so the value cannot break out of the script.
	encoded, _ := json.Marshal(s) // marshaling a string cannot fail
	return string(encoded)
}

// FetchCapWidgetVersion downloads Cap's widget script and returns the first 16 hex
// characters of its SHA-256. The standalone build of tracyhatemice/cap names its WASM
// files by their own hashes inside the widget, so there this changes whenever any of
// the three files does.
func FetchCapWidgetVersion(parent context.Context, httpClient *http.Client, widgetURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, widgetURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Cap widget request: %w", err)
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Cap widget: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch Cap widget, status code: %d", resp.StatusCode)
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, resp.Body); err != nil {
		return "", fmt.Errorf("failed to read Cap widget: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil))[:16], nil
}

const capJSBody = `
    if (!window.CAP_CUSTOM_WASM_URL) {
        window.CAP_CUSTOM_WASM_URL = WASM_URL;
    }
    if (!window.CAP_CUSTOM_HASHWX_URL) {
        window.CAP_CUSTOM_HASHWX_URL = HASHWX_URL;
    }

    function initCap() {
        var box = document.querySelector("[data-callback]");
        var form = document.getElementById("captcha-form");
        if (!box || !form) {
            console.error("Cap: captcha div or form not found");
            return;
        }

        var callback = window[box.getAttribute("data-callback")];
        var siteKey = box.getAttribute("data-sitekey");
        if (typeof callback !== "function" || !siteKey) {
            console.error("Cap: missing callback or site key");
            return;
        }

        var input = form.querySelector('input[name="cap-response"]');
        if (!input) {
            input = document.createElement("input");
            input.type = "hidden";
            input.name = "cap-response";
            form.appendChild(input);
        }

        // Like Turnstile's data-execution: "render" (default) solves as soon as the widget
        // loads, "execute" waits for the visitor to click it.
        var autoSolve = box.getAttribute("data-execution") !== "execute";
        // Cap never needs interaction, so interaction-only means the widget is never shown.
        var hidden = box.getAttribute("data-appearance") === "interaction-only";
        if (hidden && !autoSolve) {
            console.warn('Cap: data-execution="execute" needs a visible widget; ignoring data-appearance="interaction-only"');
            hidden = false;
        }

        var widget = document.createElement("cap-widget");
        widget.setAttribute("data-cap-api-endpoint", CAP_URL + "/" + encodeURIComponent(siteKey) + "/");
        if (hidden) {
            widget.style.display = "none";
        }
        widget.addEventListener("solve", function(e) {
            input.value = e.detail.token;
            callback(e.detail.token);
        });
        widget.addEventListener("error", function() {
            // Let the visitor retry by clicking the widget.
            widget.style.display = "";
        });
        box.appendChild(widget);

        var script = document.createElement("script");
        script.src = WIDGET_URL;
        script.onload = function() {
            if (!autoSolve) {
                // the widget's own checkbox starts the challenge
                return;
            }
            customElements.whenDefined("cap-widget").then(function() {
                return widget.solve();
            }).catch(function(e) {
                console.error("Cap: solve failed", e);
            });
        };
        script.onerror = function() {
            box.textContent = "Unable to load the verification widget. Please try again later.";
            console.error("Cap: failed to load " + script.src);
        };
        document.head.appendChild(script);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initCap);
    } else {
        initCap();
    }
})();`
