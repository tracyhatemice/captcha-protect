package helper

import "encoding/json"

// GetCapJS returns the adapter script that mounts a self-hosted Cap widget into the
// challenge template's [data-callback] element. capURL is the Cap base URL as the
// browser sees it, without a trailing slash.
func GetCapJS(capURL string) string {
	// json.Marshal escapes quotes and <, >, & so the URL cannot break out of the script.
	encoded, _ := json.Marshal(capURL) // marshaling a string cannot fail
	return "// Cap adapter for captcha-protect\n(function() {\n    var CAP_URL = " + string(encoded) + ";\n" + capJSBody
}

const capJSBody = `
    if (!window.CAP_CUSTOM_WASM_URL) {
        window.CAP_CUSTOM_WASM_URL = CAP_URL + "/assets/cap_wasm_bg.wasm";
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

        var widget = document.createElement("cap-widget");
        widget.setAttribute("data-cap-api-endpoint", CAP_URL + "/" + encodeURIComponent(siteKey) + "/");
        // Cap never needs interaction, so interaction-only means the widget is never shown.
        if (box.getAttribute("data-appearance") === "interaction-only") {
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
        script.src = CAP_URL + "/assets/widget.js";
        script.onload = function() {
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
