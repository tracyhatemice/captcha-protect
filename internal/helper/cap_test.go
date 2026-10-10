package helper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetCapJSEmbedsCapURL(t *testing.T) {
	js := GetCapJS("/cap", "")
	for _, want := range []string{
		`var CAP_URL = "/cap";`,
		`var WIDGET_URL = "/cap/assets/widget.js";`,
		`var WASM_URL = "/cap/assets/cap_wasm_bg.wasm";`,
		`var HASHWX_URL = "/cap/assets/hashwx.wasm";`,
		`script.src = WIDGET_URL;`,
		`window.CAP_CUSTOM_WASM_URL = WASM_URL;`,
		`window.CAP_CUSTOM_HASHWX_URL = HASHWX_URL;`,
		`"cap-response"`,
		`"interaction-only"`,
		`widget.solve()`,
		`customElements.whenDefined("cap-widget")`,
		`[data-callback]`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected Cap JS to contain %q", want)
		}
	}
}

func TestGetCapJSEscapesCapURL(t *testing.T) {
	js := GetCapJS(`/cap"</script><script>alert(1)//`, `"</script>`)
	if strings.Contains(js, "</script>") {
		t.Fatal("Cap JS must not contain a literal </script>")
	}
	want := `var CAP_URL = "/cap\"\u003c/script\u003e\u003cscript\u003ealert(1)//";`
	if !strings.Contains(js, want) {
		t.Fatalf("expected JSON-escaped CAP_URL %q in:\n%s", want, js)
	}
}

func TestGetCapJSSupportsDeferredExecution(t *testing.T) {
	js := GetCapJS("/cap", "")
	for _, want := range []string{
		// data-execution="execute" defers solving to the visitor's click.
		`var autoSolve = box.getAttribute("data-execution") !== "execute";`,
		`if (!autoSolve) {`,
		// a hidden widget has nothing to click, so deferred execution keeps it visible
		`if (hidden && !autoSolve) {`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected Cap JS to contain %q", want)
		}
	}
}

func TestGetCapJSVersionsAssetURLs(t *testing.T) {
	js := GetCapJS("/cap", "37a5d4c1917cf499")
	for _, want := range []string{
		`var WIDGET_URL = "/cap/assets/widget.js?v=37a5d4c1917cf499";`,
		`var WASM_URL = "/cap/assets/cap_wasm_bg.wasm?v=37a5d4c1917cf499";`,
		`var HASHWX_URL = "/cap/assets/hashwx.wasm?v=37a5d4c1917cf499";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected Cap JS to contain %q", want)
		}
	}
}

func TestFetchCapWidgetVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/cap/assets/widget.js" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("cap widget v1\n"))
	}))
	defer server.Close()

	version, err := FetchCapWidgetVersion(t.Context(), server.Client(), server.URL+"/cap/assets/widget.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// printf 'cap widget v1\n' | sha256sum
	if version != "37a5d4c1917cf499" {
		t.Fatalf("version = %q, want %q", version, "37a5d4c1917cf499")
	}
}

func TestFetchCapWidgetVersionRejectsNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer server.Close()

	version, err := FetchCapWidgetVersion(t.Context(), server.Client(), server.URL+"/cap/assets/widget.js")
	if err == nil {
		t.Fatalf("expected an error for a 502, got version %q", version)
	}
}
