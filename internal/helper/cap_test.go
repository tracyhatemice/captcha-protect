package helper

import (
	"strings"
	"testing"
)

func TestGetCapJSEmbedsCapURL(t *testing.T) {
	js := GetCapJS("/cap")
	for _, want := range []string{
		`var CAP_URL = "/cap";`,
		`CAP_URL + "/assets/widget.js"`,
		`CAP_URL + "/assets/cap_wasm_bg.wasm"`,
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
	js := GetCapJS(`/cap"</script><script>alert(1)//`)
	if strings.Contains(js, "</script>") {
		t.Fatal("Cap JS must not contain a literal </script>")
	}
	want := `var CAP_URL = "/cap\"\u003c/script\u003e\u003cscript\u003ealert(1)//";`
	if !strings.Contains(js, want) {
		t.Fatalf("expected JSON-escaped CAP_URL %q in:\n%s", want, js)
	}
}
