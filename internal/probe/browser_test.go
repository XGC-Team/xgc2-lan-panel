package probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserAuthorizationRejectsCrossOriginRebindingAndSimpleRequests(t *testing.T) {
	calls := 0
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	for _, fixture := range []struct {
		host, origin, contentType string
		status                    int
	}{
		{"attacker.example:3400", "", "application/json", 403},
		{"127.0.0.1:3400", "https://attacker.example", "application/json", 403},
		{"127.0.0.1:3400", "null", "application/json", 403},
		{"127.0.0.1:3400", "http://127.0.0.1:3400", "text/plain", 415},
		{"127.0.0.1:3400", "http://127.0.0.1:3400", "application/json", 204},
		{"127.0.0.1:3400", "http://localhost:3401", "application/json", 204},
		{"[::1]:3400", "", "application/json", 204},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://"+fixture.host+"/api/robots/r/apply", strings.NewReader(`{}`))
		request.Header.Set("Origin", fixture.origin)
		request.Header.Set("Content-Type", fixture.contentType)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != fixture.status {
			t.Fatalf("%+v: got %d", fixture, response.Code)
		}
	}
	if calls != 3 {
		t.Fatalf("unauthorized browser call reached credentialed domain: %d", calls)
	}
}
