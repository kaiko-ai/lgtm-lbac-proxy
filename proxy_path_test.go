package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The upstream URL may carry a base path (VictoriaMetrics cluster:
// /select/0/prometheus). The proxy must keep it in front of the request path.
func TestProxyKeepsUpstreamBasePath(t *testing.T) {
	tests := []struct {
		name      string
		basePath  string
		reqPath   string
		wantPath  string
		wantQuery string
	}{
		{"no base path", "", "/api/v1/query?query=up", "/api/v1/query", "query=up"},
		{"base path", "/select/0/prometheus", "/api/v1/query?query=up", "/select/0/prometheus/api/v1/query", "query=up"},
		{"base path with trailing slash", "/select/0/prometheus/", "/api/v1/query?query=up", "/select/0/prometheus/api/v1/query", "query=up"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotQuery string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
			}))
			defer upstream.Close()

			app := &App{}
			proxy := app.createProxy(upstream.URL+tt.basePath, "", &http.Transport{}, "test")
			proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tt.reqPath, nil))

			if gotPath != tt.wantPath {
				t.Errorf("upstream path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotQuery != tt.wantQuery {
				t.Errorf("upstream query = %q, want %q", gotQuery, tt.wantQuery)
			}
		})
	}
}
