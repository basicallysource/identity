package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

// The contract test. api/openapi.yaml is what consumers generate clients
// from, so it must not be allowed to drift from what this package does.
// Two checks hold it:
//
//   - The route table and the spec are the same set. An API route with no
//     description, or a described path with no handler, fails here.
//   - Every response the rest of this package's tests provoke is validated
//     against the spec: status, content type and body schema. newTestServer
//     wraps the handler, so this costs the other tests nothing to opt into
//     and cannot be forgotten.

var (
	specOnce       sync.Once
	decodeHTMLOnce sync.Once
	spec           *openapi3.T
	specErr        error
)

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		spec, specErr = loader.LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
		if specErr == nil {
			specErr = spec.Validate(context.Background())
		}
	})
	if specErr != nil {
		t.Fatalf("api/openapi.yaml: %v", specErr)
	}
	return spec
}

func TestEveryRouteIsInTheContractAndBack(t *testing.T) {
	spec := loadSpec(t)
	server := &Server{}

	described := map[string]bool{}
	for path, item := range spec.Paths.Map() {
		for method := range item.Operations() {
			described[method+" "+path] = true
		}
	}

	routed := map[string]bool{}
	for _, r := range server.routes() {
		if r.Kind != routeAPI {
			continue
		}
		key := r.Method + " " + r.Pattern
		routed[key] = true
		if !described[key] {
			t.Errorf("%s is served but not described in api/openapi.yaml", key)
		}
	}
	for key := range described {
		if !routed[key] {
			t.Errorf("%s is described in api/openapi.yaml but nothing serves it", key)
		}
	}
}

// validating wraps a handler so every request that matches an operation in
// the spec has its response checked against that operation. Requests the
// spec does not describe (the page, static files) pass straight through;
// the route test above is what keeps that set honest.
func validating(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	router, err := legacy.NewRouter(loadSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	// The validator decodes JSON and plain text out of the box; the failed
	// sign-in page is HTML and is checked as a string.
	decodeHTMLOnce.Do(func() {
		openapi3filter.RegisterBodyDecoder("text/html", func(body io.Reader, _ http.Header, _ *openapi3.SchemaRef, _ openapi3filter.EncodingFn) (any, error) {
			raw, err := io.ReadAll(body)
			return string(raw), err
		})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params, err := router.FindRoute(r)
		if err != nil {
			if err == routers.ErrPathNotFound || strings.Contains(err.Error(), "no matching operation") {
				next.ServeHTTP(w, r)
				return
			}
			t.Errorf("%s %s: routing against the spec: %v", r.Method, r.URL.Path, err)
			next.ServeHTTP(w, r)
			return
		}

		// Only the response is validated. Tests deliberately send malformed
		// requests to see them refused, and a refusal is a response the spec
		// must describe, which is the check that matters to a consumer.
		input := &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: params,
			Route:      route,
			Options:    &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		}

		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)

		err = openapi3filter.ValidateResponse(r.Context(), &openapi3filter.ResponseValidationInput{
			RequestValidationInput: input,
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
			Options:                &openapi3filter.Options{IncludeResponseStatus: true},
		})
		if err != nil {
			t.Errorf("%s %s answered %d in a way the spec does not describe: %v\n%s", r.Method, r.URL.Path, rec.Code, err, rec.Body.String())
		}

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	})
}
