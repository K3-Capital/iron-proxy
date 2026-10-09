package secrets

// Tests for the named-query replacement mode (replace.match_query_params).
//
// The configs in this file are decoded from YAML exactly the way the
// transform factory does (yaml.Node -> secretsConfig -> newFromConfig) so the
// tests also exercise configuration validation and the wire format operators
// will write.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	nqToken  = "proxy-key"
	nqSecret = "s3cret-value"
)

const nqDefaultRules = "    rules:\n      - host: api.example.com\n"

// nqReplace builds a replace-block body. The defaults select only the
// "apikey" query parameter and disable header scanning with the documented
// impossible-match regexp. extra lines are appended as additional fields.
func nqReplace(extra ...string) string {
	body := "      proxy_value: " + nqToken + "\n" +
		"      match_query_params: [apikey]\n" +
		"      match_headers: [\"/a^/\"]\n"
	for _, line := range extra {
		body += line + "\n"
	}
	return body
}

func nqConfig(replaceBody string) string {
	return nqConfigWithRules(replaceBody, nqDefaultRules)
}

func nqConfigWithRules(replaceBody, rules string) string {
	return "secrets:\n" +
		"  - source:\n      type: env\n      var: MY_KEY\n" +
		"    replace:\n" + replaceBody +
		rules
}

// buildNamedQuerySecrets decodes cfg through the production path and builds a
// Secrets transform backed by a test registry. secrets is the content of the
// fake env-secret store; an empty map makes MY_KEY unavailable.
func buildNamedQuerySecrets(cfg string, secrets map[string]string) (*Secrets, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(cfg), &doc); err != nil {
		return nil, err
	}
	var c secretsConfig
	if err := doc.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	reg := sourceBuilderRegistry{"env": &fakeBuilder{secrets: secrets}}
	return newFromConfig(c, reg)
}

// mustNamedQuerySecrets builds a transform or fails the test.
func mustNamedQuerySecrets(t *testing.T, cfg string, secrets map[string]string) *Secrets {
	t.Helper()
	s, err := buildNamedQuerySecrets(cfg, secrets)
	require.NoError(t, err)
	return s
}

func nqRequest(method, host, path, rawQuery string) *http.Request {
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.URL.RawQuery = rawQuery
	req.Host = host
	return req
}

// runNamedQuery runs the transform and returns the action plus the drained
// audit annotations.
func runNamedQuery(t *testing.T, s *Secrets, req *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	tctx := &transform.TransformContext{}
	res, err := s.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res.Action, tctx.DrainAnnotations()
}

func annotationJSON(t *testing.T, ann map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(ann)
	require.NoError(t, err)
	return string(raw)
}

// swappedLocations returns every location recorded in the "swapped"
// annotation, for example "query:apikey" or "header:Authorization".
func swappedLocations(t *testing.T, ann map[string]any) []string {
	t.Helper()
	var decoded struct {
		Swapped []struct {
			Secret    string   `json:"secret"`
			Locations []string `json:"locations"`
		} `json:"swapped"`
	}
	require.NoError(t, json.Unmarshal([]byte(annotationJSON(t, ann)), &decoded))
	var locs []string
	for _, sw := range decoded.Swapped {
		locs = append(locs, sw.Locations...)
	}
	return locs
}

// --- Byte-preservation and swap semantics (require: false) ---

func TestReplace_MatchQueryParams_Swap(t *testing.T) {
	cases := []struct {
		name         string
		replaceBody  string
		secret       string
		rawQuery     string
		wantQuery    string
		swap         bool   // expect a swapped annotation
		wantLocation string // expected location; defaults to query:apikey
	}{
		{
			name:      "selected value replaced, unrelated preserved",
			rawQuery:  "b=2&apikey=proxy-key&a=1",
			wantQuery: "b=2&apikey=s3cret-value&a=1",
			swap:      true,
		},
		{
			name:      "token in unselected parameter untouched",
			rawQuery:  "other=proxy-key",
			wantQuery: "other=proxy-key",
		},
		{
			name:      "duplicate keys replaced independently",
			rawQuery:  "apikey=proxy-key&x=1&apikey=proxy-key&apikey=other",
			wantQuery: "apikey=s3cret-value&x=1&apikey=s3cret-value&apikey=other",
			swap:      true,
		},
		{
			name:      "empty and bare values preserved",
			rawQuery:  "apikey=&apikey=proxy-key&bare&trail=&apikey",
			wantQuery: "apikey=&apikey=s3cret-value&bare&trail=&apikey",
			swap:      true,
		},
		{
			name:      "empty segments preserved",
			rawQuery:  "&&apikey=proxy-key&&x=&&",
			wantQuery: "&&apikey=s3cret-value&&x=&&",
			swap:      true,
		},
		{
			name:      "all occurrences replaced",
			rawQuery:  "apikey=a-proxy-key-b-proxy-key-c",
			wantQuery: "apikey=a-s3cret-value-b-s3cret-value-c",
			swap:      true,
		},
		{
			name:      "percent-encoded token replaced",
			rawQuery:  "apikey=proxy%2Dkey",
			wantQuery: "apikey=s3cret-value",
			swap:      true,
		},
		{
			name:      "double-encoded token untouched",
			rawQuery:  "apikey=proxy%252Dkey",
			wantQuery: "apikey=proxy%252Dkey",
		},
		{
			name:         "encoded parameter name selected",
			replaceBody:  "      proxy_value: proxy-key\n      match_query_params: [\"my key\"]\n      match_headers: [\"/a^/\"]\n",
			rawQuery:     "my%20key=proxy-key",
			wantQuery:    "my%20key=s3cret-value",
			swap:         true,
			wantLocation: "query:my key",
		},
		{
			name:      "unrelated raw bytes unchanged",
			rawQuery:  "a=%20%2B&apikey=proxy-key&b=x%3Dy&c=proxy-key-2",
			wantQuery: "a=%20%2B&apikey=s3cret-value&b=x%3Dy&c=proxy-key-2",
			swap:      true,
		},
		{
			name:      "parameter names are case-sensitive",
			rawQuery:  "APIKEY=proxy-key&apikey=proxy-key",
			wantQuery: "APIKEY=proxy-key&apikey=s3cret-value",
			swap:      true,
		},
		{
			name:      "plus sign decodes to space and re-encodes",
			rawQuery:  "apikey=+proxy-key+",
			wantQuery: "apikey=+s3cret-value+",
			swap:      true,
		},
		{
			name:      "secret needing URL escaping",
			secret:    "real secret/=x",
			rawQuery:  "apikey=proxy-key&x=1",
			wantQuery: "apikey=real+secret%2F%3Dx&x=1",
			swap:      true,
		},
		{
			name:      "encoded semicolon in value",
			rawQuery:  "apikey=proxy-key%3Btail",
			wantQuery: "apikey=s3cret-value%3Btail",
			swap:      true,
		},
		{
			name:      "absent parameter is not injected",
			rawQuery:  "x=1",
			wantQuery: "x=1",
		},
		{
			name:      "empty query untouched",
			rawQuery:  "",
			wantQuery: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replaceBody := tc.replaceBody
			if replaceBody == "" {
				replaceBody = nqReplace()
			}
			secret := tc.secret
			if secret == "" {
				secret = nqSecret
			}
			s := mustNamedQuerySecrets(t, nqConfig(replaceBody), map[string]string{"MY_KEY": secret})

			req := nqRequest("GET", "api.example.com", "/v1/x", tc.rawQuery)
			action, ann := runNamedQuery(t, s, req)

			require.Equal(t, transform.ActionContinue, action)
			require.Equal(t, tc.wantQuery, req.URL.RawQuery)

			if tc.swap {
				wantLocation := tc.wantLocation
				if wantLocation == "" {
					wantLocation = "query:apikey"
				}
				require.Contains(t, swappedLocations(t, ann), wantLocation)
			} else {
				require.NotContains(t, annotationJSON(t, ann), "swapped")
			}
		})
	}
}

// --- Rejections in named mode ---

func TestReplace_MatchQueryParams_Rejects(t *testing.T) {
	cases := []struct {
		name        string
		replaceBody string
		secretAvail bool
		host        string
		path        string
		rawQuery    string
		headers     map[string]string
		wantAction  transform.TransformAction
		wantReason  string
		wantQuery   string
		wantHeaders map[string]string
		wantSwapped bool
	}{
		{
			name:        "require rejects when selected placement missing",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			rawQuery:    "other=proxy-key",
			wantAction:  transform.ActionReject,
			wantReason:  "query_token_missing",
			wantQuery:   "other=proxy-key",
		},
		{
			name:        "require rejects when token only in a parameter name",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			rawQuery:    "proxy-key=x&apikey=clean",
			wantAction:  transform.ActionReject,
			wantReason:  "query_token_missing",
			wantQuery:   "proxy-key=x&apikey=clean",
		},
		{
			name:        "require rejects when token only in a header, before any mutation",
			replaceBody: "      proxy_value: proxy-key\n      match_query_params: [apikey]\n      match_headers: []\n      require: true\n",
			secretAvail: true,
			rawQuery:    "x=1",
			headers:     map[string]string{"Authorization": "Bearer proxy-key"},
			wantAction:  transform.ActionReject,
			wantReason:  "query_token_missing",
			wantQuery:   "x=1",
			wantHeaders: map[string]string{"Authorization": "Bearer proxy-key"},
		},
		{
			name:        "require rejects when token only in the path",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			path:        "/v1/proxy-key/x",
			rawQuery:    "x=1",
			wantAction:  transform.ActionReject,
			wantReason:  "query_token_missing",
			wantQuery:   "x=1",
		},
		{
			name:        "require rejects when token only in an unselected parameter",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			rawQuery:    "token=proxy-key",
			wantAction:  transform.ActionReject,
			wantReason:  "query_token_missing",
			wantQuery:   "token=proxy-key",
		},
		{
			name:        "malformed selected segment rejects without require",
			replaceBody: nqReplace(),
			secretAvail: true,
			rawQuery:    "apikey=%zz",
			wantAction:  transform.ActionReject,
			wantReason:  "malformed_query",
			wantQuery:   "apikey=%zz",
		},
		{
			name:        "malformed unselected segment rejects without require",
			replaceBody: nqReplace(),
			secretAvail: true,
			rawQuery:    "other=%zz&apikey=proxy-key",
			wantAction:  transform.ActionReject,
			wantReason:  "malformed_query",
			wantQuery:   "other=%zz&apikey=proxy-key",
		},
		{
			name:        "raw semicolon in selected segment rejects",
			replaceBody: nqReplace(),
			secretAvail: true,
			rawQuery:    "apikey=proxy-key;z=1",
			wantAction:  transform.ActionReject,
			wantReason:  "malformed_query",
			wantQuery:   "apikey=proxy-key;z=1",
		},
		{
			name:        "raw semicolon in unselected segment rejects",
			replaceBody: nqReplace(),
			secretAvail: true,
			rawQuery:    "u=a;b&apikey=proxy-key",
			wantAction:  transform.ActionReject,
			wantReason:  "malformed_query",
			wantQuery:   "u=a;b&apikey=proxy-key",
		},
		{
			name:        "required secret unavailable rejects even with placement",
			replaceBody: nqReplace("      require: true"),
			secretAvail: false,
			rawQuery:    "apikey=proxy-key",
			wantAction:  transform.ActionReject,
			wantReason:  "secret_unavailable",
			wantQuery:   "apikey=proxy-key",
		},
		{
			name:        "require satisfied by selected placement swaps",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			rawQuery:    "apikey=proxy-key&x=1",
			wantAction:  transform.ActionContinue,
			wantQuery:   "apikey=s3cret-value&x=1",
			wantSwapped: true,
		},
		{
			name:        "require satisfied even with token also in unselected parameter",
			replaceBody: nqReplace("      require: true"),
			secretAvail: true,
			rawQuery:    "other=proxy-key&apikey=proxy-key",
			wantAction:  transform.ActionContinue,
			wantQuery:   "other=proxy-key&apikey=s3cret-value",
			wantSwapped: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets := map[string]string{}
			if tc.secretAvail {
				secrets["MY_KEY"] = nqSecret
			}
			s := mustNamedQuerySecrets(t, nqConfig(tc.replaceBody), secrets)

			path := tc.path
			if path == "" {
				path = "/v1/x"
			}
			req := nqRequest("GET", "api.example.com", path, tc.rawQuery)
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			originalPath := req.URL.Path

			action, ann := runNamedQuery(t, s, req)

			require.Equal(t, tc.wantAction, action)
			require.Equal(t, tc.wantQuery, req.URL.RawQuery, "query must be rejected before mutation or mutated as expected")
			require.Equal(t, originalPath, req.URL.Path)
			for name, value := range tc.wantHeaders {
				require.Equal(t, value, req.Header.Get(name), "header %s must be untouched", name)
			}

			if tc.wantAction == transform.ActionReject {
				require.Equal(t, "MY_KEY", ann["rejected"])
				require.Equal(t, tc.wantReason, ann["reject_reason"])
			}
			if tc.wantSwapped {
				require.Contains(t, swappedLocations(t, ann), "query:apikey")
			}
		})
	}
}

// --- Rule misses must not parse, reject, or mutate ---

func TestReplace_MatchQueryParams_RuleMisses(t *testing.T) {
	malformed := "apikey=%zz" // would reject if the entry's rules matched

	cases := []struct {
		name   string
		rules  string
		method string
		host   string
		path   string
	}{
		{
			name:   "host miss",
			rules:  nqDefaultRules,
			method: "GET",
			host:   "other.example.com",
			path:   "/v1/x",
		},
		{
			name:   "method miss",
			rules:  "    rules:\n      - host: api.example.com\n        methods: [POST]\n",
			method: "GET",
			host:   "api.example.com",
			path:   "/v1/x",
		},
		{
			name:   "path miss",
			rules:  "    rules:\n      - host: api.example.com\n        paths: [\"/v1/allowed\"]\n",
			method: "GET",
			host:   "api.example.com",
			path:   "/v1/x",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustNamedQuerySecrets(t, nqConfigWithRules(nqReplace("      require: true"), tc.rules),
				map[string]string{"MY_KEY": nqSecret})

			req := nqRequest(tc.method, tc.host, tc.path, malformed)
			action, ann := runNamedQuery(t, s, req)

			require.Equal(t, transform.ActionContinue, action)
			require.Equal(t, malformed, req.URL.RawQuery, "rule miss must not parse or mutate")
			require.NotContains(t, annotationJSON(t, ann), "rejected")
		})
	}
}

// --- Header scanning independence ---

func TestReplace_MatchQueryParams_HeaderScanAllStillApplies(t *testing.T) {
	// match_headers omitted means scan-all; the named selector only changes
	// which query parameters are scanned, not header behavior.
	body := "      proxy_value: proxy-key\n" +
		"      match_query_params: [apikey]\n" +
		"      require: true\n"
	s := mustNamedQuerySecrets(t, nqConfig(body), map[string]string{"MY_KEY": nqSecret})

	req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key&other=proxy-key")
	req.Header.Set("Authorization", "Bearer proxy-key")
	req.Header.Set("X-Custom", "proxy-key")

	action, ann := runNamedQuery(t, s, req)

	require.Equal(t, transform.ActionContinue, action)
	require.Equal(t, "apikey=s3cret-value&other=proxy-key", req.URL.RawQuery)
	require.Equal(t, "Bearer s3cret-value", req.Header.Get("Authorization"))
	require.Equal(t, "s3cret-value", req.Header.Get("X-Custom"))
	locs := swappedLocations(t, ann)
	require.Contains(t, locs, "header:Authorization")
	require.Contains(t, locs, "header:X-Custom")
	require.Contains(t, locs, "query:apikey")
	// The unselected parameter still holds the token: only selected query
	// parameters are rewritten.
	require.NotContains(t, locs, "query:other")
}

func TestReplace_MatchQueryParams_QueryOnlyEntry(t *testing.T) {
	// The documented query-only combination: the impossible-match header
	// regexp, named selector, no body or path scanning.
	s := mustNamedQuerySecrets(t, nqConfig(nqReplace("      require: true")),
		map[string]string{"MY_KEY": nqSecret})

	req := nqRequest("POST", "api.example.com", "/v1/proxy-key/here", "apikey=proxy-key&x=1")
	// Adversarial header names selected by a client; none may match /a^/.
	req.Header["A"] = []string{"proxy-key"}
	req.Header["a"] = []string{"proxy-key"}
	req.Header["A^"] = []string{"proxy-key"}
	req.Header["X-Aa"] = []string{"proxy-key"}
	req.Header["Accept"] = []string{"proxy-key"}

	body := "token proxy-key in body"
	req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
	req.ContentLength = int64(len(body))

	action, ann := runNamedQuery(t, s, req)

	require.Equal(t, transform.ActionContinue, action)
	require.Equal(t, "apikey=s3cret-value&x=1", req.URL.RawQuery)

	for name, want := range map[string]string{
		"A": "proxy-key", "a": "proxy-key", "A^": "proxy-key", "X-Aa": "proxy-key", "Accept": "proxy-key",
	} {
		require.Equal(t, []string{want}, req.Header[name], "header %q must be untouched", name)
	}
	require.Equal(t, "/v1/proxy-key/here", req.URL.Path, "path must be untouched without match_path")

	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(got), "body must be untouched without match_body")

	locs := swappedLocations(t, ann)
	require.Contains(t, locs, "query:apikey")
	for _, loc := range locs {
		require.False(t, strings.HasPrefix(loc, "header:"), "no header may match /a^/: %s", loc)
	}
}

// --- Zero-header matcher proof ---

// TestReplace_MatchQueryParams_ZeroHeaderMatcher proves the documented
// combination match_headers: ["/a^/"] disables header scanning for EVERY
// possible header name, not just unlikely ones.
//
// The compiled expression is (?i)a^: a case-insensitive "a" immediately
// followed by the beginning-of-text anchor. A match would need the text
// position after the consumed "a" (at least index 1) to also be index 0,
// which is impossible for any string. The test demonstrates this by
// exhausting the whole byte space for short inputs and by running a corpus
// of adversarial longer names.
func TestReplace_MatchQueryParams_ZeroHeaderMatcher(t *testing.T) {
	matchers, err := parseHeaderMatchers([]string{"/a^/"}, "secrets[0]")
	require.NoError(t, err)
	require.Len(t, matchers, 1)
	require.NotNil(t, matchers[0].re, "/a^/ must compile to the regexp matcher")
	re := matchers[0].re

	// Every string of length 0, 1 and 2 over the full byte range.
	if re.MatchString("") {
		t.Fatal(`/a^/ must not match the empty string`)
	}
	for i := 0; i < 256; i++ {
		b1 := string([]byte{byte(i)})
		if re.MatchString(b1) {
			t.Fatalf("/a^/ must not match single byte %d", i)
		}
		for j := 0; j < 256; j++ {
			name := b1 + string([]byte{byte(j)})
			if re.MatchString(name) {
				t.Fatalf("/a^/ must not match bytes %d,%d", i, j)
			}
		}
	}

	// Every string of length 3 over an alphabet containing 'a', the anchor
	// character and other header-name characters.
	alphabet := []byte("aA^- \n\r_x")
	for _, c1 := range alphabet {
		for _, c2 := range alphabet {
			for _, c3 := range alphabet {
				name := string([]byte{c1, c2, c3})
				if re.MatchString(name) {
					t.Fatalf("/a^/ must not match short string %q", name)
				}
			}
		}
	}

	// Adversarial longer names.
	corpus := []string{
		"a", "A", "aa", "aA", "Aa", "aaa",
		"a^", "^a", "a^a", "^a^", "^",
		"a\n", "\na", "a\t", "\ta", "a ", " a",
		strings.Repeat("a", 4096),
		"a" + strings.Repeat("x", 4096),
		strings.Repeat("x", 4096) + "a",
		"X-" + strings.Repeat("a", 100) + "-Key",
		"Authorization", "X-Api-Key", "Accept", "A^", "a-^-a",
		"héader-a", "🙂a", "a🙂",
		"a\x00", "\x00a", "a\x7f",
	}
	for _, name := range corpus {
		if re.MatchString(name) {
			t.Fatalf("/a^/ must not match %q", name)
		}
		// Canonicalization is just another transformation of the name; the
		// canonical form must not match either.
		if re.MatchString(http.CanonicalHeaderKey(name)) {
			t.Fatalf("/a^/ must not match canonicalized %q", name)
		}
	}
}

// --- Legacy behavior preserved when the selector is absent ---

func TestReplace_MatchQueryParams_LegacyUnchanged(t *testing.T) {
	t.Run("legacy whole-query scan still applies", func(t *testing.T) {
		body := "      proxy_value: proxy-key\n      match_query: true\n"
		s := mustNamedQuerySecrets(t, nqConfig(body), map[string]string{"MY_KEY": nqSecret})

		req := nqRequest("GET", "api.example.com", "/v1/x", "z=1&token=proxy-key")
		action, _ := runNamedQuery(t, s, req)

		require.Equal(t, transform.ActionContinue, action)
		require.NotContains(t, req.URL.RawQuery, nqToken)
		require.Contains(t, req.URL.RawQuery, "s3cret-value")
		require.Contains(t, req.URL.RawQuery, "z=1")
	})

	t.Run("explicit null means no named selector", func(t *testing.T) {
		body := "      proxy_value: proxy-key\n      match_query: true\n      match_query_params: null\n"
		s := mustNamedQuerySecrets(t, nqConfig(body), map[string]string{"MY_KEY": nqSecret})

		req := nqRequest("GET", "api.example.com", "/v1/x", "z=1&token=proxy-key")
		action, _ := runNamedQuery(t, s, req)

		require.Equal(t, transform.ActionContinue, action)
		require.Contains(t, req.URL.RawQuery, "s3cret-value")
	})

	t.Run("null selector without match_query leaves the query alone", func(t *testing.T) {
		body := "      proxy_value: proxy-key\n      match_query_params: null\n"
		s := mustNamedQuerySecrets(t, nqConfig(body), map[string]string{"MY_KEY": nqSecret})

		req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key")
		action, _ := runNamedQuery(t, s, req)

		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "apikey=proxy-key", req.URL.RawQuery)
	})

	t.Run("deprecated top-level fields ignore the unknown key", func(t *testing.T) {
		cfg := "secrets:\n" +
			"  - source:\n      type: env\n      var: MY_KEY\n" +
			"    proxy_value: proxy-key\n" +
			"    match_headers: [\"X-Api-Key\"]\n" +
			"    match_query_params: [apikey]\n" +
			"    rules:\n      - host: api.example.com\n"
		s := mustNamedQuerySecrets(t, cfg, map[string]string{"MY_KEY": nqSecret})

		req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key")
		req.Header.Set("X-Api-Key", "proxy-key")
		action, _ := runNamedQuery(t, s, req)

		require.Equal(t, transform.ActionContinue, action)
		require.Equal(t, "apikey=proxy-key", req.URL.RawQuery, "top-level fields must not enable named query scanning")
		require.Equal(t, "s3cret-value", req.Header.Get("X-Api-Key"))
	})
}

// --- Configuration validation ---

func TestReplace_MatchQueryParams_ConfigValidation(t *testing.T) {
	base := func(lines ...string) string {
		body := "      proxy_value: proxy-key\n"
		for _, line := range lines {
			body += line + "\n"
		}
		return nqConfig(body)
	}

	cases := []struct {
		name   string
		cfg    string
		errMsg string // empty means the config must be accepted
	}{
		{
			name: "omitted selector is valid",
			cfg:  base(),
		},
		{
			name: "null selector is valid",
			cfg:  base("      match_query_params: null"),
		},
		{
			name: "empty value selector is valid",
			cfg:  base("      match_query_params:"),
		},
		{
			name:   "explicit empty list is rejected",
			cfg:    base("      match_query_params: []"),
			errMsg: "match_query_params must not be empty",
		},
		{
			name:   "empty parameter name is rejected",
			cfg:    base("      match_query_params: [\"\"]"),
			errMsg: "must not contain an empty parameter name",
		},
		{
			name:   "duplicate parameter name is rejected",
			cfg:    base("      match_query_params: [apikey, apikey]"),
			errMsg: "duplicate parameter name",
		},
		{
			name: "case-distinct names are not duplicates",
			cfg:  base("      match_query_params: [apikey, APIKEY]"),
		},
		{
			name:   "scalar instead of list is rejected",
			cfg:    base("      match_query_params: \"apikey\""),
			errMsg: "must be a list of parameter names",
		},
		{
			name:   "integer entry is rejected",
			cfg:    base("      match_query_params: [1]"),
			errMsg: "entries must be strings",
		},
		{
			name:   "boolean entry is rejected",
			cfg:    base("      match_query_params: [true]"),
			errMsg: "entries must be strings",
		},
		{
			name:   "null entry is rejected",
			cfg:    base("      match_query_params: [null]"),
			errMsg: "entries must be strings",
		},
		{
			name:   "nested list entry is rejected",
			cfg:    base("      match_query_params: [[a]]"),
			errMsg: "entries must be strings",
		},
		{
			name:   "map instead of list is rejected",
			cfg:    base("      match_query_params: {a: b}"),
			errMsg: "must be a list of parameter names",
		},
		{
			name:   "match_query true together with selector is rejected",
			cfg:    base("      match_query: true", "      match_query_params: [apikey]"),
			errMsg: "cannot be combined with match_query_params",
		},
		{
			name: "match_query false together with selector is valid",
			cfg:  base("      match_query: false", "      match_query_params: [apikey]"),
		},
		{
			name: "selector with require and scan-all headers is valid",
			cfg:  nqConfig("      proxy_value: proxy-key\n      match_query_params: [apikey]\n      require: true\n"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildNamedQuerySecrets(tc.cfg, map[string]string{"MY_KEY": nqSecret})
			if tc.errMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// --- Annotations must not carry raw request values ---

func TestReplace_MatchQueryParams_AnnotationsValueFree(t *testing.T) {
	t.Run("swap annotations contain no token or secret", func(t *testing.T) {
		s := mustNamedQuerySecrets(t, nqConfig(nqReplace()), map[string]string{"MY_KEY": nqSecret})
		req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key&x=1")
		action, ann := runNamedQuery(t, s, req)
		require.Equal(t, transform.ActionContinue, action)

		raw := annotationJSON(t, ann)
		require.NotContains(t, raw, nqToken)
		require.NotContains(t, raw, nqSecret)
		require.NotContains(t, raw, "apikey=proxy-key")
	})

	t.Run("malformed-query rejection contains no raw query bytes", func(t *testing.T) {
		s := mustNamedQuerySecrets(t, nqConfig(nqReplace()), map[string]string{"MY_KEY": nqSecret})
		req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=%zz")
		action, ann := runNamedQuery(t, s, req)
		require.Equal(t, transform.ActionReject, action)

		raw := annotationJSON(t, ann)
		require.NotContains(t, raw, "%zz")
		require.NotContains(t, raw, "apikey=%zz")
		require.NotContains(t, raw, nqToken)
	})

	t.Run("missing-placement rejection contains no raw query bytes", func(t *testing.T) {
		s := mustNamedQuerySecrets(t, nqConfig(nqReplace("      require: true")),
			map[string]string{"MY_KEY": nqSecret})
		req := nqRequest("GET", "api.example.com", "/v1/x", "x=1")
		action, ann := runNamedQuery(t, s, req)
		require.Equal(t, transform.ActionReject, action)

		raw := annotationJSON(t, ann)
		require.NotContains(t, raw, "x=1")
		require.NotContains(t, raw, nqToken)
	})
}

// --- Concurrent use and selector immutability ---

func TestReplace_MatchQueryParams_ConcurrentSafety(t *testing.T) {
	s := mustNamedQuerySecrets(t, nqConfig(nqReplace("      require: true")),
		map[string]string{"MY_KEY": nqSecret})

	var wg sync.WaitGroup
	errs := make(chan string, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tctx := &transform.TransformContext{}
			if i%2 == 0 {
				req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key&x=1")
				res, err := s.TransformRequest(context.Background(), tctx, req)
				if err != nil {
					errs <- fmt.Sprintf("request %d: unexpected error: %v", i, err)
					return
				}
				if res.Action != transform.ActionContinue {
					errs <- fmt.Sprintf("request %d: action = %v, want continue", i, res.Action)
				}
				if req.URL.RawQuery != "apikey=s3cret-value&x=1" {
					errs <- fmt.Sprintf("request %d: query = %q", i, req.URL.RawQuery)
				}
				return
			}
			req := nqRequest("GET", "api.example.com", "/v1/x", "x=1")
			res, err := s.TransformRequest(context.Background(), tctx, req)
			if err != nil {
				errs <- fmt.Sprintf("request %d: unexpected error: %v", i, err)
				return
			}
			if res.Action != transform.ActionReject {
				errs <- fmt.Sprintf("request %d: action = %v, want reject", i, res.Action)
			}
			if req.URL.RawQuery != "x=1" {
				errs <- fmt.Sprintf("request %d: query = %q, want unchanged", i, req.URL.RawQuery)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}

	// The compiled selector must remain intact after concurrent use.
	req := nqRequest("GET", "api.example.com", "/v1/x", "apikey=proxy-key&other=proxy-key")
	action, ann := runNamedQuery(t, s, req)
	require.Equal(t, transform.ActionContinue, action)
	require.Equal(t, "apikey=s3cret-value&other=proxy-key", req.URL.RawQuery)
	require.Contains(t, swappedLocations(t, ann), "query:apikey")
}
