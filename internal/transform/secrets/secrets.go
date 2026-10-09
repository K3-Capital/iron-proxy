// Package secrets implements a transform that swaps proxy tokens for real
// secrets on outbound requests, scoped to allowed hosts.
package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/headers"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("secrets", factory)
}

// secretsConfig is the YAML config structure.
type secretsConfig struct {
	Secrets []secretEntry `yaml:"secrets"`
}

type secretEntry struct {
	Source  yaml.Node              `yaml:"source"`
	Rules   []hostmatch.RuleConfig `yaml:"rules"`
	Inject  *injectConfig          `yaml:"inject,omitempty"`
	Replace *replaceConfig         `yaml:"replace,omitempty"`

	// Deprecated top-level fields for backwards compatibility.
	// Users should migrate to the replace block.
	ProxyValue   string   `yaml:"proxy_value,omitempty"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	Require      bool     `yaml:"require,omitempty"`
}

type replaceConfig struct {
	ProxyValue   string   `yaml:"proxy_value"`
	MatchHeaders []string `yaml:"match_headers,omitempty"`
	MatchBody    bool     `yaml:"match_body,omitempty"`
	MatchPath    bool     `yaml:"match_path,omitempty"`
	MatchQuery   bool     `yaml:"match_query,omitempty"`
	// MatchQueryParams selects exact, already-decoded, case-sensitive query
	// parameter names to scan. Non-nil switches query scanning to the named
	// mode; nil (omitted or null) keeps the legacy whole-query behavior
	// controlled by MatchQuery.
	MatchQueryParams matchQueryParams `yaml:"match_query_params,omitempty"`
	Require          bool             `yaml:"require,omitempty"`
}

// matchQueryParams is the replace.match_query_params configuration type. It
// requires every entry to be a string scalar: yaml.v3 otherwise coerces
// scalars like `[1]` or `[true]` into element strings, which would silently
// turn a mistyped entry into a parameter name.
type matchQueryParams []string

// UnmarshalYAML implements yaml.Unmarshaler. Null values never reach it:
// yaml.v3 decodes null into the zero value, so an omitted or null field
// stays nil (legacy mode) while `[]` yields a non-nil empty list that
// validation rejects.
func (m *matchQueryParams) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("match_query_params must be a list of parameter names (line %d)", node.Line)
	}
	names := make(matchQueryParams, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode || item.ShortTag() != "!!str" {
			return fmt.Errorf("match_query_params entries must be strings (line %d)", item.Line)
		}
		names = append(names, item.Value)
	}
	*m = names
	return nil
}

type injectConfig struct {
	Header     string `yaml:"header,omitempty"`
	QueryParam string `yaml:"query_param,omitempty"`
	Formatter  string `yaml:"formatter,omitempty"`
	// Require rejects the request when the secret is unavailable. When
	// false (default), an unavailable secret is skipped silently.
	Require bool `yaml:"require,omitempty"`
}

// resolvedSecret is a secret ready for use after config parsing and source resolution.
type resolvedSecret struct {
	source secretSource
	mode   string // "replace" or "inject"
	rules  []hostmatch.Rule

	// replace mode fields
	proxyValue       string
	matchHeaders     []headerMatcher // empty = all headers
	matchBody        bool
	matchPath        bool
	matchQuery       bool
	matchQueryParams []string // non-nil = named-query selector; exact decoded names
	require          bool

	// inject mode fields
	injectHeader     string
	injectQueryParam string
	formatter        *template.Template // nil = identity (raw value)
}

// headerMatcher selects request headers to scan. Exactly one of name or re is set.
type headerMatcher struct {
	name     string         // canonical header name; "" if regex
	wireName string         // header name with the user's original casing; "" if regex
	re       *regexp.Regexp // nil if literal name match
}

// parseHeaderMatchers compiles match_headers entries. Patterns delimited by
// "/.../" are compiled as case-insensitive regular expressions matched against
// canonical header names; all other entries are literal header names. Literal
// names are matched case-insensitively (via canonicalization) but the user's
// original casing is preserved when writing the header back over the wire.
func parseHeaderMatchers(patterns []string, ctx string) ([]headerMatcher, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	matchers := make([]headerMatcher, 0, len(patterns))
	for _, p := range patterns {
		if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid match_headers regex %q: %w", ctx, p, err)
			}
			matchers = append(matchers, headerMatcher{re: re})
			continue
		}
		matchers = append(matchers, headerMatcher{name: http.CanonicalHeaderKey(p), wireName: p})
	}
	return matchers, nil
}

// formatterData is the template context for inject formatters.
type formatterData struct {
	Value string
}

var formatterFuncs = template.FuncMap{
	"base64": func(parts ...string) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, "")))
	},
}

// Secrets is the transform that swaps proxy tokens for real secrets.
type Secrets struct {
	secrets []resolvedSecret
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c secretsConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing secrets config: %w", err)
	}
	return newFromConfig(c, defaultRegistry(logger))
}

// defaultRegistry returns the standard set of secret source builders. It is
// used by both the secrets transform's factory and by BuildSource so other
// transforms can compose the same sources.
func defaultRegistry(logger *slog.Logger) sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env":               newEnvBuilder(logger),
		"file":              newFileBuilder(logger),
		"control_plane":     newControlPlaneBuilder(logger),
		"aws_sm":            newAWSSMBuilder(logger),
		"aws_ssm":           newAWSSSMBuilder(logger),
		"vault_kv":          newVaultKVBuilder(logger),
		"1password":         newOPBuilder(logger),
		"1password_connect": newOPConnectBuilder(logger),
	}
}

// BuildSource constructs a secret Source from a yaml node shaped like a
// top-level "source:" block (e.g. {type: env, var: FOO}). It is intended for
// other transforms that want to load their inputs from any registered
// secrets backend (1Password, AWS SM, etc.).
func BuildSource(node yaml.Node, logger *slog.Logger) (Source, error) {
	return resolveSource(defaultRegistry(logger), node)
}

// jsonKeyHint peeks at the optional json_key field, common to every source
// type. When set, the source's value is parsed as a JSON object and the
// single top-level string field at that key is extracted.
type jsonKeyHint struct {
	JSONKey string `yaml:"json_key"`
}

// resolveSource dispatches a source config through the registry and applies
// the optional json_key extraction, which is available to every source type.
func resolveSource(registry sourceBuilderRegistry, node yaml.Node) (secretSource, error) {
	var hint sourceTypeHint
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing source type: %w", err)
	}
	if hint.Type == "" {
		return nil, fmt.Errorf("source.type is required")
	}
	builder, ok := registry[hint.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported source type %q", hint.Type)
	}
	src, err := builder.Build(node)
	if err != nil {
		return nil, err
	}
	var jk jsonKeyHint
	if err := node.Decode(&jk); err != nil {
		return nil, fmt.Errorf("parsing json_key: %w", err)
	}
	if jk.JSONKey != "" {
		src = &jsonKeySource{inner: src, key: jk.JSONKey}
	}
	return src, nil
}

// newFromConfig creates a Secrets transform from a parsed config.
func newFromConfig(cfg secretsConfig, registry sourceBuilderRegistry) (*Secrets, error) {
	resolved := make([]resolvedSecret, 0, len(cfg.Secrets))

	for i, entry := range cfg.Secrets {
		// Normalize legacy top-level fields into a replace block.
		replace, inject, err := normalizeEntry(i, &entry)
		if err != nil {
			return nil, err
		}

		source, err := resolveSource(registry, entry.Source)
		if err != nil {
			return nil, fmt.Errorf("secrets[%d]: %w", i, err)
		}

		rules, err := hostmatch.CompileRules(entry.Rules, fmt.Sprintf("secrets[%d]", i))
		if err != nil {
			return nil, err
		}

		if inject != nil {
			sec := resolvedSecret{
				source:           source,
				mode:             "inject",
				rules:            rules,
				require:          inject.Require,
				injectHeader:     inject.Header,
				injectQueryParam: inject.QueryParam,
			}
			if inject.Formatter != "" {
				tmpl, err := template.New(fmt.Sprintf("secrets[%d]", i)).Funcs(formatterFuncs).Parse(inject.Formatter)
				if err != nil {
					return nil, fmt.Errorf("secrets[%d]: parsing formatter template: %w", i, err)
				}
				sec.formatter = tmpl
			}
			resolved = append(resolved, sec)
		} else {
			matchers, err := parseHeaderMatchers(replace.MatchHeaders, fmt.Sprintf("secrets[%d]", i))
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, resolvedSecret{
				source:           source,
				mode:             "replace",
				proxyValue:       replace.ProxyValue,
				matchHeaders:     matchers,
				matchBody:        replace.MatchBody,
				matchPath:        replace.MatchPath,
				matchQuery:       replace.MatchQuery,
				matchQueryParams: replace.MatchQueryParams,
				require:          replace.Require,
				rules:            rules,
			})
		}
	}

	return &Secrets{secrets: resolved}, nil
}

// normalizeEntry validates the entry and returns either a replaceConfig or injectConfig.
// It handles legacy top-level fields by normalizing them into a replaceConfig.
func normalizeEntry(i int, entry *secretEntry) (*replaceConfig, *injectConfig, error) {
	hasLegacy := entry.ProxyValue != "" || len(entry.MatchHeaders) > 0 || entry.MatchBody || entry.Require
	hasReplace := entry.Replace != nil
	hasInject := entry.Inject != nil

	// Count how many modes are specified.
	modeCount := 0
	if hasLegacy {
		modeCount++
	}
	if hasReplace {
		modeCount++
	}
	if hasInject {
		modeCount++
	}

	if modeCount == 0 {
		return nil, nil, fmt.Errorf("secrets[%d]: must specify either inject or replace", i)
	}
	if modeCount > 1 {
		if hasLegacy && hasReplace {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and replace block", i)
		}
		if hasLegacy && hasInject {
			return nil, nil, fmt.Errorf("secrets[%d]: cannot use both top-level proxy_value/match_headers and inject block", i)
		}
		return nil, nil, fmt.Errorf("secrets[%d]: cannot specify both inject and replace", i)
	}

	if hasInject {
		if err := validateInject(i, entry.Inject); err != nil {
			return nil, nil, err
		}
		return nil, entry.Inject, nil
	}

	if hasReplace {
		if entry.Replace.ProxyValue == "" {
			return nil, nil, fmt.Errorf("secrets[%d]: replace.proxy_value is required", i)
		}
		if err := validateReplaceQueryParams(i, entry.Replace); err != nil {
			return nil, nil, err
		}
		return entry.Replace, nil, nil
	}

	// Legacy top-level fields: normalize into replaceConfig.
	if entry.ProxyValue == "" {
		return nil, nil, fmt.Errorf("secrets[%d]: proxy_value is required", i)
	}
	return &replaceConfig{
		ProxyValue:   entry.ProxyValue,
		MatchHeaders: entry.MatchHeaders,
		MatchBody:    entry.MatchBody,
		Require:      entry.Require,
	}, nil, nil
}

func validateInject(i int, cfg *injectConfig) error {
	hasHeader := cfg.Header != ""
	hasQuery := cfg.QueryParam != ""

	if !hasHeader && !hasQuery {
		return fmt.Errorf("secrets[%d]: inject must specify either header or query_param", i)
	}
	if hasHeader && hasQuery {
		return fmt.Errorf("secrets[%d]: inject cannot specify both header and query_param", i)
	}
	return nil
}

// validateReplaceQueryParams validates the optional named-query selector.
// A nil selector (field omitted or null) selects the legacy whole-query
// behavior; configured names are kept exactly as written.
func validateReplaceQueryParams(i int, cfg *replaceConfig) error {
	if cfg.MatchQueryParams == nil {
		return nil
	}
	if cfg.MatchQuery {
		return fmt.Errorf("secrets[%d]: replace.match_query: true cannot be combined with match_query_params", i)
	}
	if len(cfg.MatchQueryParams) == 0 {
		return fmt.Errorf("secrets[%d]: replace.match_query_params must not be empty", i)
	}
	seen := make(map[string]struct{}, len(cfg.MatchQueryParams))
	for _, name := range cfg.MatchQueryParams {
		if name == "" {
			return fmt.Errorf("secrets[%d]: replace.match_query_params must not contain an empty parameter name", i)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("secrets[%d]: replace.match_query_params contains duplicate parameter name %q", i, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (s *Secrets) Name() string { return "secrets" }

func (s *Secrets) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	type secretRecord struct {
		Secret    string   `json:"secret"`
		Locations []string `json:"locations"`
	}
	var swapped, injected []secretRecord
	var unavailable []string

	for _, sec := range s.secrets {
		if !hostmatch.MatchAnyRule(sec.rules, req) {
			continue
		}

		name := sec.source.Name()

		// Named-query mode: validate the complete query and, when the
		// secret is required, the selected placement before resolving the
		// secret or mutating anything. The per-request segments computed
		// here are reused for the swap.
		var namedSegs []querySegment
		if sec.matchQueryParams != nil {
			segs, err := splitQuerySegments(req.URL.RawQuery)
			if err != nil {
				// url.ParseQuery error text can quote raw query bytes, so
				// record a fixed reason instead of the error.
				tctx.Annotate("rejected", name)
				tctx.Annotate("reject_reason", "malformed_query")
				return &transform.TransformResult{Action: transform.ActionReject}, nil
			}
			if sec.require && !selectedQueryHasToken(segs, sec.matchQueryParams, sec.proxyValue) {
				tctx.Annotate("rejected", name)
				tctx.Annotate("reject_reason", "query_token_missing")
				return &transform.TransformResult{Action: transform.ActionReject}, nil
			}
			namedSegs = segs
		}

		realValue, err := sec.source.Get(ctx)
		if err != nil {
			if sec.require {
				tctx.Annotate("rejected", name)
				tctx.Annotate("reject_reason", "secret_unavailable")
				return &transform.TransformResult{Action: transform.ActionReject}, nil
			}
			unavailable = append(unavailable, name)
			continue
		}

		if sec.mode == "inject" {
			locations, err := s.injectSecret(req, &sec, realValue)
			if err != nil {
				return nil, fmt.Errorf("injecting secret %q: %w", name, err)
			}
			if len(locations) > 0 {
				injected = append(injected, secretRecord{Secret: name, Locations: locations})
			}
			continue
		}

		var locations []string
		locations = append(locations, s.swapHeaders(req, &sec, realValue)...)

		if sec.matchQueryParams != nil {
			locations = append(locations, s.swapNamedQuery(req, namedSegs, &sec, realValue)...)
		} else if sec.matchQuery {
			locations = append(locations, s.swapQuery(req, &sec, realValue)...)
		}

		if sec.matchPath {
			if loc := s.swapPath(req, &sec, realValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if sec.matchBody {
			if loc := s.swapBody(req, &sec, realValue); loc != "" {
				locations = append(locations, loc)
			}
		}

		if len(locations) > 0 {
			swapped = append(swapped, secretRecord{Secret: name, Locations: locations})
		} else if sec.require {
			tctx.Annotate("rejected", name)
			return &transform.TransformResult{Action: transform.ActionReject}, nil
		}
	}

	if len(swapped) > 0 {
		tctx.Annotate("swapped", swapped)
	}
	if len(injected) > 0 {
		tctx.Annotate("injected", injected)
	}
	if len(unavailable) > 0 {
		tctx.Annotate("secret_unavailable", unavailable)
	}

	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) injectSecret(req *http.Request, sec *resolvedSecret, realValue string) ([]string, error) {
	formatted, err := s.formatValue(sec, realValue)
	if err != nil {
		return nil, err
	}

	var locations []string
	if sec.injectHeader != "" {
		headers.Set(req.Header, sec.injectHeader, formatted)
		locations = append(locations, "header:"+sec.injectHeader)
	}
	if sec.injectQueryParam != "" {
		q := req.URL.Query()
		q.Set(sec.injectQueryParam, formatted)
		req.URL.RawQuery = q.Encode()
		locations = append(locations, "query:"+sec.injectQueryParam)
	}
	return locations, nil
}

func (s *Secrets) formatValue(sec *resolvedSecret, realValue string) (string, error) {
	if sec.formatter == nil {
		return realValue, nil
	}
	var buf strings.Builder
	if err := sec.formatter.Execute(&buf, formatterData{Value: realValue}); err != nil {
		return "", fmt.Errorf("executing formatter: %w", err)
	}
	return buf.String(), nil
}

func (s *Secrets) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (s *Secrets) swapHeaders(req *http.Request, sec *resolvedSecret, realValue string) []string {
	var locations []string
	if len(sec.matchHeaders) == 0 {
		for name, vals := range req.Header {
			for i, v := range vals {
				if headerContains(name, v, sec.proxyValue) {
					req.Header[name][i] = replaceInHeader(name, v, sec.proxyValue, realValue)
					locations = append(locations, "header:"+name)
				}
			}
		}
		return locations
	}

	processed := make(map[string]struct{})
	// swap scans the header identified by its canonical name and, on a match,
	// rewrites it under wireName so the user's requested casing is sent over
	// the wire. For regex matches wireName is the header's existing casing.
	swap := func(canonical, wireName string) {
		if _, done := processed[canonical]; done {
			return
		}
		processed[canonical] = struct{}{}
		hit := false
		headers.Swap(req.Header, canonical, wireName, func(v string) string {
			if headerContains(canonical, v, sec.proxyValue) {
				hit = true
			}
			return replaceInHeader(canonical, v, sec.proxyValue, realValue)
		})
		if hit {
			locations = append(locations, "header:"+wireName)
		}
	}
	for _, m := range sec.matchHeaders {
		if m.re != nil {
			for name := range req.Header {
				if m.re.MatchString(name) {
					swap(name, name)
				}
			}
			continue
		}
		swap(m.name, m.wireName)
	}
	return locations
}

// replaceInHeader performs a secret replacement in a header value. For
// Authorization headers with HTTP Basic auth, the base64 payload is decoded
// before replacement and re-encoded after.
func replaceInHeader(headerName, value, proxyValue, realValue string) string {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			replaced := strings.ReplaceAll(decoded, proxyValue, realValue)
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(replaced))
		}
	}
	return strings.ReplaceAll(value, proxyValue, realValue)
}

// headerContains checks whether a header value contains the proxy token.
// For Authorization headers with HTTP Basic auth, the base64 payload is
// decoded before checking.
func headerContains(headerName, value, proxyValue string) bool {
	if strings.EqualFold(headerName, "Authorization") {
		if decoded, ok := decodeBasicAuth(value); ok {
			return strings.Contains(decoded, proxyValue)
		}
	}
	return strings.Contains(value, proxyValue)
}

// decodeBasicAuth extracts and base64-decodes the payload from a "Basic ..."
// Authorization header value. Returns the decoded string and true on success.
func decodeBasicAuth(value string) (string, bool) {
	after, ok := strings.CutPrefix(value, "Basic ")
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(after)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func (s *Secrets) swapQuery(req *http.Request, sec *resolvedSecret, realValue string) []string {
	raw := req.URL.RawQuery
	if raw == "" || !strings.Contains(raw, sec.proxyValue) {
		return nil
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}

	var locations []string
	for key, vals := range params {
		for i, v := range vals {
			if strings.Contains(v, sec.proxyValue) {
				params[key][i] = strings.ReplaceAll(v, sec.proxyValue, realValue)
				locations = append(locations, "query:"+key)
			}
		}
	}

	if len(locations) > 0 {
		req.URL.RawQuery = params.Encode()
	}
	return locations
}

// querySegment is one ampersand-delimited piece of a raw query string with
// its key and value decoded exactly once.
type querySegment struct {
	rawKey   string // the original encoded key
	rawValue string // the original encoded value ("" when the segment has no '=')
	key      string // the decoded key
	value    string // the decoded value
	hasEq    bool   // whether the segment contains '='
}

// splitQuerySegments validates raw with the standard query parser and then
// splits it into ampersand-delimited segments, decoding each key and value
// once. A malformed query yields the parser error so the caller can reject
// the request instead of forwarding a partial parse.
func splitQuerySegments(raw string) ([]querySegment, error) {
	if _, err := url.ParseQuery(raw); err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, "&")
	segs := make([]querySegment, 0, len(parts))
	for _, part := range parts {
		rawKey, rawValue, hasEq := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			// Unreachable when url.ParseQuery accepted the query above;
			// reject defensively rather than forward undecodable bytes.
			return nil, err
		}
		value := ""
		if hasEq {
			value, err = url.QueryUnescape(rawValue)
			if err != nil {
				return nil, err
			}
		}
		segs = append(segs, querySegment{
			rawKey:   rawKey,
			rawValue: rawValue,
			key:      key,
			value:    value,
			hasEq:    hasEq,
		})
	}
	return segs, nil
}

// selectedQueryHasToken reports whether any selected parameter's decoded
// value contains the proxy token.
func selectedQueryHasToken(segs []querySegment, selected []string, token string) bool {
	for _, seg := range segs {
		if slices.Contains(selected, seg.key) && strings.Contains(seg.value, token) {
			return true
		}
	}
	return false
}

// swapNamedQuery replaces every proxy-token occurrence inside the decoded
// values of the selected query parameters. Only changed values are
// re-encoded; encoded keys and every untouched segment keep their original
// bytes, so unrelated query data is preserved verbatim.
func (s *Secrets) swapNamedQuery(req *http.Request, segs []querySegment, sec *resolvedSecret, realValue string) []string {
	var locations []string
	for i := range segs {
		seg := &segs[i]
		if !slices.Contains(sec.matchQueryParams, seg.key) {
			continue
		}
		if !strings.Contains(seg.value, sec.proxyValue) {
			continue
		}
		seg.rawValue = url.QueryEscape(strings.ReplaceAll(seg.value, sec.proxyValue, realValue))
		locations = append(locations, "query:"+seg.key)
	}
	if len(locations) == 0 {
		return nil
	}

	var b strings.Builder
	for i := range segs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(segs[i].rawKey)
		if segs[i].hasEq {
			b.WriteByte('=')
			b.WriteString(segs[i].rawValue)
		}
	}
	req.URL.RawQuery = b.String()
	return locations
}

func (s *Secrets) swapPath(req *http.Request, sec *resolvedSecret, realValue string) string {
	path := req.URL.Path
	if path == "" || !strings.Contains(path, sec.proxyValue) {
		return ""
	}
	req.URL.Path = strings.ReplaceAll(path, sec.proxyValue, realValue)
	// RawPath is an optional encoded form; clear it so net/http re-derives
	// the encoding from the new Path.
	req.URL.RawPath = ""
	return "path"
}

func (s *Secrets) swapBody(req *http.Request, sec *resolvedSecret, realValue string) string {
	if req.Body == nil {
		return ""
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}

	if !bytes.Contains(data, []byte(sec.proxyValue)) {
		return ""
	}

	replaced := bytes.ReplaceAll(data, []byte(sec.proxyValue), []byte(realValue))
	req.Body = transform.NewBufferedBodyFromBytes(replaced)
	return "body"
}
