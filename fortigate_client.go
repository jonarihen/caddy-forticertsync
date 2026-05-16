package forticertsync

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// FortiGateClient handles all communication with the FortiGate REST API.
type FortiGateClient struct {
	baseURL    string
	apiToken   string
	vdom       string
	httpClient *http.Client
	logger     *zap.Logger
}

// FortiCert represents a certificate stored on FortiGate, as returned by
// the CMDB endpoint /api/v2/cmdb/vpn.certificate/local. The CMDB response
// has no validity dates — the monitor endpoint that did is not available
// on FortiOS 7.6.6, so we rely on the date suffix in the cert name for
// ordering.
type FortiCert struct {
	Name        string
	Source      string
	LastUpdated int64
}

// CertReference represents an object on FortiGate that references a certificate.
type CertReference struct {
	Endpoint string // CMDB API path (e.g., "vpn.ssl/settings")
	MKey     string // Object key if applicable (for list-type endpoints)
	Field    string // The field name holding the cert reference
	OldValue string // Current cert name value
}

// certRefEndpoint defines a FortiGate CMDB endpoint that may reference certificates.
type certRefEndpoint struct {
	path     string // CMDB path (e.g., "vpn.ssl/settings")
	field    string // Field name that holds the cert reference
	isList   bool   // Whether the endpoint returns a list of objects
	keyField string // For list endpoints, the field used as the mkey
}

// certReferenceEndpoints lists all known CMDB endpoints that can reference local certificates.
// This list can be extended for additional FortiGate features.
var certReferenceEndpoints = []certRefEndpoint{
	{path: "vpn.ssl/settings", field: "servercert", isList: false},
	{path: "firewall/vip", field: "server-cert", isList: true, keyField: "name"},
	{path: "system/global", field: "admin-server-cert", isList: false},
	{path: "firewall/ssl-ssh-profile", field: "server-cert", isList: true, keyField: "name"},
	// TODO: Add more endpoints as needed (e.g., user/radius, log.fortianalyzer/setting)
}

// NewFortiGateClient creates a new FortiGate REST API client.
func NewFortiGateClient(baseURL, apiToken, vdom string, insecureSkipVerify bool, logger *zap.Logger) *FortiGateClient {
	return &FortiGateClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiToken: apiToken,
		vdom:     vdom,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
				},
			},
		},
		logger: logger,
	}
}

// buildURL constructs a full FortiGate API URL with optional VDOM query parameter.
func (c *FortiGateClient) buildURL(apiPath string, queryParams ...string) string {
	u := fmt.Sprintf("%s/%s", c.baseURL, strings.TrimLeft(apiPath, "/"))

	params := url.Values{}
	if c.vdom != "" {
		params.Set("vdom", c.vdom)
	}
	// Add any additional query params (key=value pairs)
	for i := 0; i+1 < len(queryParams); i += 2 {
		params.Set(queryParams[i], queryParams[i+1])
	}

	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	return u
}

// doRequest executes an HTTP request to the FortiGate API with proper auth headers.
func (c *FortiGateClient) doRequest(ctx context.Context, method, apiURL string, body interface{}) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, apiURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// GetCertificateByPattern retrieves the latest certificate from FortiGate whose name
// matches the given base pattern (with or without a date suffix like "_ddMMyyyy").
// Ordering uses the trailing _ddMMyyyy date suffix on the cert name, since the
// CMDB response has no validity dates.
func (c *FortiGateClient) GetCertificateByPattern(ctx context.Context, namePattern string) (*FortiCert, error) {
	certs, err := c.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}

	var best *FortiCert
	var bestDate time.Time
	for i := range certs {
		cert := &certs[i]
		if cert.Name == namePattern || strings.HasPrefix(cert.Name, namePattern+"_") {
			d := extractNameDate(cert.Name)
			if best == nil || d.After(bestDate) {
				best = cert
				bestDate = d
			}
		}
	}

	if best == nil {
		return nil, nil // Not found, not an error
	}
	return best, nil
}

// extractNameDate parses a trailing "_ddMMyyyy" suffix off a cert name and
// returns the encoded date. Returns the zero time if no parseable suffix
// is present.
func extractNameDate(name string) time.Time {
	idx := strings.LastIndex(name, "_")
	if idx < 0 || len(name)-idx-1 != 8 {
		return time.Time{}
	}
	t, err := time.Parse("02012006", name[idx+1:])
	if err != nil {
		return time.Time{}
	}
	return t
}

// ListCertificates returns all local certificates on the FortiGate.
//
// FortiOS 7.6.6 removed the monitor endpoint /api/v2/monitor/vpn-certificate/local/select
// (returns 404), so we use the CMDB endpoint instead. The CMDB response only
// carries name, source, and last-updated — no validity dates.
func (c *FortiGateClient) ListCertificates(ctx context.Context) ([]FortiCert, error) {
	apiURL := c.buildURL("api/v2/cmdb/vpn.certificate/local")

	body, statusCode, err := c.doRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("list certificates returned status %d: %s", statusCode, string(body))
	}

	var result struct {
		Results []struct {
			Name        string `json:"name"`
			Source      string `json:"source"`
			LastUpdated int64  `json:"last-updated"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing certificate list response: %w", err)
	}

	certs := make([]FortiCert, 0, len(result.Results))
	for _, r := range result.Results {
		certs = append(certs, FortiCert{
			Name:        r.Name,
			Source:      r.Source,
			LastUpdated: r.LastUpdated,
		})
	}

	return certs, nil
}

// ImportCertificate uploads a new certificate and private key to FortiGate.
//
// PEM payload format — confirmed against FortiOS 7.6.6.
// Sending full armored PEM (BEGIN/END headers + newlines) is rejected with
// HTTP 500 / error -145. The API accepts only the raw base64 body of a
// single certificate, so we parse certPEM, take the first CERTIFICATE block
// (the leaf), and send its base64-encoded DER. FortiOS 7.6 administration
// guide documents file_content as a string field but does not specify the
// encoding requirement:
//
//	https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/379103
//
// Intermediate CAs in the input chain are NOT sent here; the caller is
// responsible for importing them separately via ImportCACertificate so
// FortiGate's TLS engine can include them in the handshake.
func (c *FortiGateClient) ImportCertificate(ctx context.Context, certName string, certPEM, keyPEM []byte) error {
	blocks, err := splitPEMChain(certPEM)
	if err != nil {
		return fmt.Errorf("parsing certificate PEM for %q: %w", certName, err)
	}
	leafBase64 := base64.StdEncoding.EncodeToString(blocks[0].Bytes)

	apiURL := c.buildURL("api/v2/monitor/vpn-certificate/local/import")

	scope := "global"
	if c.vdom != "" {
		scope = "vdom"
	}
	payload := map[string]string{
		"type":             "regular",
		"certname":         certName,
		"file_content":     leafBase64,
		"key_file_content": stripPEMHeaders(keyPEM),
		"scope":            scope,
	}

	body, statusCode, err := c.doRequest(ctx, http.MethodPost, apiURL, payload)
	if err != nil {
		return fmt.Errorf("importing certificate %q: %w", certName, err)
	}

	if statusCode != http.StatusOK {
		// FortiOS returns error -23 ("entry already exists") with HTTP 500
		// when the same cert content is re-imported. Multiple domains can
		// share a single FortiGate cert slot, so two cert_obtained events
		// for the same SAN cert race and the second loses. Treat as success.
		if isAlreadyExistsError(body) {
			c.logger.Info("certificate already exists on FortiGate, skipping",
				zap.String("cert_name", certName))
			return nil
		}
		return fmt.Errorf("import certificate %q returned status %d: %s", certName, statusCode, string(body))
	}

	c.logger.Info("certificate imported to FortiGate",
		zap.String("cert_name", certName))
	return nil
}

// ImportCACertificate uploads an intermediate or root CA certificate to
// FortiGate. FortiOS uses the CA store to construct the chain it presents
// during TLS handshakes for any leaf cert whose issuer matches an entry
// here, so importing the intermediate alongside the leaf is what makes
// strict TLS clients (Android OkHttp, Java's TrustManager) trust the
// chain. The caDER argument is the raw DER body of a single CA cert.
func (c *FortiGateClient) ImportCACertificate(ctx context.Context, caName string, caDER []byte) error {
	apiURL := c.buildURL("api/v2/monitor/vpn-certificate/ca/import")

	scope := "global"
	if c.vdom != "" {
		scope = "vdom"
	}
	payload := map[string]string{
		"scope":         scope,
		"import_method": "file",
		"certname":      caName,
		"file_content":  base64.StdEncoding.EncodeToString(caDER),
	}

	body, statusCode, err := c.doRequest(ctx, http.MethodPost, apiURL, payload)
	if err != nil {
		return fmt.Errorf("importing CA certificate %q: %w", caName, err)
	}

	if statusCode != http.StatusOK {
		// Same -23 semantics as ImportCertificate. We use deterministic
		// CA names (chain_<hash>) so renewals re-attempt the same import
		// every time — "already exists" is the common case, not an error.
		if isAlreadyExistsError(body) {
			c.logger.Debug("CA certificate already exists on FortiGate, skipping",
				zap.String("ca_name", caName))
			return nil
		}
		return fmt.Errorf("import CA certificate %q returned status %d: %s", caName, statusCode, string(body))
	}

	c.logger.Info("CA certificate imported to FortiGate",
		zap.String("ca_name", caName))
	return nil
}

// isAlreadyExistsError returns true if the FortiGate response body
// contains error code -23 ("entry already exists").
func isAlreadyExistsError(body []byte) bool {
	var errResp struct {
		Error int `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		return false
	}
	return errResp.Error == -23
}

// splitPEMChain returns every CERTIFICATE block from a PEM bundle in the
// order they appear. blocks[0] is the leaf; blocks[1:] are intermediates
// (the root is usually omitted by ACME servers). Non-CERTIFICATE blocks
// are skipped.
func splitPEMChain(pemData []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := pemData
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			blocks = append(blocks, blk)
		}
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks in PEM data")
	}
	return blocks, nil
}

// DeleteCertificate removes a certificate from FortiGate by its exact name.
//
// FortiOS 7.6.6 removed the monitor endpoint /api/v2/monitor/vpn-certificate/local/clear
// (returns 404), so we use the CMDB endpoint with HTTP DELETE.
func (c *FortiGateClient) DeleteCertificate(ctx context.Context, certName string) error {
	apiURL := c.buildURL(fmt.Sprintf("api/v2/cmdb/vpn.certificate/local/%s", url.PathEscape(certName)))

	body, statusCode, err := c.doRequest(ctx, http.MethodDelete, apiURL, nil)
	if err != nil {
		return fmt.Errorf("deleting certificate %q: %w", certName, err)
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("delete certificate %q returned status %d: %s", certName, statusCode, string(body))
	}

	c.logger.Info("old certificate deleted from FortiGate",
		zap.String("cert_name", certName))
	return nil
}

// FindCertReferences queries known CMDB endpoints to find all objects
// that reference the given certificate name.
func (c *FortiGateClient) FindCertReferences(ctx context.Context, certName string) ([]CertReference, error) {
	var refs []CertReference

	for _, ep := range certReferenceEndpoints {
		apiURL := c.buildURL(fmt.Sprintf("api/v2/cmdb/%s", ep.path))

		body, statusCode, err := c.doRequest(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			c.logger.Warn("failed to query CMDB endpoint for cert references",
				zap.String("endpoint", ep.path),
				zap.Error(err))
			continue
		}
		if statusCode != http.StatusOK {
			continue
		}

		if ep.isList {
			found := findRefsInList(body, ep, certName)
			refs = append(refs, found...)
		} else {
			found := findRefsInSingleton(body, ep, certName)
			if found != nil {
				refs = append(refs, *found)
			}
		}
	}

	return refs, nil
}

// UpdateCertReference updates a single CMDB object to reference a new
// certificate name. For multi-value fields (e.g. ssl-ssh-profile's
// server-cert in "Protecting SSL Server" mode), it first GETs the current
// value and replaces only the matching cert name, preserving siblings.
func (c *FortiGateClient) UpdateCertReference(ctx context.Context, ref CertReference, newCertName string) error {
	var apiURL string
	if ref.MKey != "" {
		apiURL = c.buildURL(fmt.Sprintf("api/v2/cmdb/%s/%s", ref.Endpoint, url.PathEscape(ref.MKey)))
	} else {
		apiURL = c.buildURL(fmt.Sprintf("api/v2/cmdb/%s", ref.Endpoint))
	}

	getBody, statusCode, err := c.doRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("fetching cert reference at %s: %w", ref.Endpoint, err)
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("fetch cert reference at %s returned status %d: %s", ref.Endpoint, statusCode, string(getBody))
	}

	currentValue, err := extractFieldValueFromResults(getBody, ref.Field)
	if err != nil {
		return fmt.Errorf("extracting current value for %s/%s: %w", ref.Endpoint, ref.Field, err)
	}

	newValue := replaceCertInValue(currentValue, ref.OldValue, newCertName)

	payload := map[string]interface{}{
		ref.Field: newValue,
	}

	body, statusCode, err := c.doRequest(ctx, http.MethodPut, apiURL, payload)
	if err != nil {
		return fmt.Errorf("updating cert reference at %s: %w", ref.Endpoint, err)
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("update cert reference at %s returned status %d: %s", ref.Endpoint, statusCode, string(body))
	}

	c.logger.Info("rebound cert reference",
		zap.String("endpoint", ref.Endpoint),
		zap.String("mkey", ref.MKey),
		zap.String("field", ref.Field),
		zap.String("old_cert", ref.OldValue),
		zap.String("new_cert", newCertName))
	return nil
}

// findRefsInList parses a FortiGate CMDB list response and finds objects referencing the cert.
func findRefsInList(body []byte, ep certRefEndpoint, certName string) []CertReference {
	var result struct {
		Results []map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	var refs []CertReference
	for _, obj := range result.Results {
		if !valueContainsCert(obj[ep.field], certName) {
			continue
		}
		mkey, _ := obj[ep.keyField].(string)
		refs = append(refs, CertReference{
			Endpoint: ep.path,
			MKey:     mkey,
			Field:    ep.field,
			OldValue: certName,
		})
	}
	return refs
}

// valueContainsCert returns true if val references certName. A string value
// is split on whitespace (FortiGate multi-value fields like
// ssl-ssh-profile server-cert are returned as space-separated quoted names
// joined into one string by the JSON API). An array value is expected to
// contain objects keyed by "name" or "q_origin_key".
func valueContainsCert(val interface{}, certName string) bool {
	switch v := val.(type) {
	case string:
		for _, token := range strings.Fields(v) {
			if strings.Trim(token, `"`) == certName {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if name, _ := m["q_origin_key"].(string); name == certName {
				return true
			}
			if name, _ := m["name"].(string); name == certName {
				return true
			}
		}
	}
	return false
}

// extractFieldValueFromResults reads the named field out of a FortiGate
// CMDB response, accepting either a singleton "results" object or a
// single-element "results" array.
func extractFieldValueFromResults(body []byte, field string) (interface{}, error) {
	var raw struct {
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var asMap map[string]interface{}
	if err := json.Unmarshal(raw.Results, &asMap); err == nil && asMap != nil {
		if v, ok := asMap[field]; ok {
			return v, nil
		}
	}

	var asArr []map[string]interface{}
	if err := json.Unmarshal(raw.Results, &asArr); err == nil && len(asArr) > 0 {
		if v, ok := asArr[0][field]; ok {
			return v, nil
		}
	}

	return nil, fmt.Errorf("field %q not present in results", field)
}

// replaceCertInValue returns a copy of val with oldName swapped for
// newName. Strings are tokenized on whitespace and rejoined with single
// spaces; arrays of objects produce [{"name": ...}, ...] entries.
func replaceCertInValue(val interface{}, oldName, newName string) interface{} {
	switch v := val.(type) {
	case string:
		tokens := strings.Fields(v)
		for i, t := range tokens {
			if strings.Trim(t, `"`) == oldName {
				tokens[i] = newName
			}
		}
		return strings.Join(tokens, " ")
	case []interface{}:
		out := make([]map[string]string, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if name == "" {
				name, _ = m["q_origin_key"].(string)
			}
			if name == oldName {
				name = newName
			}
			out = append(out, map[string]string{"name": name})
		}
		return out
	}
	return val
}

// stripPEMHeaders returns the raw base64 body of a PEM block with all
// "-----BEGIN ...-----" / "-----END ...-----" lines and whitespace removed.
// Reserved for use if a FortiOS version rejects full-PEM imports.
func stripPEMHeaders(pemData []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(pemData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// findRefsInSingleton parses a FortiGate CMDB singleton response and checks if it references the cert.
func findRefsInSingleton(body []byte, ep certRefEndpoint, certName string) *CertReference {
	var result struct {
		Results map[string]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// Some endpoints return results as a single object, some as an array with one element
		var resultArr struct {
			Results []map[string]interface{} `json:"results"`
		}
		if err2 := json.Unmarshal(body, &resultArr); err2 != nil || len(resultArr.Results) == 0 {
			return nil
		}
		result.Results = resultArr.Results[0]
	}

	if !valueContainsCert(result.Results[ep.field], certName) {
		return nil
	}
	return &CertReference{
		Endpoint: ep.path,
		Field:    ep.field,
		OldValue: certName,
	}
}
