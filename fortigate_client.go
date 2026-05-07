package forticertsync

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// FortiCert represents a certificate stored on FortiGate.
type FortiCert struct {
	Name      string
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
	Source    string
	QRef     int // Reference count
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
func (c *FortiGateClient) GetCertificateByPattern(ctx context.Context, namePattern string) (*FortiCert, error) {
	certs, err := c.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}

	var best *FortiCert
	for i := range certs {
		cert := &certs[i]
		// Match if the cert name equals the pattern exactly,
		// or starts with the pattern followed by an underscore (date suffix).
		if cert.Name == namePattern || strings.HasPrefix(cert.Name, namePattern+"_") {
			if best == nil || cert.NotBefore.After(best.NotBefore) {
				best = cert
			}
		}
	}

	if best == nil {
		return nil, nil // Not found, not an error
	}
	return best, nil
}

// ListCertificates returns all local certificates on the FortiGate.
func (c *FortiGateClient) ListCertificates(ctx context.Context) ([]FortiCert, error) {
	apiURL := c.buildURL("api/v2/monitor/vpn-certificate/local/select")

	body, statusCode, err := c.doRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("list certificates returned status %d: %s", statusCode, string(body))
	}

	// FortiGate returns JSON with a "results" array. Date fields can be
	// either Unix epoch seconds (number) or formatted strings depending on
	// FortiOS version, so we use json.RawMessage and a flexible parser.
	var result struct {
		Results []struct {
			Name      string          `json:"name"`
			Subject   string          `json:"subject"`
			Issuer    string          `json:"issuer"`
			ValidFrom json.RawMessage `json:"valid_from"`
			ValidTo   json.RawMessage `json:"valid_to"`
			Serial    string          `json:"serial_number"`
			Source    string          `json:"source"`
			QRef      int             `json:"q_ref"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing certificate list response: %w", err)
	}

	certs := make([]FortiCert, 0, len(result.Results))
	for _, r := range result.Results {
		cert := FortiCert{
			Name:    r.Name,
			Subject: r.Subject,
			Issuer:  r.Issuer,
			Serial:  r.Serial,
			Source:  r.Source,
			QRef:    r.QRef,
		}
		if t, err := parseFortiDate(r.ValidFrom); err == nil {
			cert.NotBefore = t
		}
		if t, err := parseFortiDate(r.ValidTo); err == nil {
			cert.NotAfter = t
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// parseFortiDate parses a FortiGate date field which may be either a Unix
// epoch (as a JSON number or a quoted numeric string) or a formatted date
// string in one of several common FortiOS shapes.
func parseFortiDate(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}, fmt.Errorf("empty date field")
	}

	// Try as a JSON number (epoch seconds)
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}

	// Try as a quoted string
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, fmt.Errorf("date field is neither number nor string: %s", string(raw))
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date string")
	}

	// String containing only digits → epoch seconds
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(epoch, 0).UTC(), nil
	}

	// Try common FortiOS date string formats
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
		"Jan 2 15:04:05 2006 MST",
		"Jan _2 15:04:05 2006 GMT",
		"Mon Jan _2 15:04:05 2006 MST",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized date format: %q", s)
}

// ImportCertificate uploads a new certificate and private key to FortiGate.
//
// The payload sends full PEM content (including BEGIN/END headers and
// newlines) as file_content / key_file_content. Some FortiOS versions
// reportedly accept only the raw base64 body without the PEM armor — if
// import fails with a malformed-input style error, switch to passing
// stripPEMHeaders(certPEM) and stripPEMHeaders(keyPEM) instead.
func (c *FortiGateClient) ImportCertificate(ctx context.Context, certName string, certPEM, keyPEM []byte) error {
	apiURL := c.buildURL("api/v2/monitor/vpn-certificate/local/import")

	scope := "global"
	if c.vdom != "" {
		scope = "vdom"
	}
	payload := map[string]string{
		"type":             "regular",
		"certname":         certName,
		"file_content":     string(certPEM),
		"key_file_content": string(keyPEM),
		"scope":            scope,
	}

	body, statusCode, err := c.doRequest(ctx, http.MethodPost, apiURL, payload)
	if err != nil {
		return fmt.Errorf("importing certificate %q: %w", certName, err)
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("import certificate %q returned status %d: %s", certName, statusCode, string(body))
	}

	c.logger.Info("certificate imported to FortiGate",
		zap.String("cert_name", certName))
	return nil
}

// DeleteCertificate removes a certificate from FortiGate by its exact name.
func (c *FortiGateClient) DeleteCertificate(ctx context.Context, certName string) error {
	apiURL := c.buildURL("api/v2/monitor/vpn-certificate/local/clear", "mkey", certName)

	body, statusCode, err := c.doRequest(ctx, http.MethodPost, apiURL, nil)
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

// UpdateCertReference updates a single CMDB object to reference a new certificate name.
func (c *FortiGateClient) UpdateCertReference(ctx context.Context, ref CertReference, newCertName string) error {
	var apiURL string
	if ref.MKey != "" {
		apiURL = c.buildURL(fmt.Sprintf("api/v2/cmdb/%s/%s", ref.Endpoint, url.PathEscape(ref.MKey)))
	} else {
		apiURL = c.buildURL(fmt.Sprintf("api/v2/cmdb/%s", ref.Endpoint))
	}

	payload := map[string]string{
		ref.Field: newCertName,
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
		val, ok := obj[ep.field].(string)
		if ok && val == certName {
			mkey, _ := obj[ep.keyField].(string)
			refs = append(refs, CertReference{
				Endpoint: ep.path,
				MKey:     mkey,
				Field:    ep.field,
				OldValue: certName,
			})
		}
	}
	return refs
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

	val, ok := result.Results[ep.field].(string)
	if ok && val == certName {
		return &CertReference{
			Endpoint: ep.path,
			Field:    ep.field,
			OldValue: certName,
		}
	}
	return nil
}
