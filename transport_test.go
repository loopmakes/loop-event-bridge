package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func transportFixture(t *testing.T, method string, params map[string]any) (*http.Request, *rpcRequest) {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": mcpProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	r.Header.Set("Mcp-Method", method)
	if name, ok := params["name"].(string); ok && (method == "tools/call" || method == "prompts/get") {
		r.Header.Set("Mcp-Name", name)
	}
	if uri, ok := params["uri"].(string); ok && method == "resources/read" {
		r.Header.Set("Mcp-Name", uri)
	}
	return r, &rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: raw}
}

func TestTransportValidModernRequests(t *testing.T) {
	for _, method := range []string{"server/discover", "events/list", "events/subscribe", "events/unsubscribe", "tools/list", "tools/call", "prompts/get", "resources/read"} {
		t.Run(method, func(t *testing.T) {
			r, q := transportFixture(t, method, map[string]any{"name": "bridge_status", "uri": "resource://example"})
			if status, err := validateTransport(r, q); status != http.StatusOK || err != nil {
				t.Fatalf("valid request rejected: %d %#v", status, err)
			}
		})
	}
}

func TestTransportHeaderConformance(t *testing.T) {
	for _, header := range []string{"MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
		for _, variant := range []string{"missing", "different", "duplicate"} {
			t.Run(header+"/"+variant, func(t *testing.T) {
				r, q := transportFixture(t, "tools/call", map[string]any{"name": "bridge_status"})
				switch variant {
				case "missing":
					r.Header.Del(header)
				case "different":
					r.Header.Set(header, "other")
				case "duplicate":
					r.Header.Add(header, r.Header.Get(header))
				}
				if status, err := validateTransport(r, q); status != http.StatusBadRequest || err == nil || err.Code != -32020 {
					t.Fatalf("expected HeaderMismatch, got %d %#v", status, err)
				}
			})
		}
	}
}

func TestTransportVersionNegotiation(t *testing.T) {
	r, q := transportFixture(t, "server/discover", nil)
	var params map[string]any
	_ = json.Unmarshal(q.Params, &params)
	params["_meta"].(map[string]any)["io.modelcontextprotocol/protocolVersion"] = "2025-11-25"
	q.Params, _ = json.Marshal(params)
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	status, err := validateTransport(r, q)
	if status != http.StatusBadRequest || err == nil || err.Code != -32022 {
		t.Fatalf("expected UnsupportedProtocolVersion, got %d %#v", status, err)
	}
	data, _ := json.Marshal(err.Data)
	if string(data) != `{"requested":"2025-11-25","supported":["2026-07-28"]}` {
		t.Fatalf("incorrect version negotiation detail: %s", data)
	}
}

func TestTransportRequiredMetadata(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}`, `{"_meta":null}`, `{"_meta":{}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":null}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"client"}}}`,
	} {
		r, q := transportFixture(t, "server/discover", nil)
		q.Params = json.RawMessage(raw)
		if status, err := validateTransport(r, q); status != http.StatusBadRequest || err == nil || err.Code != -32602 {
			t.Fatalf("invalid metadata %s: got %d %#v", raw, status, err)
		}
	}
}

func TestTransportNameEncoding(t *testing.T) {
	for _, name := range []string{"bridge_status", "name with spaces", " padded ", "\u4e16\u754c", "=?base64?literal?="} {
		r, q := transportFixture(t, "tools/call", map[string]any{"name": name})
		r.Header.Set("Mcp-Name", "=?base64?"+base64.StdEncoding.EncodeToString([]byte(name))+"?=")
		if status, err := validateTransport(r, q); status != http.StatusOK || err != nil {
			t.Fatalf("encoded name %q rejected: %d %#v", name, status, err)
		}
	}
	for _, header := range []string{"=?base64?invalid!?=", "\u4e16\u754c", " bridge_status ", "=?base64?/w==?="} {
		r, q := transportFixture(t, "tools/call", map[string]any{"name": "bridge_status"})
		r.Header.Set("Mcp-Name", header)
		if status, err := validateTransport(r, q); status != http.StatusBadRequest || err == nil || err.Code != -32020 {
			t.Fatalf("invalid header %q accepted: %d %#v", header, status, err)
		}
	}
}
