package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"
)

const mcpProtocolVersion = "2026-07-28"

// validateTransport validates the modern per-request metadata and its HTTP
// mirrors before dispatch. The authenticated request body remains the source
// of truth; no context is inferred from a previous request or connection.
// See https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http.
func validateTransport(r *http.Request, q *rpcRequest) (int, *rpcError) {
	headerError := func(name string) (int, *rpcError) {
		return http.StatusBadRequest, &rpcError{-32020, "Header mismatch: " + name + " is missing, malformed, or does not match the request body", nil}
	}
	paramError := func(message string) (int, *rpcError) {
		return http.StatusBadRequest, &rpcError{-32602, message, nil}
	}
	versionHeader, ok := transportHeader(r.Header, "MCP-Protocol-Version")
	if !ok {
		return headerError("MCP-Protocol-Version")
	}
	methodHeader, ok := transportHeader(r.Header, "Mcp-Method")
	if !ok || methodHeader != q.Method {
		return headerError("Mcp-Method")
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(q.Params, &params) != nil || params == nil {
		return paramError("params must contain modern MCP request metadata")
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil || meta == nil {
		return paramError("params._meta must be an object")
	}
	var version string
	if json.Unmarshal(meta["io.modelcontextprotocol/protocolVersion"], &version) != nil || version == "" {
		return paramError("params._meta must include a protocolVersion string")
	}
	if versionHeader != version {
		return headerError("MCP-Protocol-Version")
	}
	if version != mcpProtocolVersion {
		return http.StatusBadRequest, &rpcError{-32022, "Unsupported protocol version", map[string]any{"supported": []string{mcpProtocolVersion}, "requested": version}}
	}
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(meta["io.modelcontextprotocol/clientCapabilities"], &capabilities) != nil || capabilities == nil {
		return paramError("params._meta must include a clientCapabilities object")
	}
	if raw, present := meta["io.modelcontextprotocol/clientInfo"]; present {
		var info map[string]json.RawMessage
		if json.Unmarshal(raw, &info) != nil || info == nil {
			return paramError("clientInfo must be an object containing name and version strings")
		}
		for _, field := range []string{"name", "version"} {
			var value *string
			if json.Unmarshal(info[field], &value) != nil || value == nil {
				return paramError("clientInfo must contain name and version strings")
			}
		}
	}
	// Mcp-Name is specified for these core methods only. Event methods carry
	// names in their bodies but do not require this additional HTTP header.
	field := ""
	switch q.Method {
	case "tools/call", "prompts/get":
		field = "name"
	case "resources/read":
		field = "uri"
	}
	if field != "" {
		var name *string
		if json.Unmarshal(params[field], &name) != nil || name == nil {
			return paramError("request must include a " + field + " string")
		}
		nameHeader, ok := transportHeader(r.Header, "Mcp-Name")
		if !ok {
			return headerError("Mcp-Name")
		}
		if strings.HasPrefix(nameHeader, "=?base64?") && strings.HasSuffix(nameHeader, "?=") {
			decoded, err := base64.StdEncoding.Strict().DecodeString(nameHeader[len("=?base64?") : len(nameHeader)-len("?=")])
			if err != nil || !utf8.Valid(decoded) {
				return headerError("Mcp-Name")
			}
			nameHeader = string(decoded)
		}
		if nameHeader != *name {
			return headerError("Mcp-Name")
		}
	}
	return http.StatusOK, nil
}

func transportHeader(h http.Header, name string) (string, bool) {
	values := h.Values(name)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false
	}
	for _, c := range []byte(values[0]) {
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return "", false
		}
	}
	return values[0], true
}
