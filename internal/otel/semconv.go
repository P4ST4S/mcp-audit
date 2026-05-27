package otel

const (
	attrServiceName = "service.name"
)

const (
	attrMCPMethodName = "mcp.method.name"
)

const (
	attrGenAIOperationName = "gen_ai.operation.name"
	attrGenAIToolName      = "gen_ai.tool.name"
)

const (
	attrJSONRPCRequestID = "jsonrpc.request.id"
)

const (
	attrNetworkTransport    = "network.transport"
	attrNetworkProtocolName = "network.protocol.name"
)

const (
	attrServerAddress = "server.address"
	attrServerPort    = "server.port"
)

const (
	attrRPCResponseStatusCode = "rpc.response.status_code"
)

const (
	attrErrorType = "error.type"
)

const (
	attrMCPAuditEntryID          = "mcp_audit.entry_id"
	attrMCPAuditDirection        = "mcp_audit.direction"
	attrMCPAuditClientID         = "mcp_audit.client_id"
	attrMCPAuditServerID         = "mcp_audit.server_id"
	attrMCPAuditStorage          = "mcp_audit.storage"
	attrMCPAuditSignaturePresent = "mcp_audit.signature.present"
)
