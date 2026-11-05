/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Generated from the redacted live samples in work/runtime
// (compare-after.sink.redacted.log, ams-stdout.redacted.log), normalised
// to the AuditEvent contract per the feature spec's mapping rules.

import type { AuditEvent, AuditEventListResponse } from "@agent-management-platform/types";

export const llmChatOk: AuditEvent = {
  "id": "01a1a638-2b33-77e9-8ca2-f575e16673d9",
  "timestamp": "2026-11-04T11:00:59.777Z",
  "source": "GATEWAY",
  "category": "LLM",
  "action": "llm:chat",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "gpt-4o-mini -> gpt-4o-mini-2024-07-18, 17 tokens",
  "actor": {
    "type": "ANONYMOUS",
    "display": "API key",
    "authMethod": "apikey",
    "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "LlmProxy",
    "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
    "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy"
  },
  "decision": null,
  "llm": {
    "provider": "openai",
    "requestModel": "gpt-4o-mini",
    "model": "gpt-4o-mini-2024-07-18",
    "promptTokens": 8,
    "completionTokens": 9,
    "totalTokens": 17
  },
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E01-llm-chat-ok"
  },
  "correlationId": "0c61bd90-b742-468d-abf4-746b7f43dfbb",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-2b33-77e9-8ca2-f575e16673d9",
    "seq": 1,
    "timestamp": "2026-11-04T11:00:59.777Z",
    "correlationId": "0c61bd90-b742-468d-abf4-746b7f43dfbb",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "version": "1.0.0",
      "context": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597",
      "kind": "LlmProxy"
    },
    "operation": {
      "method": "POST",
      "path": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597/chat/completions"
    },
    "target": {
      "statusCode": 200,
      "destination": "127.0.0.1/openai-audit/chat/completions"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E01-llm-chat-ok"
    },
    "auth": {
      "authenticated": true,
      "type": "apikey",
      "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89",
      "authorized": false
    },
    "ai": {
      "provider": "openai",
      "providerVersion": "1.0.0",
      "model": "gpt-4o-mini-2024-07-18",
      "requestModel": "gpt-4o-mini",
      "promptTokens": 8,
      "completionTokens": 9,
      "totalTokens": 17
    },
    "latencies": {
      "durationUs": 1322679,
      "requestMediationLatencyUs": 61272,
      "responseMediationLatencyUs": 1781,
      "backendLatencyUs": 1236632
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {
        "ApplicationID": "",
        "ApplicationName": ""
      },
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "524b2519787bffeb1942018be9403b48b7e32b9bc7a93f0c8050176af8c1e43c",
      "p_auth_type": "apikey",
      "p_metadata": {
        "provider_name": "openai-audit",
        "template_handle": "openai",
        "x-wso2-application-id": ""
      }
    }
  }
};

export const llmNoKeyDenied: AuditEvent = {
  "id": "01a1a638-32db-78f7-95e2-ca2b9735e1cc",
  "timestamp": "2026-11-04T11:01:02.951Z",
  "source": "GATEWAY",
  "category": "LLM",
  "action": "llm:chat",
  "outcome": "DENIED",
  "statusCode": 401,
  "summary": "llm:chat denied by api-key-auth (request_headers)",
  "actor": {
    "type": "ANONYMOUS"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "LlmProxy",
    "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
    "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy"
  },
  "decision": {
    "terminalReason": "policy_denied",
    "deniedBy": {
      "policy": "api-key-auth",
      "version": "v1",
      "phase": "request_headers"
    }
  },
  "llm": null,
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": {
    "type": "AUTH",
    "code": 401,
    "message": "AUTHENTICATION_FAILURE"
  },
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E04-llm-no-key"
  },
  "correlationId": "1c08bb1b-3371-4ea4-8d25-87de1f5592ba",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-32db-78f7-95e2-ca2b9735e1cc",
    "seq": 4,
    "timestamp": "2026-11-04T11:01:02.951Z",
    "correlationId": "1c08bb1b-3371-4ea4-8d25-87de1f5592ba",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 401,
    "api": {
      "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "version": "1.0.0",
      "context": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597",
      "kind": "LlmProxy"
    },
    "operation": {
      "method": "POST"
    },
    "target": {
      "statusCode": 401,
      "destination": "default-default.gateway.localhost:19080/audit-llm-3dc9f0dbfb6c4d76-27f6b597/chat/completions"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E04-llm-no-key"
    },
    "decision": {
      "terminalReason": "policy_denied",
      "deniedBy": {
        "policy": "api-key-auth",
        "version": "v1",
        "phase": "request_headers"
      }
    },
    "errorType": "AUTH",
    "error": {
      "errorCode": 401,
      "errorMessage": "AUTHENTICATION_FAILURE"
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {},
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "",
      "p_auth_type": "",
      "p_metadata": {
        "provider_name": "openai-audit",
        "template_handle": "openai"
      }
    }
  }
};

export const llmGuardrailDenied: AuditEvent = {
  "id": "01a1a638-32db-7ac5-9aa4-73e98c8c0593",
  "timestamp": "2026-11-04T11:01:02.967Z",
  "source": "GATEWAY",
  "category": "LLM",
  "action": "llm:chat",
  "outcome": "DENIED",
  "statusCode": 422,
  "summary": "llm:chat denied by content-length-guardrail (request_body)",
  "actor": {
    "type": "ANONYMOUS",
    "display": "API key",
    "authMethod": "apikey",
    "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "LlmProxy",
    "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
    "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy"
  },
  "decision": {
    "terminalReason": "policy_denied",
    "deniedBy": {
      "policy": "content-length-guardrail",
      "version": "v1",
      "phase": "request_body"
    }
  },
  "llm": null,
  "mcp": null,
  "a2a": null,
  "guardrail": {
    "hit": true,
    "name": "content-length-guardrail"
  },
  "error": {
    "type": "OTHER",
    "code": 422,
    "message": "UNCLASSIFIED"
  },
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E05-llm-request-guardrail"
  },
  "correlationId": "481d435f-dc23-48df-8f9b-b71ca022230a",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-32db-7ac5-9aa4-73e98c8c0593",
    "seq": 5,
    "timestamp": "2026-11-04T11:01:02.967Z",
    "correlationId": "481d435f-dc23-48df-8f9b-b71ca022230a",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 422,
    "api": {
      "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "version": "1.0.0",
      "context": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597",
      "kind": "LlmProxy"
    },
    "operation": {
      "method": "POST"
    },
    "target": {
      "statusCode": 422,
      "destination": "default-default.gateway.localhost:19080/audit-llm-3dc9f0dbfb6c4d76-27f6b597/chat/completions"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E05-llm-request-guardrail"
    },
    "auth": {
      "authenticated": true,
      "type": "apikey",
      "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89",
      "authorized": false
    },
    "decision": {
      "terminalReason": "policy_denied",
      "deniedBy": {
        "policy": "content-length-guardrail",
        "version": "v1",
        "phase": "request_body"
      }
    },
    "errorType": "OTHER",
    "error": {
      "errorCode": 422,
      "errorMessage": "UNCLASSIFIED"
    },
    "guardrail": {
      "hit": true,
      "name": "content-length-guardrail"
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {
        "ApplicationID": "",
        "ApplicationName": ""
      },
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "524b2519787bffeb1942018be9403b48b7e32b9bc7a93f0c8050176af8c1e43c",
      "p_auth_type": "apikey",
      "p_metadata": {
        "provider_name": "openai-audit",
        "template_handle": "openai",
        "x-wso2-application-id": ""
      }
    }
  }
};

export const llmUpstream404: AuditEvent = {
  "id": "01a1a638-36c6-72a7-8ac3-266f627a104a",
  "timestamp": "2026-11-04T11:01:02.985Z",
  "source": "GATEWAY",
  "category": "LLM",
  "action": "llm:chat",
  "outcome": "FAILED",
  "statusCode": 404,
  "summary": "no-such-model-xyz -> no-such-model-xyz, None tokens",
  "actor": {
    "type": "ANONYMOUS",
    "display": "API key",
    "authMethod": "apikey",
    "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "LlmProxy",
    "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
    "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy"
  },
  "decision": null,
  "llm": {
    "provider": "openai",
    "requestModel": "no-such-model-xyz",
    "model": "no-such-model-xyz"
  },
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": {
    "type": "OTHER",
    "code": 404,
    "message": "UNCLASSIFIED"
  },
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E06-llm-upstream-404"
  },
  "correlationId": "51de7ec3-2e9d-4b1d-9fa7-c6d7dbd69731",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-36c6-72a7-8ac3-266f627a104a",
    "seq": 6,
    "timestamp": "2026-11-04T11:01:02.985Z",
    "correlationId": "51de7ec3-2e9d-4b1d-9fa7-c6d7dbd69731",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 404,
    "api": {
      "id": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "name": "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy",
      "version": "1.0.0",
      "context": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597",
      "kind": "LlmProxy"
    },
    "operation": {
      "method": "POST",
      "path": "/audit-llm-3dc9f0dbfb6c4d76-27f6b597/chat/completions"
    },
    "target": {
      "statusCode": 404,
      "destination": "127.0.0.1/openai-audit/chat/completions"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E06-llm-upstream-404"
    },
    "auth": {
      "authenticated": true,
      "type": "apikey",
      "tokenId": "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89",
      "authorized": false
    },
    "errorType": "OTHER",
    "error": {
      "errorCode": 404,
      "errorMessage": "UNCLASSIFIED"
    },
    "ai": {
      "provider": "openai",
      "providerVersion": "1.0.0",
      "model": "no-such-model-xyz",
      "requestModel": "no-such-model-xyz"
    },
    "latencies": {
      "durationUs": 422419,
      "requestMediationLatencyUs": 1147,
      "responseMediationLatencyUs": 685,
      "backendLatencyUs": 420264
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {
        "ApplicationID": "",
        "ApplicationName": ""
      },
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "524b2519787bffeb1942018be9403b48b7e32b9bc7a93f0c8050176af8c1e43c",
      "p_auth_type": "apikey",
      "p_metadata": {
        "provider_name": "openai-audit",
        "template_handle": "openai",
        "x-wso2-application-id": ""
      }
    }
  }
};

export const mcpToolsCallOk: AuditEvent = {
  "id": "01a1a638-4281-7bd5-bff2-8046bb98e87d",
  "timestamp": "2026-11-04T11:01:06.979Z",
  "source": "GATEWAY",
  "category": "MCP",
  "action": "mcp:tools/call",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "tools/call echo on everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
  "actor": {
    "type": "AGENT",
    "id": "01a1a364-bef0-7b63-bad3-f7f002d3e771",
    "display": "ext-audit-agent",
    "authMethod": "mcp/oauth+authz",
    "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
    "tokenId": "01a1a638-3baf-7e1c-bf77-fdc677a37321"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "Mcp",
    "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "id": "25562dac-9b5b-493c-81a7-36bfcae64611"
  },
  "decision": null,
  "llm": null,
  "mcp": {
    "server": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "method": "tools/call",
    "tool": "echo",
    "sessionId": "cb444cb1-4a59-45e1-a034-b3df32771fdb",
    "jsonRpcId": "3",
    "isError": false
  },
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E11-mcp-tools-call-echo-ok"
  },
  "correlationId": "84cb05c8-d172-49a9-b947-8e4bbb3590ce",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-4281-7bd5-bff2-8046bb98e87d",
    "seq": 11,
    "timestamp": "2026-11-04T11:01:06.979Z",
    "correlationId": "84cb05c8-d172-49a9-b947-8e4bbb3590ce",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "25562dac-9b5b-493c-81a7-36bfcae64611",
      "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
      "version": "v1.0",
      "context": "/everything",
      "kind": "Mcp"
    },
    "operation": {
      "method": "POST",
      "path": "/everything/mcp"
    },
    "target": {
      "statusCode": 200,
      "destination": "db720294-98fd-40f4-85a1-cc6a3b65bc9a-prod.e1-us-east-azure.choreoapis.dev/godzilla/mcp-everything-server/v1.0/mcp"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E11-mcp-tools-call-echo-ok"
    },
    "auth": {
      "subject": "01a1a364-bef0-7b63-bad3-f7f002d3e771",
      "authenticated": true,
      "type": "mcp/oauth+authz",
      "issuer": "http://default-idp.amp.localhost:8080",
      "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
      "tokenId": "01a1a638-3baf-7e1c-bf77-fdc677a37321",
      "audience": [
        "http://default-default.gateway.localhost:19080/everything/mcp"
      ],
      "scopes": [
        "everything:read"
      ],
      "authorized": true
    },
    "mcp": {
      "method": "tools/call",
      "id": "3",
      "capability": "TOOL",
      "name": "echo",
      "sessionId": "cb444cb1-4a59-45e1-a034-b3df32771fdb",
      "isError": false,
      "resultType": "complete"
    },
    "latencies": {
      "durationUs": 271090,
      "requestMediationLatencyUs": 879,
      "responseMediationLatencyUs": 2675,
      "backendLatencyUs": 267220
    },
    "properties": {
      "p_auth_authorized": true,
      "p_auth_credential_id": "8MrgYJLUzHxuGCysR_wQ0g",
      "p_auth_issuer": "http://default-idp.amp.localhost:8080",
      "p_auth_property": {
        "client_id": "8MrgYJLUzHxuGCysR_wQ0g",
        "grant_type": "client_credentials"
      },
      "p_auth_scopes": [
        "everything:read"
      ],
      "p_auth_subject": "01a1a364-bef0-7b63-bad3-f7f002d3e771",
      "p_auth_token_id": "01a1a638-3baf-7e1c-bf77-fdc677a37321",
      "p_auth_type": "mcp/oauth+authz",
      "p_metadata": {
        "bodyResolved": true,
        "gatewayHost": "default-default.gateway.localhost",
        "gatewayUrl": "",
        "mcp.method": "tools/call",
        "mcp.name": "echo",
        "mcp.type": "tool"
      }
    }
  }
};

export const mcpOboToolsCallOk: AuditEvent = {
  "id": "01a1a638-59ed-71a9-9214-eeaeec24f479",
  "timestamp": "2026-11-04T11:01:11.678Z",
  "source": "GATEWAY",
  "category": "MCP",
  "action": "mcp:tools/call",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "tools/call echo on everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
  "actor": {
    "type": "AGENT",
    "id": "01a1a364-bef0-7b63-bad3-f7f002d3e771",
    "display": "ext-audit-agent",
    "authMethod": "mcp/oauth+authz",
    "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
    "tokenId": "01a1a638-5248-7926-8e89-c8a5fb36d517"
  },
  "onBehalfOf": {
    "subject": "01900000-0000-7000-8000-000000000030",
    "chain": [
      "01a1a364-bef0-7b63-bad3-f7f002d3e771"
    ]
  },
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "Mcp",
    "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "id": "25562dac-9b5b-493c-81a7-36bfcae64611"
  },
  "decision": null,
  "llm": null,
  "mcp": {
    "server": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "method": "tools/call",
    "tool": "echo",
    "sessionId": "5770a021-947f-4c0f-b1f7-65680cc058e6",
    "jsonRpcId": "6",
    "isError": false
  },
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E15-mcp-obo-tools-call-echo-ok"
  },
  "correlationId": "f5087e5f-fed8-4df3-96d7-739fba128ae9",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-59ed-71a9-9214-eeaeec24f479",
    "seq": 15,
    "timestamp": "2026-11-04T11:01:11.678Z",
    "correlationId": "f5087e5f-fed8-4df3-96d7-739fba128ae9",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "25562dac-9b5b-493c-81a7-36bfcae64611",
      "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
      "version": "v1.0",
      "context": "/everything",
      "kind": "Mcp"
    },
    "operation": {
      "method": "POST",
      "path": "/everything/mcp"
    },
    "target": {
      "statusCode": 200,
      "destination": "db720294-98fd-40f4-85a1-cc6a3b65bc9a-prod.e1-us-east-azure.choreoapis.dev/godzilla/mcp-everything-server/v1.0/mcp"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E15-mcp-obo-tools-call-echo-ok"
    },
    "auth": {
      "subject": "01900000-0000-7000-8000-000000000030",
      "authenticated": true,
      "type": "mcp/oauth+authz",
      "issuer": "http://default-idp.amp.localhost:8080",
      "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
      "tokenId": "01a1a638-5248-7926-8e89-c8a5fb36d517",
      "audience": [
        "http://default-default.gateway.localhost:19080/everything/mcp"
      ],
      "scopes": [
        "everything:read"
      ],
      "authorized": true,
      "claims": {
        "act": {
          "iss": "http://default-idp.amp.localhost:8080",
          "sub": "01a1a364-bef0-7b63-bad3-f7f002d3e771"
        }
      }
    },
    "mcp": {
      "method": "tools/call",
      "id": "6",
      "capability": "TOOL",
      "name": "echo",
      "sessionId": "5770a021-947f-4c0f-b1f7-65680cc058e6",
      "isError": false,
      "resultType": "complete"
    },
    "latencies": {
      "durationUs": 699426,
      "requestMediationLatencyUs": 1967,
      "responseMediationLatencyUs": 965,
      "backendLatencyUs": 696131
    },
    "properties": {
      "p_auth_authorized": true,
      "p_auth_credential_id": "8MrgYJLUzHxuGCysR_wQ0g",
      "p_auth_issuer": "http://default-idp.amp.localhost:8080",
      "p_auth_property": {
        "act": "{\"iss\":\"http://default-idp.amp.localhost:8080\",\"sub\":\"01a1a364-bef0-7b63-bad3-f7f002d3e771\"}",
        "client_id": "8MrgYJLUzHxuGCysR_wQ0g",
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"
      },
      "p_auth_scopes": [
        "everything:read"
      ],
      "p_auth_subject": "01900000-0000-7000-8000-000000000030",
      "p_auth_token_id": "01a1a638-5248-7926-8e89-c8a5fb36d517",
      "p_auth_type": "mcp/oauth+authz",
      "p_metadata": {
        "bodyResolved": true,
        "gatewayHost": "default-default.gateway.localhost",
        "gatewayUrl": "",
        "mcp.method": "tools/call",
        "mcp.name": "echo",
        "mcp.type": "tool"
      }
    }
  }
};

export const mcpOboToolsCallDenied: AuditEvent = {
  "id": "01a1a638-59ed-7656-abc4-88f9206974b0",
  "timestamp": "2026-11-04T11:01:12.382Z",
  "source": "GATEWAY",
  "category": "MCP",
  "action": "mcp:tools/call",
  "outcome": "DENIED",
  "statusCode": 403,
  "summary": "mcp:tools/call denied by mcp-authz (request_headers)",
  "actor": {
    "type": "AGENT",
    "id": "01a1a364-bef0-7b63-bad3-f7f002d3e771",
    "display": "ext-audit-agent",
    "authMethod": "mcp/oauth",
    "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
    "tokenId": "01a1a638-5248-7926-8e89-c8a5fb36d517"
  },
  "onBehalfOf": {
    "subject": "01900000-0000-7000-8000-000000000030",
    "chain": [
      "01a1a364-bef0-7b63-bad3-f7f002d3e771"
    ]
  },
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "Mcp",
    "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "id": "25562dac-9b5b-493c-81a7-36bfcae64611"
  },
  "decision": {
    "terminalReason": "policy_denied",
    "deniedBy": {
      "policy": "mcp-authz",
      "version": "v1",
      "phase": "request_headers"
    }
  },
  "llm": null,
  "mcp": {
    "server": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
    "method": "tools/call",
    "tool": "orderPizza",
    "sessionId": "5770a021-947f-4c0f-b1f7-65680cc058e6",
    "jsonRpcId": "7",
    "isError": false
  },
  "a2a": null,
  "guardrail": null,
  "error": {
    "type": "AUTH",
    "code": 403,
    "message": "AUTHORIZATION_FAILURE"
  },
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E16-mcp-obo-tools-call-denied"
  },
  "correlationId": "3b15e00b-d105-4fb3-aa13-b8d8a92f21fd",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-59ed-7656-abc4-88f9206974b0",
    "seq": 16,
    "timestamp": "2026-11-04T11:01:12.382Z",
    "correlationId": "3b15e00b-d105-4fb3-aa13-b8d8a92f21fd",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 403,
    "api": {
      "id": "25562dac-9b5b-493c-81a7-36bfcae64611",
      "name": "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab",
      "version": "v1.0",
      "context": "/everything",
      "kind": "Mcp"
    },
    "operation": {
      "method": "POST"
    },
    "target": {
      "statusCode": 403,
      "destination": "default-default.gateway.localhost:19080/everything/mcp"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E16-mcp-obo-tools-call-denied"
    },
    "auth": {
      "subject": "01900000-0000-7000-8000-000000000030",
      "authenticated": true,
      "type": "mcp/oauth",
      "issuer": "http://default-idp.amp.localhost:8080",
      "clientId": "8MrgYJLUzHxuGCysR_wQ0g",
      "tokenId": "01a1a638-5248-7926-8e89-c8a5fb36d517",
      "audience": [
        "http://default-default.gateway.localhost:19080/everything/mcp"
      ],
      "scopes": [
        "everything:read"
      ],
      "authorized": false,
      "claims": {
        "act": {
          "iss": "http://default-idp.amp.localhost:8080",
          "sub": "01a1a364-bef0-7b63-bad3-f7f002d3e771"
        }
      }
    },
    "decision": {
      "terminalReason": "policy_denied",
      "deniedBy": {
        "policy": "mcp-authz",
        "version": "v1",
        "phase": "request_headers"
      }
    },
    "errorType": "AUTH",
    "error": {
      "errorCode": 403,
      "errorMessage": "AUTHORIZATION_FAILURE"
    },
    "mcp": {
      "method": "tools/call",
      "id": "7",
      "capability": "TOOL",
      "name": "orderPizza",
      "sessionId": "5770a021-947f-4c0f-b1f7-65680cc058e6"
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "8MrgYJLUzHxuGCysR_wQ0g",
      "p_auth_issuer": "http://default-idp.amp.localhost:8080",
      "p_auth_property": {
        "act": "{\"iss\":\"http://default-idp.amp.localhost:8080\",\"sub\":\"01a1a364-bef0-7b63-bad3-f7f002d3e771\"}",
        "client_id": "8MrgYJLUzHxuGCysR_wQ0g",
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"
      },
      "p_auth_scopes": [
        "everything:read"
      ],
      "p_auth_subject": "01900000-0000-7000-8000-000000000030",
      "p_auth_token_id": "01a1a638-5248-7926-8e89-c8a5fb36d517",
      "p_auth_type": "mcp/oauth",
      "p_metadata": {
        "bodyResolved": true,
        "gatewayHost": "default-default.gateway.localhost",
        "gatewayUrl": "",
        "mcp.method": "tools/call",
        "mcp.name": "orderPizza",
        "mcp.type": "tool"
      }
    }
  }
};

export const otelExportOk: AuditEvent = {
  "id": "01a1a638-59ed-7881-9e38-d7456887b28e",
  "timestamp": "2026-11-04T11:01:12.388Z",
  "source": "GATEWAY",
  "category": "OTHER",
  "action": "telemetry:export",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "POST /otel/v1/traces -> 200",
  "actor": {
    "type": "AGENT",
    "id": "ext-audit-agent",
    "display": "ext-audit-agent",
    "authMethod": "jwt",
    "tokenId": "19d7f08d-4a3b-44c6-b6f6-35f96336bcee"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "ext-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "RestApi",
    "name": "api-platform-default-default-otel-restapi",
    "id": "01a1a27c-d4ab-7c99-8120-d29c0641c001"
  },
  "decision": null,
  "llm": null,
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/E17-otel-ok"
  },
  "correlationId": "9b5cc016-8102-4017-b638-facbcd06d43a",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-59ed-7881-9e38-d7456887b28e",
    "seq": 17,
    "timestamp": "2026-11-04T11:01:12.388Z",
    "correlationId": "9b5cc016-8102-4017-b638-facbcd06d43a",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "01a1a27c-d4ab-7c99-8120-d29c0641c001",
      "name": "api-platform-default-default-otel-restapi",
      "version": "v1.0",
      "context": "/otel",
      "kind": "RestApi"
    },
    "operation": {
      "method": "POST",
      "path": "/otel/v1/traces"
    },
    "target": {
      "statusCode": 200,
      "destination": "opentelemetry-collector.openchoreo-observability-plane.svc.cluster.local/v1/traces"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/E17-otel-ok"
    },
    "auth": {
      "subject": "ext-audit-agent",
      "authenticated": true,
      "type": "jwt",
      "issuer": "agent-manager-service",
      "tokenId": "19d7f08d-4a3b-44c6-b6f6-35f96336bcee",
      "authorized": false
    },
    "latencies": {
      "durationUs": 403295,
      "requestMediationLatencyUs": 24490,
      "responseMediationLatencyUs": 1105,
      "backendLatencyUs": 377418
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "agent-manager-service",
      "p_auth_property": {
        "component_uid": "0fd9425f-ffa9-461f-8c0e-302e86245996",
        "environment_uid": "ca151496-8f62-42de-b7df-d72ae7c4eaab",
        "namespace": "default",
        "org_id": "01900000-0000-7000-8000-000000000001",
        "project_uid": "ce3a2999-1af1-488c-b31c-570065fa7a50"
      },
      "p_auth_scopes": [],
      "p_auth_subject": "ext-audit-agent",
      "p_auth_token_id": "19d7f08d-4a3b-44c6-b6f6-35f96336bcee",
      "p_auth_type": "jwt",
      "p_metadata": {}
    }
  }
};

export const agentEndpointOk: AuditEvent = {
  "id": "01a1a638-5dd2-7502-88f1-b8814a8e08df",
  "timestamp": "2026-11-04T11:01:12.800Z",
  "source": "GATEWAY",
  "category": "OTHER",
  "action": "agent:invoke",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "GET /default-default-int-audit-agent/health -> 200",
  "actor": {
    "type": "ANONYMOUS",
    "display": "API key",
    "authMethod": "apikey",
    "tokenId": "hmac-sha256:dc59deec57cec11e2e3c4466e2f7b396f1b56f68c9be51ac579a5cc52abd9da3"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "int-audit-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "RestApi",
    "name": "int-audit-agent-default",
    "id": "01a1a370-9a24-7d3c-a37f-f6bf20d1c4cc"
  },
  "decision": null,
  "llm": null,
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/I01-agent-endpoint-ok"
  },
  "correlationId": "0944af1a-9105-4e2d-93c0-b06a77cd9b1b",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-5dd2-7502-88f1-b8814a8e08df",
    "seq": 19,
    "timestamp": "2026-11-04T11:01:12.800Z",
    "correlationId": "0944af1a-9105-4e2d-93c0-b06a77cd9b1b",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "01a1a370-9a24-7d3c-a37f-f6bf20d1c4cc",
      "name": "int-audit-agent-default",
      "version": "v1.0",
      "context": "/default-default-int-audit-agent",
      "kind": "RestApi",
      "projectId": "ce3a2999-1af1-488c-b31c-570065fa7a50"
    },
    "operation": {
      "method": "GET",
      "path": "/default-default-int-audit-agent/health"
    },
    "target": {
      "statusCode": 200,
      "destination": "int-audit-agent.dp-default-default-default-ccb66d74/health"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/I01-agent-endpoint-ok"
    },
    "auth": {
      "authenticated": true,
      "type": "apikey",
      "tokenId": "hmac-sha256:dc59deec57cec11e2e3c4466e2f7b396f1b56f68c9be51ac579a5cc52abd9da3",
      "authorized": false
    },
    "latencies": {
      "durationUs": 901939,
      "requestMediationLatencyUs": 1845,
      "responseMediationLatencyUs": 2369,
      "backendLatencyUs": 897382
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {
        "ApplicationID": "",
        "ApplicationName": ""
      },
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "a5b636f54e9fe69a2405ccbda9ad47a15ceeed53bbfafcfb6f4554ac9bb0fce0",
      "p_auth_type": "apikey",
      "p_metadata": {
        "cors_headers": {
          "Access-Control-Allow-Credentials": "false",
          "Access-Control-Allow-Origin": "*"
        },
        "x-wso2-application-id": ""
      }
    }
  }
};

export const a2aSendMessageOk: AuditEvent = {
  "id": "01a1a638-ee6c-7913-9373-9c0dd0bb96c3",
  "timestamp": "2026-11-04T11:01:50.058Z",
  "source": "GATEWAY",
  "category": "A2A",
  "action": "a2a:SendMessage",
  "outcome": "SUCCESS",
  "statusCode": 200,
  "summary": "SendMessage to a2a-notes-agent",
  "actor": {
    "type": "ANONYMOUS",
    "display": "API key",
    "authMethod": "apikey",
    "tokenId": "hmac-sha256:a16ffa5d2298826af22e9e77d220201aa5be31e9010295913fe836c377d03094"
  },
  "onBehalfOf": null,
  "agent": {
    "name": "a2a-notes-agent",
    "project": "default"
  },
  "project": "default",
  "environment": "default",
  "resource": {
    "type": "Agent",
    "name": "a2a-notes-agent",
    "id": "01a1a5fb-868f-752a-a6ef-f8ba3e8733d7"
  },
  "decision": null,
  "llm": null,
  "mcp": null,
  "a2a": {
    "requestType": "operation",
    "operation": "SendMessage",
    "transport": "JSONRPC",
    "protocolVersion": "1.0",
    "messageId": "m-643e6f59",
    "inputPartCount": 1,
    "returnImmediately": false,
    "isError": false,
    "isStreaming": false,
    "payloadType": "task",
    "responseTaskId": "219943cc-d06c-43cd-ac02-f002bd731eb8",
    "responseContextId": "a2feb9e2-932c-4365-9a70-45523a1f141a",
    "taskState": "TASK_STATE_FAILED",
    "terminal": true,
    "outcome": "SUCCESS"
  },
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "audit-lab/after/A02-a2a-sendmessage-ok"
  },
  "correlationId": "a8773a76-03d2-4252-8d1e-40265ffe2c01",
  "gateway": {
    "id": "api-platform-default-default",
    "organization": "default",
    "environment": "default"
  },
  "raw": {
    "component": "pol",
    "eventId": "01a1a638-ee6c-7913-9373-9c0dd0bb96c3",
    "seq": 26,
    "timestamp": "2026-11-04T11:01:50.058Z",
    "correlationId": "a8773a76-03d2-4252-8d1e-40265ffe2c01",
    "gateway": {
      "id": "api-platform-default-default",
      "organization": "default",
      "environment": "default"
    },
    "status": 200,
    "api": {
      "id": "01a1a5fb-868f-752a-a6ef-f8ba3e8733d7",
      "name": "a2a-notes-agent",
      "version": "v1.0",
      "context": "/a2a-notes-agent",
      "kind": "Agent"
    },
    "operation": {
      "method": "POST",
      "path": "/a2a-notes-agent/rpc"
    },
    "target": {
      "statusCode": 200,
      "destination": "a2a-notes-agent.dp-default-default-default-ccb66d74.svc.cluster.local/rpc"
    },
    "client": {
      "ip": "10.42.0.1",
      "userAgent": "audit-lab/after/A02-a2a-sendmessage-ok"
    },
    "auth": {
      "authenticated": true,
      "type": "apikey",
      "tokenId": "hmac-sha256:a16ffa5d2298826af22e9e77d220201aa5be31e9010295913fe836c377d03094",
      "authorized": false
    },
    "a2a": {
      "requestType": "operation",
      "operation": "SendMessage",
      "transport": "JSONRPC",
      "protocolVersion": "1.0",
      "messageId": "m-643e6f59",
      "inputPartCount": 1,
      "returnImmediately": false,
      "isError": false,
      "isStreaming": false,
      "payloadType": "task",
      "responseTaskId": "219943cc-d06c-43cd-ac02-f002bd731eb8",
      "responseContextId": "a2feb9e2-932c-4365-9a70-45523a1f141a",
      "taskState": "TASK_STATE_FAILED",
      "terminal": true,
      "outcome": "SUCCESS"
    },
    "latencies": {
      "durationUs": 790306,
      "requestMediationLatencyUs": 6885,
      "responseMediationLatencyUs": 1700,
      "backendLatencyUs": 780121
    },
    "properties": {
      "p_auth_authorized": false,
      "p_auth_credential_id": "",
      "p_auth_issuer": "",
      "p_auth_property": {
        "ApplicationID": "",
        "ApplicationName": ""
      },
      "p_auth_scopes": [],
      "p_auth_subject": "",
      "p_auth_token_id": "7a6fe28130cdd6ee81b4703fee52f397a41eee6f1b3924a590f0e49abfdfd89b",
      "p_auth_type": "apikey",
      "p_metadata": {
        "bodyResolved": true,
        "cors_headers": {
          "Access-Control-Allow-Credentials": "false",
          "Access-Control-Allow-Origin": "*"
        },
        "x-wso2-application-id": ""
      }
    }
  }
};

export const cpAgentCreate: AuditEvent = {
  "id": "b4ca1e08-1615-4840-9df3-21fa91de44b9",
  "timestamp": "2026-11-03T21:50:50.593442572Z",
  "source": "CONTROL_PLANE",
  "category": "OPERATIONAL",
  "action": "agent:create",
  "outcome": "SUCCESS",
  "statusCode": 202,
  "summary": "agent:create POST /orgs/{orgName}/projects/{projName}/agents",
  "actor": {
    "type": "USER",
    "id": "01900000-0000-7000-8000-000000000030",
    "display": "admin",
    "authMethod": "jwt-bearer",
    "tokenId": "01a1a35f-499f-760a-b529-e6bd0e927fb8"
  },
  "onBehalfOf": null,
  "agent": null,
  "resource": {},
  "decision": null,
  "llm": null,
  "mcp": null,
  "a2a": null,
  "guardrail": null,
  "error": null,
  "network": {
    "clientIp": "10.42.0.1",
    "userAgent": "Python-urllib/3.9"
  },
  "correlationId": "a94336a8-7e92-47db-806a-258ce6986be5",
  "gateway": null,
  "raw": {
    "time": "2026-11-03T21:50:50.718003656Z",
    "level": "INFO",
    "msg": "audit",
    "log_type": "audit",
    "event": {
      "eventId": "b4ca1e08-1615-4840-9df3-21fa91de44b9",
      "schemaVersion": 1,
      "occurredAt": "2026-11-03T21:50:50.593442572Z",
      "durationMs": 71,
      "action": "agent:create",
      "actionClass": "config",
      "severity": 2,
      "actorType": "user",
      "actorId": "01900000-0000-7000-8000-000000000030",
      "actorOuId": "01900000-0000-7000-8000-000000000001",
      "authMethod": "jwt-bearer",
      "actorTokenId": "01a1a35f-499f-760a-b529-e6bd0e927fb8",
      "surface": "api",
      "sourceIp": "10.42.0.1",
      "userAgent": "Python-urllib/3.9",
      "correlationId": "a94336a8-7e92-47db-806a-258ce6986be5",
      "requestMethod": "POST",
      "requestPath": "/orgs/{orgName}/projects/{projName}/agents",
      "ouId": "01900000-0000-7000-8000-000000000001",
      "outcome": "success",
      "statusCode": 202,
      "requiredPermission": "amp:agent:create",
      "details": {
        "envelope": true
      }
    }
  }
};

/**
 * An audit.Begin intent record (outcome "unknown" in the store), as the API
 * returns it. Kept out of ALL_EVENTS so the page totals stay those of the
 * live sample.
 */
export const cpIdentityProvisionStarted: AuditEvent = {
  ...cpAgentCreate,
  "id": "8d2bb99e-6669-45ce-9413-4405fb4d613b",
  "action": "agent-identity:provision",
  "outcome": "STARTED",
  "statusCode": null,
  "summary": "01900000-0000-7000-8000-000000000030 agent-identity:provision agent-identity ext-audit-agent (started)",
  "resource": { "type": "agent-identity", "name": "ext-audit-agent" },
  "raw": {
    "log_type": "audit",
    "event": {
      "eventId": "8d2bb99e-6669-45ce-9413-4405fb4d613b",
      "action": "agent-identity:provision",
      "outcome": "unknown",
    },
  },
};

/** All fixtures, newest first. */
export const ALL_EVENTS: AuditEvent[] = [
  a2aSendMessageOk,
  agentEndpointOk,
  otelExportOk,
  mcpOboToolsCallDenied,
  mcpOboToolsCallOk,
  mcpToolsCallOk,
  llmUpstream404,
  llmGuardrailDenied,
  llmNoKeyDenied,
  llmChatOk,
  cpAgentCreate,
];

export const PAGE_ONE: AuditEventListResponse = {
  events: ALL_EVENTS,
  nextCursor: "WzE3NjIyNTQwNTAwNTgsIjAxYTFhNjM4Il0=",
  total: 11,
  totalRelation: "eq",
  categoryCounts: {"OPERATIONAL": 1, "LLM": 4, "MCP": 3, "A2A": 1, "OTHER": 2},
};
