# Gatekeeper MCP Server

The Model Context Protocol (MCP) server allows AI agents to manage the firewall programmatically.

## Enabling

```bash
gatekeeperd --enable-mcp --api-key-file /etc/gatekeeper/api.key
```

The MCP endpoint is available at `/mcp/` on the same port as the API (default :8080).

## Authentication

MCP requests are routed through the same API auth middleware. Include the API key:
```
X-API-Key: <your-api-key>
```

## Tool Categories

| Category | Rate Limit | Description |
|----------|-----------|-------------|
| read_only | 100/min | List zones, aliases, policies, status |
| diagnostic | 10/min | Ping, dry-run, path test |
| mutation | 20/min | Create/update/delete zones, aliases, commit |
| dangerous | 5/min | Rollback, import, service enable/disable |

## Available Tools (25+)

- `list_zones`, `create_zone`, `delete_zone`
- `list_aliases`, `create_alias`, `add_alias_member`
- `list_policies`, `create_policy`, `add_rule`
- `assign_device`, `unassign_device`
- `commit`, `rollback`, `diff`
- `dry_run`, `test_path`, `explain`
- `wg_list_peers`, `wg_add_peer`, `wg_remove_peer`
- `list_services`, `enable_service`, `disable_service`
- `status`, `audit`

## Permissions

When `cfg.Permissions` is nil (default with `--enable-mcp` alone), all tools are denied by default. Configure per-principal permissions in code or via the admin API.

## Audit

All MCP tool calls are logged with:
- Principal identity (from auth)
- Tool name and category
- SHA-256 context hash
- Timestamp
