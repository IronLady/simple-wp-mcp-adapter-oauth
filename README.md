# Simple WP MCP Adapter OAuth

Adds OAuth 2.1 authorization server support for WordPress MCP Adapter.

## Motivation

WordPress MCP Adapter does not natively cover AI clients that require strict OAuth 2.1 flows.

This plugin fills that gap by turning the existing WordPress site into the OAuth authorization server for MCP access, reusing:

- the existing WordPress login (`wp-login.php`) for authentication
- a WordPress-hosted consent flow for authorization decisions

## Requirements

- WordPress 6.8+
- PHP 7.4+
- OpenSSL extension
- WordPress MCP Adapter plugin

## Features

- OAuth authorize endpoint with consent flow
- OAuth token endpoint
- PKCE support for Authorization Code flow (`S256`)
- Dynamic client registration endpoint
- OAuth discovery endpoint
- JWKS endpoint

## Install (development)

1. Run `composer install`.
2. Activate the plugin in WordPress Admin.

## How OAuthTransport is used

By default, this plugin registers `SimpleWpMcpAdapterOAuth\OAuthTransport` as the MCP transport by filtering `mcp_adapter_default_server_config`.

If you want to register a server with `OAuthTransport` explicitly, you can do:

```php
add_action(
	'mcp_adapter_init',
	function ( $adapter ) {
		$adapter->create_server(
			'alpha-server',
			'alpha',
			'mcp',
			'Alpha MCP Server',
			'Central MCP server for Alpha',
			'1.0.0',
			array( \SimpleWpMcpAdapterOAuth\OAuthTransport::class ),
			null,
			null,
			array( 'alpha/get-posts' ),
			array(),
			array()
		);
	}
);
```

After activation, your MCP server exposes:

- OAuth protected resource metadata: `/.well-known/oauth-protected-resource`
- OAuth authorization server metadata: `/.well-known/oauth-authorization-server`
- OAuth token endpoint: `/token`

## All OAuth endpoints

Assuming:

- Namespace: `{namespace}`
- MCP route: `{server_route}`
- REST prefix: `/wp-json`

Endpoints:

- `GET /wp-json/{namespace}/{server_route}` (MCP server endpoint)
- `GET /wp-json/{namespace}/{server_route}/.well-known/oauth-protected-resource`
- `GET /wp-json/{namespace}/{server_route}/.well-known/oauth-authorization-server`
- `GET /wp-json/{namespace}/{server_route}/.well-known/jwks.json`
- `POST /wp-json/{namespace}/{server_route}/token`
- `POST /wp-json/{namespace}/{server_route}/register`
- `GET /wp-json/{namespace}/{server_route}/register/{client_id}`
- `PUT /wp-json/{namespace}/{server_route}/register/{client_id}`
- `DELETE /wp-json/{namespace}/{server_route}/register/{client_id}`
- `GET|POST /wp-admin/admin-post.php?action=simple_mcp_oauth_authorize`
