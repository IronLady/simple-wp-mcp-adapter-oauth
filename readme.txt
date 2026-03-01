=== Simple WP MCP Adapter OAuth ===
Contributors: Samuel Sena
Tags: oauth, oauth2, mcp, api, authentication
Requires at least: 6.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds OAuth 2.1 authorization server support for WordPress MCP Adapter.

== Description ==

Simple WP MCP Adapter OAuth enables OAuth-based authorization flows for MCP servers exposed through the WordPress MCP Adapter ecosystem.

Motivation:

WordPress MCP Adapter does not natively cover AI clients that require strict OAuth 2.1 flows.
This plugin fills that gap by turning the existing WordPress site into the OAuth authorization server for MCP access, reusing the existing WordPress login (`wp-login.php`) and a WordPress-hosted consent flow.

Features:

* OAuth authorization endpoint with consent screen.
* Token endpoint (authorization code, refresh token, and client credentials grants).
* PKCE support for Authorization Code flow (`S256`).
* Dynamic client registration endpoint.
* OAuth discovery and JWKS endpoints.
* WordPress-integrated user session and consent handling.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`, or install it through the Plugins screen.
2. Activate **Simple WP MCP Adapter OAuth** in WordPress Admin.
3. Ensure the required dependency plugin (WordPress MCP Adapter) is active.
4. Configure your MCP server/client to use the exposed OAuth endpoints.

== How to Use OAuthTransport ==

This plugin automatically registers `SimpleWpMcpAdapterOAuth\OAuthTransport` as the MCP transport via the `mcp_adapter_default_server_config` filter.

If you want to register a server with `OAuthTransport` explicitly, add:

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

After activation, your MCP server exposes OAuth metadata and token routes, including:

* `/.well-known/oauth-protected-resource`
* `/.well-known/oauth-authorization-server`
* `/token`

== All OAuth Endpoints ==

Assuming:

* Namespace: `{namespace}`
* MCP route: `{server_route}`
* REST prefix: `/wp-json`

Endpoints:

* `GET /wp-json/{namespace}/{server_route}` (MCP server endpoint)
* `GET /wp-json/{namespace}/{server_route}/.well-known/oauth-protected-resource`
* `GET /wp-json/{namespace}/{server_route}/.well-known/oauth-authorization-server`
* `GET /wp-json/{namespace}/{server_route}/.well-known/jwks.json`
* `POST /wp-json/{namespace}/{server_route}/token`
* `POST /wp-json/{namespace}/{server_route}/register`
* `GET /wp-json/{namespace}/{server_route}/register/{client_id}`
* `PUT /wp-json/{namespace}/{server_route}/register/{client_id}`
* `DELETE /wp-json/{namespace}/{server_route}/register/{client_id}`
* `GET|POST /wp-admin/admin-post.php?action=simple_mcp_oauth_authorize`

== Frequently Asked Questions ==

= Does this plugin require another plugin? =

Yes. It requires the WordPress MCP Adapter plugin to be active.

= Where are signing keys stored? =

Signing keys are created in the WordPress uploads directory at `uploads/simple-wp-mcp-adapter-oauth-keys`.

= What happens on uninstall? =

On uninstall, plugin-created OAuth database tables and generated signing keys are removed.

== Screenshots ==

1. OAuth consent screen shown during authorization.
2. OAuth discovery and token endpoints exposed by the plugin.

== Changelog ==

= 1.0.0 =

* Initial stable release.

== Upgrade Notice ==

= 1.0.0 =

Initial stable release with OAuth support for MCP Adapter.
