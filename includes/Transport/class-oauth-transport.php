<?php
namespace SimpleWpMcpAdapterOAuth;

use WP\MCP\Transport\HttpTransport;
use WP\MCP\Transport\Infrastructure\McpTransportContext;

class OAuthTransport extends HttpTransport {

	/**
	 * Initialize the class and register routes
	 *
	 * @param \WP\MCP\Transport\Infrastructure\McpTransportContext $transport_context The transport context.
	 */
	public function __construct( McpTransportContext $transport_context ) {
		parent::__construct( $transport_context );
		add_filter( 'rest_request_after_callbacks', array( $this, 'add_authenticate_header' ), 10, 3 );
	}

	/**
	 * Register MCP route and OAuth protected-resource metadata route.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		parent::register_routes();

		$server = $this->request_handler->transport_context->mcp_server;

		register_rest_route(
			$server->get_server_route_namespace(),
			$server->get_server_route() . '/.well-known/oauth-protected-resource',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_oauth_protected_resource' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Return OAuth protected-resource metadata for this MCP server.
	 *
	 * @param \WP_REST_Request $request REST request.
	 * @return \WP_REST_Response
	 */
	public function get_oauth_protected_resource( \WP_REST_Request $request ) {
		$server = $this->request_handler->transport_context->mcp_server;

		$server_route_namespace = $server->get_server_route_namespace();
		$server_route           = $server->get_server_route();

		$resource_metadata = array(
			'resource'                 => rest_url( $server_route_namespace . '/' . $server_route ),
			'authorization_server'     => rest_url( $server_route_namespace . '/' . $server_route . '/.well-known/oauth-authorization-server' ),
			'bearer_methods_supported' => array( 'header' ),
		);

		return rest_ensure_response( $resource_metadata );
	}

	/**
	 * Add authenticate header to response
	 *
	 * @param mixed            $response The response object.
	 * @param array            $handler  The handler that was called.
	 * @param \WP_REST_Request $request  Request used to generate the response.
	 *
	 * @return mixed
	 */
	public function add_authenticate_header( $response, array $handler, \WP_REST_Request $request ) {
		if ( ! isset( $handler['callback'][0] ) || $handler['callback'][0] !== $this ) {
			return $response;
		}

		if ( is_wp_error( $response ) ) {
			$server      = $this->request_handler->transport_context->mcp_server;
			$error_codes = $response->get_error_codes();

			// Only add the header for authentication errors (rest_forbidden).
			if ( in_array( 'rest_forbidden', $error_codes, true ) ) {
				$header_key = 'WWW-Authenticate';

				// Build a URL to the resource metadata endpoint (the .well-known URI on the MCP server).
				$metadata_url = rest_url( $server->get_server_route_namespace() . '/' . $server->get_server_route() . '/.well-known/oauth-protected-resource' );

				$header_value = sprintf( 'Bearer realm="%s", resource_metadata="%s"', $server->get_server_route_namespace(), $metadata_url );

				// Keep default rest_forbidden body/status and add auth challenge metadata.
				$error_response = rest_convert_error_to_response( $response );
				$error_response->header( $header_key, $header_value );

				return $error_response;
			}
		}

		return $response;
	}
}
