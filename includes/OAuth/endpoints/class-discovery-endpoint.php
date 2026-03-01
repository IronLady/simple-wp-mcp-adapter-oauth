<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Discovery_Endpoint extends Base_Endpoint {

	/**
	 * Handle discovery endpoint request.
	 *
	 * @param \WP_REST_Request $request The request.
	 * @return \WP_REST_Response
	 */
	public function handle_request( $request ) {
		$route      = $request->get_route();
		$base_route = str_replace( '/.well-known/oauth-authorization-server', '', $route );
		$base       = untrailingslashit( rest_url( ltrim( $base_route, '/' ) ) );
		$config     = array(
			'issuer'                                => untrailingslashit( $base ),
			'authorization_endpoint'                => admin_url( 'admin-post.php?action=simple_mcp_oauth_authorize' ),
			'token_endpoint'                        => $base . '/token',
			'registration_endpoint'                 => $base . '/register',
			'jwks_uri'                              => $base . '/.well-known/jwks.json',
			'response_types_supported'              => array( 'code' ),
			'scopes_supported'                      => array( 'profile', 'email' ),
			'token_endpoint_auth_methods_supported' => array( 'none' ),
			'grant_types_supported'                 => array( 'authorization_code', 'refresh_token', 'client_credentials' ),
			'code_challenge_methods_supported'      => array( 'S256' ),
		);
		return new \WP_REST_Response( $config, 200 );
	}
}
