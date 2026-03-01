<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use GuzzleHttp\Psr7\Response;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Token_Endpoint extends Base_Endpoint {

	/**
	 * OAuth Server instance.
	 *
	 * @var AuthorizationServer
	 */
	private $server;

	/**
	 * Constructor.
	 *
	 * @param AuthorizationServer $server The OAuth server.
	 */
	public function __construct( AuthorizationServer $server ) {
		$this->server = $server;
	}

	/**
	 * Handles the token request.
	 *
	 * @param \WP_REST_Request $request The WordPress REST request.
	 */
	public function handle_request( $request ) {
		try {
			$psr_request = $this->convert_to_psr_request( $request );
			$response    = $this->server->respondToAccessTokenRequest( $psr_request, new Response() );
			$this->send_psr_response( $response );
		} catch ( OAuthServerException $exception ) {
			return $this->handle_oauth_exception( $exception );
		} catch ( \Exception $exception ) {
			return new \WP_REST_Response( array( 'error' => $exception->getMessage() ), 500 );
		}
	}
}
