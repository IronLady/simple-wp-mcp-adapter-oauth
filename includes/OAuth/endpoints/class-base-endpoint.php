<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Base_Endpoint {

	/**
	 * Creates a PSR-7 ServerRequest from PHP globals.
	 *
	 * @return ServerRequestInterface
	 */
	protected function create_psr_request_from_globals() {
		$request = new ServerRequest(
			isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
			isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/',
			$this->get_request_headers(),
			null,
			'1.1',
			$_SERVER
		);

		return $request
			->withQueryParams( $_GET ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			->withParsedBody( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Converts a WP_REST_Request to a PSR-7 ServerRequest.
	 *
	 * @param \WP_REST_Request $request The WordPress REST request.
	 * @return ServerRequestInterface
	 */
	protected function convert_to_psr_request( $request ) {
		$server_request = new ServerRequest(
			$request->get_method(),
			isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/',
			$this->get_request_headers(),
			$request->get_body(),
			'1.1',
			$_SERVER
		);

		return $server_request
			->withQueryParams( $request->get_query_params() )
			->withParsedBody( $request->get_params() );
	}

	/**
	 * Send a PSR-7 response and terminate execution.
	 *
	 * @param \Psr\Http\Message\ResponseInterface $response Response object.
	 * @return void
	 */
	protected function send_psr_response( $response ) {
		foreach ( $response->getHeaders() as $name => $values ) {
			foreach ( $values as $value ) {
				header( sprintf( '%s: %s', $name, $value ), false );
			}
		}
		status_header( $response->getStatusCode() );
		echo $response->getBody(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Convert OAuth server exception to WP REST response.
	 *
	 * @param \League\OAuth2\Server\Exception\OAuthServerException $exception OAuth exception.
	 * @return \WP_REST_Response
	 */
	protected function handle_oauth_exception( $exception ) {
		return new \WP_REST_Response(
			array(
				'error'             => $exception->getErrorType(),
				'error_description' => $exception->getMessage(),
			),
			$exception->getHttpStatusCode()
		);
	}

	/**
	 * Build request headers from server globals.
	 *
	 * @return array<string, string>
	 */
	private function get_request_headers() {
		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			if ( is_array( $headers ) ) {
				return $headers;
			}
		}

		$headers = array();
		foreach ( $_SERVER as $name => $value ) {
			if ( 0 !== strpos( $name, 'HTTP_' ) || ! is_string( $value ) ) {
				continue;
			}

			$header_name             = str_replace( '_', '-', substr( $name, 5 ) );
			$headers[ $header_name ] = sanitize_text_field( wp_unslash( $value ) );
		}

		return $headers;
	}
}
