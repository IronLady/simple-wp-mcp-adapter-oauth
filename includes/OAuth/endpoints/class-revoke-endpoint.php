<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

use SimpleWpMcpAdapterOAuth\OAuth\Repositories\AccessTokenRepository;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\RefreshTokenRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * RFC 7009 token revocation endpoint.
 *
 * Always returns HTTP 200 — per spec, revealing whether a token was valid
 * is a security risk, so the response is intentionally opaque.
 */
class Revoke_Endpoint extends Base_Endpoint {

	/**
	 * Handle POST /revoke.
	 *
	 * @param \WP_REST_Request $request The request.
	 * @return \WP_REST_Response
	 */
	public function handle_request( $request ) {
		$token = sanitize_text_field( (string) $request->get_param( 'token' ) );
		$hint  = sanitize_text_field( (string) $request->get_param( 'token_type_hint' ) );

		if ( '' !== $token ) {
			if ( 'refresh_token' === $hint ) {
				$this->revoke_refresh_token( $token );
			} elseif ( 'access_token' === $hint || $this->looks_like_jwt( $token ) ) {
				$this->revoke_access_token( $token );
			} else {
				// Unknown hint — try refresh token (simpler DB lookup), then access token.
				$this->revoke_refresh_token( $token );
				$this->revoke_access_token( $token );
			}
		}

		// RFC 7009 §2.2: always 200, no body.
		return new \WP_REST_Response( null, 200 );
	}

	/**
	 * Revoke an access token by extracting its jti and adding it to the blocklist.
	 *
	 * @param string $raw_token Raw JWT string.
	 * @return void
	 */
	private function revoke_access_token( $raw_token ) {
		$jti = $this->extract_jti( $raw_token );
		if ( null !== $jti ) {
			( new AccessTokenRepository() )->revokeAccessToken( $jti );
		}
	}

	/**
	 * Revoke a refresh token by its opaque identifier.
	 *
	 * @param string $token_id Refresh token string.
	 * @return void
	 */
	private function revoke_refresh_token( $token_id ) {
		( new RefreshTokenRepository() )->revokeRefreshToken( $token_id );
	}

	/**
	 * Extract the jti claim from a JWT without verifying the signature.
	 *
	 * Intentionally skips signature verification so expired tokens can still
	 * be revoked — the blocklist check happens on future requests, not here.
	 *
	 * @param string $token Raw JWT string.
	 * @return string|null jti value, or null if the token is not a valid JWT.
	 */
	private function extract_jti( $token ) {
		$parts = explode( '.', $token );
		if ( 3 !== count( $parts ) ) {
			return null;
		}

		// Base64url → base64 → JSON.
		$padding = strlen( $parts[1] ) % 4;
		if ( $padding ) {
			$parts[1] .= str_repeat( '=', 4 - $padding );
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding JWT payload, not obfuscating code.
		$payload = json_decode( base64_decode( strtr( $parts[1], '-_', '+/' ) ), true );
		if ( ! is_array( $payload ) || empty( $payload['jti'] ) ) {
			return null;
		}

		return (string) $payload['jti'];
	}

	/**
	 * Heuristic: does the token look like a three-segment JWT?
	 *
	 * @param string $token Token string.
	 * @return bool
	 */
	private function looks_like_jwt( $token ) {
		return 2 === substr_count( $token, '.' );
	}
}
