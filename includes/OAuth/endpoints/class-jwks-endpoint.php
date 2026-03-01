<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class JWKS_Endpoint extends Base_Endpoint {

	/**
	 * Handle JWKS endpoint request.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_request() {
		// Get keys from file system.
		$upload_dir      = wp_upload_dir();
		$keys_dir        = $upload_dir['basedir'] . '/simple-wp-mcp-adapter-oauth-keys';
		$public_key_path = $keys_dir . '/public.key';

		if ( ! file_exists( $public_key_path ) ) {
			return new \WP_REST_Response( array( 'error' => 'Public key not found' ), 500 );
		}

		$public_key = file_get_contents( $public_key_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$res        = openssl_pkey_get_public( $public_key );
		if ( ! $res ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid public key' ), 500 );
		}
		$details = openssl_pkey_get_details( $res );
		$jwk     = array(
			'kty' => 'RSA',
			'alg' => 'RS256',
			'use' => 'sig',
			'n'   => strtr( rtrim( base64_encode( $details['rsa']['n'] ), '=' ), '+/', '-_' ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'e'   => strtr( rtrim( base64_encode( $details['rsa']['e'] ), '=' ), '+/', '-_' ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'kid' => hash( 'sha256', $public_key ),
		);
		return new \WP_REST_Response( array( 'keys' => array( $jwk ) ), 200 );
	}
}
