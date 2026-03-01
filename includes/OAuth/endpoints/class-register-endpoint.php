<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

use SimpleWpMcpAdapterOAuth\OAuth\Data_Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Register_Endpoint extends Base_Endpoint {

	/**
	 * Create a new dynamic client registration (RFC 7591).
	 */
	public function handle_create( $request ) {
		$body = json_decode( $request->get_body(), true );
		if ( null === $body ) {
			return new \WP_REST_Response(
				array(
					'error'             => 'invalid_request',
					'error_description' => 'Invalid JSON',
				),
				400
			);
		}

		// Basic validation: must include redirect_uris for confidential/public web clients.
		if ( empty( $body['redirect_uris'] ) || ! is_array( $body['redirect_uris'] ) ) {
			return new \WP_REST_Response(
				array(
					'error'             => 'invalid_client_metadata',
					'error_description' => 'redirect_uris is required and must be an array',
				),
				400
			);
		}

		// This implementation supports public clients only.
		$body['token_endpoint_auth_method'] = 'none';
		$client_id                          = $this->generate_client_id();
		$client_secret                      = '';
		$registration_access_token          = $this->generate_registration_access_token();
		$now                                = time();
		$base_route                         = str_replace( '/register', '', $request->get_route() );
		$registration_client_uri            = untrailingslashit( rest_url( ltrim( $base_route . '/register/' . $client_id, '/' ) ) );

		$client = array(
			'client_id'                 => $client_id,
			'client_secret'             => $client_secret,
			'client_id_issued_at'       => $now,
			'client_secret_expires_at'  => 0,
			'registration_access_token' => $registration_access_token,
			'registration_client_uri'   => $registration_client_uri,
			'metadata'                  => $body,
		);

		$this->save_registered_client( $client );

		$response_body = array(
			'client_id'                 => $client_id,
			'client_id_issued_at'       => $now,
			'registration_access_token' => $registration_access_token,
			'registration_client_uri'   => $client['registration_client_uri'],
			'client_secret'             => $client_secret,
			'client_secret_expires_at'  => 0,
		) + $body;

		$resp = new \WP_REST_Response( $response_body, 201 );
		$resp->header( 'Location', $client['registration_client_uri'] );
		return $resp;
	}

	/**
	 * Get / Update / Delete a registered client. Must present registration access token.
	 */
	public function handle_manage( $request ) {
		$client_id = $request->get_param( 'client_id' );
		$client    = $this->get_registered_client( $client_id );
		if ( empty( $client ) ) {
			return new \WP_REST_Response( array( 'error' => 'not_found' ), 404 );
		}

		// Validate registration access token.
		$provided = $this->extract_registration_access_token( $request );
		if ( '' === $provided || ! hash_equals( (string) $client['registration_access_token'], $provided ) ) {
			return new \WP_REST_Response( array( 'error' => 'invalid_token' ), 401 );
		}

			$method = $request->get_method();
		switch ( $method ) {
			case 'GET':
				return new \WP_REST_Response(
					array_merge(
						array(
							'client_id'           => $client['client_id'],
							'client_id_issued_at' => $client['client_id_issued_at'],
							'client_secret'       => $client['client_secret'],
						),
						(array) $client['metadata']
					),
					200
				);
			case 'PUT':
				$body = json_decode( $request->get_body(), true );
				if ( null === $body ) {
					return new \WP_REST_Response(
						array(
							'error'             => 'invalid_request',
							'error_description' => 'Invalid JSON',
						),
						400
					);
				}

				// Replace metadata per RFC 7591.
				$client['metadata'] = $body;
				$this->save_registered_client( $client );
				return new \WP_REST_Response( $body, 200 );
			case 'DELETE':
				$this->delete_registered_client( $client_id );
				return new \WP_REST_Response( null, 204 );
		}

			return new \WP_REST_Response( array( 'error' => 'unsupported_method' ), 405 );
	}

	/** Helpers to persist registered clients in DB table */
	private function get_registered_client( $client_id ) {
		global $wpdb;

		$table = Data_Store::table( 'clients' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT client_id, client_secret, client_id_issued_at, client_secret_expires_at, registration_access_token, registration_client_uri, metadata FROM ' . $table . ' WHERE client_id = %s LIMIT 1',
				$client_id
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

		if ( ! is_array( $row ) ) {
			return null;
		}

		$metadata = json_decode( $row['metadata'], true );
		if ( ! is_array( $metadata ) ) {
			$metadata = array();
		}

		return array(
			'client_id'                 => (string) $row['client_id'],
			'client_secret'             => (string) $row['client_secret'],
			'client_id_issued_at'       => (int) $row['client_id_issued_at'],
			'client_secret_expires_at'  => (int) $row['client_secret_expires_at'],
			'registration_access_token' => (string) $row['registration_access_token'],
			'registration_client_uri'   => (string) $row['registration_client_uri'],
			'metadata'                  => $metadata,
		);
	}

	private function save_registered_client( $client ) {
		global $wpdb;

		$table = Data_Store::table( 'clients' );
		$now   = gmdate( 'Y-m-d H:i:s' );

		$existing = $this->get_registered_client( $client['client_id'] );
		$created  = $now;

		if ( is_array( $existing ) && ! empty( $existing['client_id_issued_at'] ) ) {
			$created = gmdate( 'Y-m-d H:i:s', (int) $existing['client_id_issued_at'] );
		}

		$wpdb->replace(
			$table,
			array(
				'client_id'                 => (string) $client['client_id'],
				'client_secret'             => (string) $client['client_secret'],
				'client_id_issued_at'       => (int) $client['client_id_issued_at'],
				'client_secret_expires_at'  => (int) $client['client_secret_expires_at'],
				'registration_access_token' => (string) $client['registration_access_token'],
				'registration_client_uri'   => (string) $client['registration_client_uri'],
				'metadata'                  => wp_json_encode( $client['metadata'] ),
				'created_at'                => $created,
				'updated_at'                => $now,
			),
			array( '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	private function delete_registered_client( $client_id ) {
		global $wpdb;

		$table = Data_Store::table( 'clients' );
		$wpdb->delete(
			$table,
			array( 'client_id' => (string) $client_id ),
			array( '%s' )
		);
	}

	/**
	 * Extract registration access token from Authorization header or request params.
	 *
	 * @param \WP_REST_Request $request REST request.
	 * @return string
	 */
	private function extract_registration_access_token( $request ) {
		$auth = $request->get_header( 'authorization' );
		if ( is_string( $auth ) && '' !== trim( $auth ) ) {
			$auth = trim( $auth );
			if ( preg_match( '/^Bearer\s+(.+)$/i', $auth, $m ) ) {
				// Keep only the bearer token before any optional auth-params.
				$token = trim( $m[1] );
				$comma = strpos( $token, ',' );
				if ( false !== $comma ) {
					$token = substr( $token, 0, $comma );
				}

				return trim( $token, " \t\n\r\0\x0B\"'" );
			}
		}

		$fallback = $request->get_param( 'registration_access_token' );
		if ( is_string( $fallback ) ) {
			return trim( $fallback );
		}

		return '';
	}

	private function generate_client_id() {
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( \Exception $e ) {
			return uniqid( 'c_', true );
		}
	}

	private function generate_client_secret() {
		try {
			return bin2hex( random_bytes( 24 ) );
		} catch ( \Exception $e ) {
			return wp_generate_password( 40, false, false );
		}
	}

	private function generate_registration_access_token() {
		try {
			return bin2hex( random_bytes( 24 ) );
		} catch ( \Exception $e ) {
			return wp_generate_password( 48, false, false );
		}
	}
}
