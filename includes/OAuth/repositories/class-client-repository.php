<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\ClientEntity;
use SimpleWpMcpAdapterOAuth\OAuth\Data_Store;

class ClientRepository implements ClientRepositoryInterface {

	/**
	 * Retrieve client entity by identifier.
	 *
	 * @param string $client_identifier Client identifier.
	 * @return ClientEntity|null
	 */
	public function getClientEntity( $client_identifier ) {
		global $wpdb;

		$client_identifier = trim( (string) $client_identifier );
		$table             = Data_Store::table( 'clients' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT client_id, client_secret, metadata FROM ' . $table . ' WHERE client_id = %s LIMIT 1',
				$client_identifier
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

		$client = new ClientEntity();
		$client->setIdentifier( $client_identifier );

		$name = isset( $metadata['client_name'] ) ? $metadata['client_name'] : $client_identifier;
		$name = apply_filters( 'simple_wp_oauth21_client_name', $name, $client_identifier );
		$client->setName( $name );

		if ( isset( $metadata['redirect_uris'] ) && is_array( $metadata['redirect_uris'] ) ) {
			$client->setRedirectUri( $metadata['redirect_uris'] );
		}

		if ( ! empty( $row['client_secret'] ) ) {
			$client->setConfidential();
		}

		return $client;
	}

	/**
	 * Validate client credentials for a grant.
	 *
	 * @param string      $client_identifier Client identifier.
	 * @param string|null $client_secret Client secret.
	 * @param string|null $grant_type Grant type.
	 * @return bool
	 */
	public function validateClient( $client_identifier, $client_secret, $grant_type = null ) {
		global $wpdb;

		$client_identifier = trim( (string) $client_identifier );
		$table             = Data_Store::table( 'clients' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT client_secret FROM ' . $table . ' WHERE client_id = %s LIMIT 1',
				$client_identifier
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

		if ( ! is_array( $row ) ) {
			return false;
		}

		$stored_secret = isset( $row['client_secret'] ) ? (string) $row['client_secret'] : '';

		// Public clients do not authenticate with a secret.
		if ( '' === $stored_secret ) {
			return true;
		}

		if ( ! is_string( $client_secret ) || '' === $client_secret ) {
			return false;
		}

		// Support either plaintext or password_hash()-stored secrets.
		if ( 0 === strpos( $stored_secret, '$2y$' ) || 0 === strpos( $stored_secret, '$argon2' ) ) {
			return password_verify( $client_secret, $stored_secret );
		}

		return hash_equals( $stored_secret, (string) $client_secret );
	}
}
