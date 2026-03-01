<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\AuthCodeEntity;
use SimpleWpMcpAdapterOAuth\OAuth\Data_Store;

class AuthCodeRepository implements AuthCodeRepositoryInterface {

	public function getNewAuthCode() {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		return new AuthCodeEntity();
	}

	public function persistNewAuthCode( AuthCodeEntityInterface $auth_code_entity ) {
		global $wpdb;

		$table    = Data_Store::table( 'auth_codes' );
		$scopes   = array();
		$entities = $auth_code_entity->getScopes();

		foreach ( $entities as $scope ) {
			$scopes[] = $scope->getIdentifier();
		}

		$wpdb->replace(
			$table,
			array(
				'code_id'    => $auth_code_entity->getIdentifier(),
				'user_id'    => $auth_code_entity->getUserIdentifier() ? (int) $auth_code_entity->getUserIdentifier() : 0,
				'client_id'  => $auth_code_entity->getClient()->getIdentifier(),
				'scopes'     => wp_json_encode( $scopes ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', $auth_code_entity->getExpiryDateTime()->getTimestamp() ),
				'revoked'    => 0,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%d', '%s', '%s', '%s', '%d', '%s' )
		);
	}

	public function revokeAuthCode( $code_id ) {
		global $wpdb;

		$table = Data_Store::table( 'auth_codes' );
		$wpdb->update(
			$table,
			array( 'revoked' => 1 ),
			array( 'code_id' => (string) $code_id ),
			array( '%d' ),
			array( '%s' )
		);
	}

	public function isAuthCodeRevoked( $code_id ) {
		global $wpdb;

		$table = Data_Store::table( 'auth_codes' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT revoked, expires_at FROM ' . $table . ' WHERE code_id = %s LIMIT 1',
				$code_id
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared

		if ( ! is_array( $row ) ) {
			return true;
		}

		if ( ! empty( $row['revoked'] ) ) {
			return true;
		}

		$expiry_ts = strtotime( (string) $row['expires_at'] );
		if ( false === $expiry_ts ) {
			return true;
		}

		return $expiry_ts <= time();
	}
}
