<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\RefreshTokenEntity;
use SimpleWpMcpAdapterOAuth\OAuth\Data_Store;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface {

	/**
	 * Create a new refresh token entity.
	 *
	 * @return RefreshTokenEntityInterface
	 */
	public function getNewRefreshToken() {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		return new RefreshTokenEntity();
	}

	/**
	 * Persist a newly issued refresh token.
	 *
	 * @param RefreshTokenEntityInterface $refresh_token_entity Refresh token.
	 * @return void
	 */
	public function persistNewRefreshToken( RefreshTokenEntityInterface $refresh_token_entity ) {
		global $wpdb;

		$table           = Data_Store::table( 'refresh_tokens' );
		$token_id        = $refresh_token_entity->getIdentifier();
		$access_token_id = $refresh_token_entity->getAccessToken()->getIdentifier();
		$expiry          = gmdate( 'Y-m-d H:i:s', $refresh_token_entity->getExpiryDateTime()->getTimestamp() );
		$user_id         = $refresh_token_entity->getAccessToken()->getUserIdentifier();
		$client_id       = $refresh_token_entity->getAccessToken()->getClient()->getIdentifier();

		$wpdb->replace(
			$table,
			array(
				'token_id'        => $token_id,
				'access_token_id' => $access_token_id,
				'user_id'         => $user_id ? (int) $user_id : 0,
				'client_id'       => $client_id,
				'expires_at'      => $expiry,
				'revoked'         => 0,
				'created_at'      => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%d', '%s', '%s', '%d', '%s' )
		);
	}

	/**
	 * Revoke refresh token by ID.
	 *
	 * @param string $token_id Token identifier.
	 * @return void
	 */
	public function revokeRefreshToken( $token_id ) {
		global $wpdb;

		$table = Data_Store::table( 'refresh_tokens' );
		$wpdb->update(
			$table,
			array( 'revoked' => 1 ),
			array( 'token_id' => (string) $token_id ),
			array( '%d' ),
			array( '%s' )
		);
	}

	/**
	 * Determine whether refresh token is revoked/expired.
	 *
	 * @param string $token_id Token identifier.
	 * @return bool
	 */
	public function isRefreshTokenRevoked( $token_id ) {
		global $wpdb;

		$table = Data_Store::table( 'refresh_tokens' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT revoked, expires_at FROM ' . $table . ' WHERE token_id = %s LIMIT 1',
				$token_id
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
