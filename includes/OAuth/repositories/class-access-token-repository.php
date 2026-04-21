<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\AccessTokenEntity;
use SimpleWpMcpAdapterOAuth\OAuth\Data_Store;

class AccessTokenRepository implements AccessTokenRepositoryInterface {

	/**
	 * Create a new access token entity.
	 *
	 * @param ClientEntityInterface  $client_entity Client entity.
	 * @param array<int, mixed>      $scopes Token scopes.
	 * @param int|string|null        $user_identifier User identifier.
	 * @return AccessTokenEntityInterface
	 */
	public function getNewToken( ClientEntityInterface $client_entity, array $scopes, $user_identifier = null ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		$access_token = new AccessTokenEntity();
		$access_token->setClient( $client_entity );
		foreach ( $scopes as $scope ) {
			$access_token->addScope( $scope );
		}
		$access_token->setUserIdentifier( $user_identifier );
		return $access_token;
	}

	/**
	 * Persist newly issued access token.
	 *
	 * @param AccessTokenEntityInterface $access_token_entity Access token.
	 * @return void
	 */
	public function persistNewAccessToken( AccessTokenEntityInterface $access_token_entity ) {
		// Access tokens are self-contained JWTs; no persistence required.
	}

	/**
	 * Revoke an access token by adding its JTI to the blocklist.
	 *
	 * @param string $token_id Token identifier (JWT ID / jti claim).
	 * @return void
	 */
	public function revokeAccessToken( $token_id ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		global $wpdb;

		$table = Data_Store::table( 'revoked_access_tokens' );
		$wpdb->replace(
			$table,
			array(
				'token_id'   => (string) $token_id,
				'revoked_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s' )
		);

		// Prune entries older than the maximum access token lifetime (1 hour).
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
				'DELETE FROM ' . $table . ' WHERE revoked_at < %s',
				gmdate( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS )
			)
		);
	}

	/**
	 * Check whether an access token has been revoked.
	 *
	 * @param string $token_id Token identifier (JWT ID / jti claim).
	 * @return bool
	 */
	public function isAccessTokenRevoked( $token_id ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		global $wpdb;

		$table = Data_Store::table( 'revoked_access_tokens' );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Table name is from internal Data_Store::table() mapping.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $table . ' WHERE token_id = %s',
				$token_id
			)
		);

		return (int) $count > 0;
	}
}
