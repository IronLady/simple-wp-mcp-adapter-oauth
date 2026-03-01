<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\AccessTokenEntity;

class AccessTokenRepository implements AccessTokenRepositoryInterface {

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

	public function persistNewAccessToken( AccessTokenEntityInterface $access_token_entity ) {
		// Access tokens are self-contained JWTs; no persistence required.
	}

	public function revokeAccessToken( $token_id ) {
		// Access token revocation is not tracked server-side in this simplified flow.
	}

	public function isAccessTokenRevoked( $token_id ) {
		return false;
	}
}
