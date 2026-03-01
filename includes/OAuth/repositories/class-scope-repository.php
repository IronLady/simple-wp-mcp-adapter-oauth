<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface {

	public function getScopeEntityByIdentifier( $scope_identifier ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		$scope = new ScopeEntity();
		$scope->setIdentifier( $scope_identifier );

		return $scope;
	}

	public function finalizeScopes(
		array $scopes,
		$grant_type,
		ClientEntityInterface $client_entity,
		$user_identifier = null
	) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		// Just return the requested scopes for now.
		return $scopes;
	}
}
