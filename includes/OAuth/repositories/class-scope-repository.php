<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface {

	/**
	 * Resolve scope entity by identifier.
	 *
	 * @param string $scope_identifier Scope identifier.
	 * @return ScopeEntity|null
	 */
	public function getScopeEntityByIdentifier( $scope_identifier ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		$scope = new ScopeEntity();
		$scope->setIdentifier( $scope_identifier );

		return $scope;
	}

	/**
	 * Finalize granted scopes.
	 *
	 * @param array<int, mixed>       $scopes Requested scopes.
	 * @param string                  $grant_type Grant type.
	 * @param ClientEntityInterface   $client_entity Client entity.
	 * @param int|string|null         $user_identifier User identifier.
	 * @return array<int, mixed>
	 */
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
