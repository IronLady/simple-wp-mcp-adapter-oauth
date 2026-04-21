<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Repositories;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use SimpleWpMcpAdapterOAuth\OAuth\Entities\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface {

	/**
	 * Scopes this server recognizes.
	 *
	 * Extendable via the `simple_wp_mcp_oauth_allowed_scopes` filter.
	 */
	const ALLOWED_SCOPES = array( 'profile', 'email' );

	/**
	 * Resolve scope entity by identifier, or null if the scope is not allowed.
	 *
	 * @param string $scope_identifier Scope identifier.
	 * @return ScopeEntity|null
	 */
	public function getScopeEntityByIdentifier( $scope_identifier ) {
		// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		$allowed = apply_filters( 'simple_wp_mcp_oauth_allowed_scopes', self::ALLOWED_SCOPES );

		if ( ! in_array( $scope_identifier, $allowed, true ) ) {
			return null;
		}

		$scope = new ScopeEntity();
		$scope->setIdentifier( $scope_identifier );

		return $scope;
	}

	/**
	 * Finalize granted scopes, stripping any not in the allowed list.
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
		$allowed = apply_filters( 'simple_wp_mcp_oauth_allowed_scopes', self::ALLOWED_SCOPES );

		return array_values(
			array_filter(
				$scopes,
				function ( $scope ) use ( $allowed ) {
					return in_array( $scope->getIdentifier(), $allowed, true );
				}
			)
		);
	}
}
