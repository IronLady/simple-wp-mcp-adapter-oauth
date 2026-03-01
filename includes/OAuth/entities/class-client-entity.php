<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Entities;

use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface {

	use ClientTrait;
	use EntityTrait;

	/**
	 * Set client display name.
	 *
	 * @param string $name Client name.
	 * @return void
	 */
	public function setName( $name ) {
		$this->name = $name;
	}

	/**
	 * Set client redirect URI/URIs.
	 *
	 * @param string|array<int, string> $uri Redirect URI or list.
	 * @return void
	 */
	public function setRedirectUri( $uri ) {
		$this->redirectUri = $uri; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
	}

	/**
	 * Mark client as confidential.
	 *
	 * @return void
	 */
	public function setConfidential() {
		$this->isConfidential = true; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
	}
}
