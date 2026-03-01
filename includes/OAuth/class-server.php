<?php
namespace SimpleWpMcpAdapterOAuth\OAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main Server Class.
 */
class Server {

	/**
	 * Instance.
	 *
	 * @var Server|null
	 */
	private static $instance = null;

	/**
	 * Get instance.
	 *
	 * @return Server
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->includes();
		$this->init_rest_api();
	}

	/**
	 * Include module files.
	 *
	 * @return void
	 */
	private function includes() {
		require_once __DIR__ . '/class-data-store.php';

		// Endpoints
		require_once __DIR__ . '/endpoints/class-base-endpoint.php';
		require_once __DIR__ . '/endpoints/class-authorize-endpoint.php';
		require_once __DIR__ . '/endpoints/class-token-endpoint.php';
		require_once __DIR__ . '/endpoints/class-jwks-endpoint.php';
		require_once __DIR__ . '/endpoints/class-discovery-endpoint.php';
		require_once __DIR__ . '/endpoints/class-register-endpoint.php';

		require_once __DIR__ . '/class-rest-api.php';

		// Repositories
		require_once __DIR__ . '/repositories/class-client-repository.php';
		require_once __DIR__ . '/repositories/class-access-token-repository.php';
		require_once __DIR__ . '/repositories/class-auth-code-repository.php';
		require_once __DIR__ . '/repositories/class-refresh-token-repository.php';
		require_once __DIR__ . '/repositories/class-scope-repository.php';

		// Entities
		require_once __DIR__ . '/entities/class-client-entity.php';
		require_once __DIR__ . '/entities/class-access-token-entity.php';
		require_once __DIR__ . '/entities/class-auth-code-entity.php';
		require_once __DIR__ . '/entities/class-refresh-token-entity.php';
		require_once __DIR__ . '/entities/class-scope-entity.php';
		require_once __DIR__ . '/entities/class-user-entity.php';
	}

	/**
	 * Initialize REST API.
	 */
	private function init_rest_api() {
		REST_API::get_instance();
	}
}
