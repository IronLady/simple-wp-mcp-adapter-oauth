<?php
/**
 * Main adapter class.
 */
namespace SimpleWpMcpAdapterOAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Adapter {

	/**
	 * Instance.
	 *
	 * @var Adapter|null
	 */
	private static $instance = null;

	/**
	 * Get instance.
	 *
	 * @return Adapter
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
		$this->init_server();
		$this->init_oauth_server();
	}

	/**
	 * Include necessary files.
	 */
	private function includes() {
		// Transport
		require_once __DIR__ . '/Transport/class-oauth-transport.php';

		// Server
		require_once __DIR__ . '/Server/class-server.php';

		// OAuth module
		require_once __DIR__ . '/OAuth/class-server.php';
	}

	/**
	 * Initialize Server.
	 */
	private function init_server() {
		Server::get_instance();
	}

	/**
	 * Initialize OAuth module.
	 *
	 * @return void
	 */
	private function init_oauth_server() {
		OAuth\Server::get_instance();
	}
}
