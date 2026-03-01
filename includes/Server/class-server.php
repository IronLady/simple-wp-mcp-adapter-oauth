<?php
namespace SimpleWpMcpAdapterOAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Simple server helper to override the default MCP server config.
 *
 * This class only hooks the `mcp_adapter_default_server_config` filter
 * and replaces the `mcp_transports` entry with the OAuth transport.
 */
class Server {

	/**
	 * Singleton instance.
	 *
	 * @var Server|null
	 */
	private static $instance = null;

	/**
	 * Initialize and register filter.
	 */
	private function __construct() {
		add_filter( 'mcp_adapter_default_server_config', array( $this, 'override_default_config' ) );
	}

	/**
	 * Get singleton instance.
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
	 * Replace default transports with the OAuth transport.
	 *
	 * @param array $wordpress_defaults Defaults passed from the factory.
	 * @return array Modified defaults.
	 */
	public function override_default_config( $wordpress_defaults ) {
		$wordpress_defaults['mcp_transports'] = array( OAuthTransport::class );
		return $wordpress_defaults;
	}
}
