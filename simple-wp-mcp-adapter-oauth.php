<?php
/**
 * Plugin Name: Simple WP MCP Adapter OAuth
 * Plugin URI: https://samuelsena.blog
 * Description: Adds OAuth 2.1 authorization server support for the WordPress MCP Adapter plugin.
 * Version: 1.0.0
 * Author: Samuel Sena
 * Author URI: https://samuelsena.blog
 * Requires at least: 6.8
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: simple-wp-mcp-adapter-oauth
 */

use WP\MCP\Core\McpAdapter;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use GuzzleHttp\Psr7\ServerRequest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Load Composer autoloader if it exists.
if ( file_exists( __DIR__ . '/vendor/autoload_packages.php' ) ) {
	require_once __DIR__ . '/vendor/autoload_packages.php';
}

/**
 * Initialize the plugin.
 */
function simple_wpmcp_adapter_oauth_init() {
	if ( ! class_exists( McpAdapter::class ) ) {
		add_action( 'admin_notices', 'simple_wpmcp_adapter_oauth_missing_notice' );
		return;
	}

	if ( ! extension_loaded( 'openssl' ) ) {
		add_action( 'admin_notices', 'simple_wpmcp_adapter_oauth_openssl_missing_notice' );
		return;
	}

	if ( ! simple_wpmcp_adapter_oauth_has_oauth_dependencies() ) {
		add_action( 'admin_notices', 'simple_wpmcp_adapter_oauth_missing_oauth_libs_notice' );
		return;
	}

	if ( ! simple_wpmcp_adapter_oauth_ensure_keys() ) {
		add_action( 'admin_notices', 'simple_wpmcp_adapter_oauth_keys_error_notice' );
		return;
	}

	simple_wpmcp_adapter_oauth_install_database_tables();

	// Root class for the Adapter.
	require_once __DIR__ . '/includes/class-adapter.php';

	// Initialize the adapter.
	McpAdapter::instance();
	SimpleWpMcpAdapterOAuth\Adapter::get_instance();
}
add_action( 'plugins_loaded', 'simple_wpmcp_adapter_oauth_init' );

/**
 * Admin notice for missing McpAdapter.
 */
function simple_wpmcp_adapter_oauth_missing_notice() {
	?>
	<div class="notice notice-error">
		<p><?php esc_html_e( 'WP Simple MCP Adapter OAuth requires the MCP Adapter plugin. Please install and activate it to use this plugin.', 'simple-wp-mcp-adapter-oauth' ); ?></p>
	</div>
	<?php
}

/**
 * Admin notice for missing OpenSSL extension.
 */
function simple_wpmcp_adapter_oauth_openssl_missing_notice() {
	?>
	<div class="notice notice-error">
		<p><?php esc_html_e( 'WP Simple MCP Adapter OAuth requires the OpenSSL PHP extension. Please enable it to use this plugin.', 'simple-wp-mcp-adapter-oauth' ); ?></p>
	</div>
	<?php
}

/**
 * Admin notice for missing OAuth package dependencies.
 */
function simple_wpmcp_adapter_oauth_missing_oauth_libs_notice() {
	?>
	<div class="notice notice-error">
		<p><?php esc_html_e( 'WP Simple MCP Adapter OAuth requires league/oauth2-server and guzzlehttp/psr7. Run composer install in this plugin directory.', 'simple-wp-mcp-adapter-oauth' ); ?></p>
	</div>
	<?php
}

/**
 * Admin notice when key generation fails.
 */
function simple_wpmcp_adapter_oauth_keys_error_notice() {
	?>
	<div class="notice notice-error">
		<p><?php esc_html_e( 'WP Simple MCP Adapter OAuth could not initialize signing keys in uploads/simple-wp-mcp-adapter-oauth-keys.', 'simple-wp-mcp-adapter-oauth' ); ?></p>
	</div>
	<?php
}

/**
 * Activation hook.
 */
register_activation_hook( __FILE__, 'simple_wpmcp_adapter_oauth_activate' );
function simple_wpmcp_adapter_oauth_activate() {
	if ( ! class_exists( McpAdapter::class ) ) {
		wp_die( esc_html__( 'WP Simple MCP Adapter OAuth requires the MCP Adapter plugin. Please install and activate it to activate this plugin.', 'simple-wp-mcp-adapter-oauth' ) );
	}

	if ( ! extension_loaded( 'openssl' ) ) {
		wp_die( esc_html__( 'WP Simple MCP Adapter OAuth requires the OpenSSL PHP extension. Please enable it to activate this plugin.', 'simple-wp-mcp-adapter-oauth' ) );
	}

	if ( ! simple_wpmcp_adapter_oauth_has_oauth_dependencies() ) {
		wp_die( esc_html__( 'WP Simple MCP Adapter OAuth is missing dependencies. Run composer install in this plugin directory before activation.', 'simple-wp-mcp-adapter-oauth' ) );
	}

	if ( ! simple_wpmcp_adapter_oauth_ensure_keys() ) {
		wp_die( esc_html__( 'WP Simple MCP Adapter OAuth could not create signing keys in uploads/simple-wp-mcp-adapter-oauth-keys.', 'simple-wp-mcp-adapter-oauth' ) );
	}

	simple_wpmcp_adapter_oauth_install_database_tables();
}

/**
 * Install OAuth database tables.
 *
 * @return void
 */
function simple_wpmcp_adapter_oauth_install_database_tables() {
	require_once __DIR__ . '/includes/OAuth/class-data-store.php';
	\SimpleWpMcpAdapterOAuth\OAuth\Data_Store::create_tables();
}

/**
 * Verify OAuth dependencies are available.
 *
 * @return bool
 */
function simple_wpmcp_adapter_oauth_has_oauth_dependencies() {
	return class_exists( AuthorizationServer::class )
		&& interface_exists( ClientRepositoryInterface::class )
		&& class_exists( ServerRequest::class );
}

/**
 * Ensure OAuth signing keys exist and are protected.
 *
 * @return bool
 */
function simple_wpmcp_adapter_oauth_ensure_keys() {
	$upload_dir = wp_upload_dir();
	$keys_dir   = $upload_dir['basedir'] . '/simple-wp-mcp-adapter-oauth-keys';

	if ( ! file_exists( $keys_dir ) && ! wp_mkdir_p( $keys_dir ) ) {
		return false;
	}

	$htaccess = $keys_dir . '/.htaccess';
	if ( ! file_exists( $htaccess ) ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $htaccess, "Deny from all\n" ) ) {
			return false;
		}
	}

	$private_key_path = $keys_dir . '/private.key';
	$public_key_path  = $keys_dir . '/public.key';

	if ( file_exists( $private_key_path ) && file_exists( $public_key_path ) ) {
		simple_wpmcp_adapter_oauth_harden_key_permissions( $private_key_path, $public_key_path );
		return true;
	}

	$config = array(
		'digest_alg'       => 'sha256',
		'private_key_bits' => 2048,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
	);

	$res = openssl_pkey_new( $config );
	if ( false === $res ) {
		return false;
	}

	$private_key = '';
	if ( ! openssl_pkey_export( $res, $private_key ) ) {
		return false;
	}

	$public_key_details = openssl_pkey_get_details( $res );
	if ( ! is_array( $public_key_details ) || empty( $public_key_details['key'] ) ) {
		return false;
	}

	$public_key = $public_key_details['key'];

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	if ( false === file_put_contents( $private_key_path, $private_key ) ) {
		return false;
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	if ( false === file_put_contents( $public_key_path, $public_key ) ) {
		return false;
	}

	simple_wpmcp_adapter_oauth_harden_key_permissions( $private_key_path, $public_key_path );

	return true;
}

/**
 * Enforce secure permissions for OAuth key files.
 *
 * @param string $private_key_path Path to private key file.
 * @param string $public_key_path  Path to public key file.
 * @return void
 */
function simple_wpmcp_adapter_oauth_harden_key_permissions( $private_key_path, $public_key_path ) {
	if ( 0 === strpos( PHP_OS, 'WIN' ) ) {
		return;
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
	chmod( $private_key_path, 0600 );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
	chmod( $public_key_path, 0600 );
}
