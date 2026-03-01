<?php
namespace SimpleWpMcpAdapterOAuth\OAuth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Data_Store {

	/**
	 * Get a plugin table name.
	 *
	 * @param string $key Table key.
	 * @return string
	 */
	public static function table( $key ) {
		global $wpdb;

		$tables = array(
			'clients'        => $wpdb->prefix . 'simple_mcp_oauth_clients',
			'auth_codes'     => $wpdb->prefix . 'simple_mcp_oauth_auth_codes',
			'refresh_tokens' => $wpdb->prefix . 'simple_mcp_oauth_refresh_tokens',
		);

		return isset( $tables[ $key ] ) ? $tables[ $key ] : '';
	}

	/**
	 * Create or update OAuth storage tables.
	 *
	 * @return void
	 */
	public static function create_tables() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$clients         = self::table( 'clients' );
		$auth_codes      = self::table( 'auth_codes' );
		$refresh_tokens  = self::table( 'refresh_tokens' );

		$sql_clients = "CREATE TABLE {$clients} (
			client_id varchar(191) NOT NULL,
			client_secret varchar(255) NOT NULL DEFAULT '',
			client_id_issued_at bigint(20) unsigned NOT NULL DEFAULT 0,
			client_secret_expires_at bigint(20) unsigned NOT NULL DEFAULT 0,
			registration_access_token varchar(191) NOT NULL,
			registration_client_uri text NOT NULL,
			metadata longtext NOT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (client_id),
			KEY registration_access_token (registration_access_token)
		) {$charset_collate};";

		$sql_auth_codes = "CREATE TABLE {$auth_codes} (
			code_id varchar(191) NOT NULL,
			user_id bigint(20) unsigned DEFAULT NULL,
			client_id varchar(191) NOT NULL,
			scopes text NOT NULL,
			expires_at datetime NOT NULL,
			revoked tinyint(1) NOT NULL DEFAULT 0,
			created_at datetime NOT NULL,
			PRIMARY KEY  (code_id),
			KEY client_id (client_id),
			KEY user_id (user_id),
			KEY expires_at (expires_at),
			KEY revoked (revoked)
		) {$charset_collate};";

		$sql_refresh_tokens = "CREATE TABLE {$refresh_tokens} (
			token_id varchar(191) NOT NULL,
			access_token_id varchar(191) NOT NULL,
			user_id bigint(20) unsigned DEFAULT NULL,
			client_id varchar(191) NOT NULL,
			expires_at datetime NOT NULL,
			revoked tinyint(1) NOT NULL DEFAULT 0,
			created_at datetime NOT NULL,
			PRIMARY KEY  (token_id),
			KEY access_token_id (access_token_id),
			KEY client_id (client_id),
			KEY user_id (user_id),
			KEY expires_at (expires_at),
			KEY revoked (revoked)
		) {$charset_collate};";

		dbDelta( $sql_clients );
		dbDelta( $sql_auth_codes );
		dbDelta( $sql_refresh_tokens );
	}
}
