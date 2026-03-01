<?php
namespace SimpleWpMcpAdapterOAuth\OAuth;

use WP\MCP\Core\McpAdapter;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\ClientRepository;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\AccessTokenRepository;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\AuthCodeRepository;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\RefreshTokenRepository;
use SimpleWpMcpAdapterOAuth\OAuth\Repositories\ScopeRepository;
use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use GuzzleHttp\Psr7\ServerRequest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST API Handler.
 */
class REST_API {

	private static $instance = null;
	private $server;
	/**
	 * Resource Server.
	 *
	 * @var ResourceServer
	 */
	private $resource_server;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_filter( 'determine_current_user', array( $this, 'authenticate_request' ), 15 );
		add_action( 'admin_post_simple_mcp_oauth_authorize', array( $this, 'handle_authorize_admin_post' ) );
		add_action( 'admin_post_nopriv_simple_mcp_oauth_authorize', array( $this, 'handle_authorize_admin_post' ) );
		$this->setup_server();
	}

	private function setup_server() {
		$client_repository        = new ClientRepository();
		$access_token_repository  = new AccessTokenRepository();
		$scope_repository         = new ScopeRepository();
		$auth_code_repository     = new AuthCodeRepository();
		$refresh_token_repository = new RefreshTokenRepository();

		// Get keys from file system.
		$upload_dir  = wp_upload_dir();
		$keys_dir    = $upload_dir['basedir'] . '/simple-wp-mcp-adapter-oauth-keys';
		$private_key = 'file://' . $keys_dir . '/private.key';
		$public_key  = 'file://' . $keys_dir . '/public.key';

		$this->server = new AuthorizationServer(
			$client_repository,
			$access_token_repository,
			$scope_repository,
			$private_key,
			$public_key
		);

		// Authorization Code Grant.
		$auth_code_grant = new AuthCodeGrant(
			$auth_code_repository,
			$refresh_token_repository,
			new \DateInterval( 'PT10M' )
		);
		$auth_code_grant->setRefreshTokenTTL( new \DateInterval( 'P1M' ) );

		$this->server->enableGrantType(
			$auth_code_grant,
			new \DateInterval( 'PT1H' )
		);

		// Refresh Token Grant.
		$refresh_token_grant = new RefreshTokenGrant( $refresh_token_repository );
		$refresh_token_grant->setRefreshTokenTTL( new \DateInterval( 'P1M' ) );

		$this->server->enableGrantType(
			$refresh_token_grant,
			new \DateInterval( 'PT1H' )
		);

		// Client Credentials Grant.
		$this->server->enableGrantType(
			new ClientCredentialsGrant(),
			new \DateInterval( 'PT1H' )
		);

		$this->resource_server = new ResourceServer(
			$access_token_repository,
			$public_key
		);
	}

	public function get_server() {
		return $this->server;
	}

	/**
	 * Authenticate the request.
	 *
	 * @param int|bool $user_id Current user ID.
	 * @return int|bool
	 */
	public function authenticate_request( $user_id ) {
		// If we already have a user, don't override.
		if ( ! empty( $user_id ) ) {
			return $user_id;
		}

		// Only attempt OAuth auth for this plugin's MCP routes.
		if ( ! $this->is_mcp_oauth_request() ) {
			return $user_id;
		}

		$authorization_header = $this->get_authorization_header();
		if ( '' === $authorization_header || 0 !== stripos( $authorization_header, 'Bearer ' ) ) {
			return $user_id;
		}

		try {
			$psr_request = $this->get_psr_request();
			$psr_request = $this->resource_server->validateAuthenticatedRequest( $psr_request );

			$wp_user_id = $psr_request->getAttribute( 'oauth_user_id' );
			if ( $wp_user_id ) {
				return $wp_user_id;
			}

			return $user_id;
		} catch ( OAuthServerException $exception ) {
			return $user_id;
		} catch ( \Exception $exception ) {
			return $user_id;
		}
	}

	public function register_routes() {
		$token_endpoint     = new Endpoints\Token_Endpoint( $this->server );
		$jwks_endpoint      = new Endpoints\JWKS_Endpoint();
		$discovery_endpoint = new Endpoints\Discovery_Endpoint();
		$register_endpoint  = new Endpoints\Register_Endpoint();

		foreach ( $this->get_oauth_server_routes() as $oauth_server_route ) {
			$namespace = $oauth_server_route['namespace'];
			$base      = '/' . $oauth_server_route['server_route'];

				register_rest_route(
					$namespace,
					$base . '/token',
					array(
						'methods'             => 'POST',
						'callback'            => array( $token_endpoint, 'handle_request' ),
						'permission_callback' => '__return_true',
					)
				);

			register_rest_route(
				$namespace,
				$base . '/.well-known/jwks.json',
				array(
					'methods'             => 'GET',
					'callback'            => array( $jwks_endpoint, 'handle_request' ),
					'permission_callback' => '__return_true',
				)
			);

			register_rest_route(
				$namespace,
				$base . '/.well-known/oauth-authorization-server',
				array(
					'methods'             => 'GET',
					'callback'            => array( $discovery_endpoint, 'handle_request' ),
					'permission_callback' => '__return_true',
				)
			);

			// RFC 7591 Dynamic Client Registration
			register_rest_route(
				$namespace,
				$base . '/register',
				array(
					'methods'             => 'POST',
					'callback'            => array( $register_endpoint, 'handle_create' ),
					'permission_callback' => '__return_true',
				)
			);

			register_rest_route(
				$namespace,
				$base . '/register/(?P<client_id>[a-zA-Z0-9_-]+)',
				array(
					'methods'             => array( 'GET', 'PUT', 'DELETE' ),
					'callback'            => array( $register_endpoint, 'handle_manage' ),
					'permission_callback' => '__return_true',
				)
			);
		}
	}

	/**
	 * Handle OAuth authorize screen via wp-admin/admin-post.php.
	 *
	 * @return void
	 */
	public function handle_authorize_admin_post() {
		$authorize_endpoint = new Endpoints\Authorize_Endpoint( $this->server );
		$authorize_endpoint->handle_request();
	}

	/**
	 * Create a PSR-7 request from globals.
	 *
	 * @return ServerRequest
	 */
	private function get_psr_request() {
		$headers = $this->get_request_headers();

		if ( ! isset( $headers['Authorization'] ) && isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$headers['Authorization'] = sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		}

		$request = new ServerRequest(
			isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET',
			isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/',
			$headers,
			null,
			'1.1',
			$_SERVER
		);

		return $request;
	}

	/**
	 * Build request headers from server globals.
	 *
	 * @return array<string, string>
	 */
	private function get_request_headers() {
		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			if ( is_array( $headers ) ) {
				return $headers;
			}
		}

		$headers = array();
		foreach ( $_SERVER as $name => $value ) {
			if ( 0 !== strpos( $name, 'HTTP_' ) || ! is_string( $value ) ) {
				continue;
			}

			$header_name             = str_replace( '_', '-', substr( $name, 5 ) );
			$headers[ $header_name ] = sanitize_text_field( wp_unslash( $value ) );
		}

		return $headers;
	}

	/**
	 * Get authorization header from request headers.
	 *
	 * @return string
	 */
	private function get_authorization_header() {
		$headers = $this->get_request_headers();

		if ( isset( $headers['Authorization'] ) && is_string( $headers['Authorization'] ) ) {
			return $headers['Authorization'];
		}

		if ( isset( $headers['authorization'] ) && is_string( $headers['authorization'] ) ) {
			return $headers['authorization'];
		}

		// Server-dependent fallback used by some hosts/proxies.
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) && is_string( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		}

		if ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) && is_string( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) );
		}

		return '';
	}

	/**
	 * Determine whether current request targets an MCP OAuth-protected route.
	 *
	 * @return bool
	 */
	private function is_mcp_oauth_request() {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) || ! is_string( $_SERVER['REQUEST_URI'] ) ) {
			return false;
		}

		$request_uri  = wp_unslash( $_SERVER['REQUEST_URI'] );
		$request_path = wp_parse_url( $request_uri, PHP_URL_PATH );

		if ( ! is_string( $request_path ) || '' === $request_path ) {
			return false;
		}

		$rest_prefix     = '/' . rest_get_url_prefix() . '/';
		$rest_prefix_pos = strpos( $request_path, $rest_prefix );
		if ( false === $rest_prefix_pos ) {
			return false;
		}

		$rest_route = ltrim( substr( $request_path, $rest_prefix_pos + strlen( $rest_prefix ) ), '/' );
		if ( '' === $rest_route ) {
			return false;
		}

		foreach ( $this->get_oauth_server_routes( false ) as $oauth_server_route ) {
			$base_route = trim( $oauth_server_route['namespace'], '/' ) . '/' . trim( $oauth_server_route['server_route'], '/' );

			if ( $rest_route === $base_route || 0 === strpos( $rest_route, $base_route . '/' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get MCP routes that have OAuth transport enabled.
	 *
	 * @param bool $require_metadata_route Whether to require oauth-protected-resource route presence.
	 *
	 * @return array<int, array<string, string>>
	 */
	private function get_oauth_server_routes( $require_metadata_route = true ) {
		$adapter = McpAdapter::instance();
		$servers = $adapter->get_servers();
		$result  = array();

		if ( ! $require_metadata_route ) {
			foreach ( $servers as $server ) {
				$result[] = array(
					'namespace'    => $server->get_server_route_namespace(),
					'server_route' => $server->get_server_route(),
				);
			}

			return $result;
		}

		$routes = rest_get_server()->get_routes();

		foreach ( $servers as $server ) {
			$namespace      = $server->get_server_route_namespace();
			$server_route   = $server->get_server_route();
			$metadata_route = '/' . $namespace . '/' . $server_route . '/.well-known/oauth-protected-resource';

			// Metadata route only exists when OAuthTransport is used by the server.
			if ( ! isset( $routes[ $metadata_route ] ) ) {
				continue;
			}

				$result[] = array(
					'namespace'    => $namespace,
					'server_route' => $server_route,
				);
		}

		return $result;
	}
}
