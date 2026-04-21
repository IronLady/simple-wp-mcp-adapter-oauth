<?php
namespace SimpleWpMcpAdapterOAuth\OAuth\Endpoints;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use GuzzleHttp\Psr7\Response;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Authorize_Endpoint extends Base_Endpoint {

	/**
	 * OAuth Server instance.
	 *
	 * @var AuthorizationServer
	 */
	private $server;

	/**
	 * Constructor.
	 *
	 * @param AuthorizationServer $server The OAuth server.
	 */
	public function __construct( AuthorizationServer $server ) {
		$this->server = $server;
	}

	/**
	 * Handles the authorization request.
	 *
	 * @param \WP_REST_Request|null $request Optional REST request.
	 */
	public function handle_request( $request = null ) {
		$psr_request = ( $request instanceof \WP_REST_Request )
			? $this->convert_to_psr_request( $request )
			: $this->create_psr_request_from_globals();

		if ( ! is_user_logged_in() ) {
			// Redirect cleanly to login, bringing them right back here afterward.
			$current_url = $this->get_current_url();
			$login_url   = wp_login_url( $current_url );
			wp_safe_redirect( $login_url );
			exit;
		}

		try {
			$auth_request = $this->server->validateAuthorizationRequest( $psr_request );

			// Check if a form submission occurred.
			if ( empty( $_POST['approval_action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$this->show_consent_screen( $auth_request );
				exit;
			}

			// Verify Nonce.
			if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'oauth2_consent' ) ) {
				wp_die( esc_html__( 'Security check failed', 'simple-wp-mcp-adapter-oauth' ) );
			}

			$user = wp_get_current_user();
			$auth_request->setUser( new \SimpleWpMcpAdapterOAuth\OAuth\Entities\UserEntity( $user->ID ) );

			// Process explicitly Approve or Deny.
			$is_approved = ( 'approve' === sanitize_text_field( wp_unslash( $_POST['approval_action'] ) ) );
			$auth_request->setAuthorizationApproved( $is_approved );

			$response = $this->server->completeAuthorizationRequest( $auth_request, new Response() );
			$this->send_psr_response( $response );

		} catch ( OAuthServerException $exception ) {
			$response = $exception->generateHttpResponse( new Response() );
			$this->send_psr_response( $response );
		} catch ( \Exception $exception ) {
			error_log( 'OAuth authorize endpoint error: ' . $exception->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			wp_die( esc_html__( 'An unexpected error occurred while processing authorization.', 'simple-wp-mcp-adapter-oauth' ) );
		}
	}

	/**
	 * Shows the consent screen.
	 *
	 * @param \League\OAuth2\Server\RequestTypes\AuthorizationRequest $auth_request The authorization request.
	 */
	private function show_consent_screen( $auth_request ) {
		// IMPORTANT: We MUST preserve all OAuth parameters in the query string so that
		// validateAuthorizationRequest() succeeds when processing the POST submission.
		$form_action_url = $this->get_current_url();
		$client_name     = esc_html( $auth_request->getClient()->getName() );
		$current_user    = wp_get_current_user();
		$scopes          = $auth_request->getScopes();

		wp_enqueue_style( 'login' );
		wp_enqueue_style(
			'mcp-oauth-consent',
			plugin_dir_url( SIMPLE_WP_MCP_ADAPTER_OAUTH_FILE ) . 'assets/css/consent-screen.css',
			array( 'login' ),
			SIMPLE_WP_MCP_ADAPTER_OAUTH_VERSION
		);
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php esc_html_e( 'Authorize Access', 'simple-wp-mcp-adapter-oauth' ); ?> &lsaquo; <?php bloginfo( 'name' ); ?></title>
		<?php wp_print_styles( array( 'login', 'mcp-oauth-consent' ) ); ?>
</head>
<body class="login">
<div id="login">
		<?php
		$logo_url = function_exists( 'get_custom_logo' ) ? get_site_url() : 'https://wordpress.org/';
		?>
	<h1><a href="<?php echo esc_url( $logo_url ); ?>"><?php bloginfo( 'name' ); ?></a></h1>

	<div class="mcp-oauth-card">
		<h1><?php echo esc_html( $client_name ); ?></h1>
		<p class="mcp-oauth-meta">
			<?php
			/* translators: %s: WordPress username */
			printf( esc_html__( 'Signed in as %s', 'simple-wp-mcp-adapter-oauth' ), '<strong>' . esc_html( $current_user->user_login ) . '</strong>' );
			?>
		</p>

		<?php if ( ! empty( $scopes ) ) : ?>
		<p style="font-size:13px;color:#1d2327;margin-bottom:8px;">
			<?php esc_html_e( 'This application is requesting permission to:', 'simple-wp-mcp-adapter-oauth' ); ?>
		</p>
		<ul class="mcp-oauth-scopes">
			<?php foreach ( $scopes as $scope ) : ?>
			<li><?php echo esc_html( $scope->getIdentifier() ); ?></li>
			<?php endforeach; ?>
		</ul>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( $form_action_url ); ?>">
			<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'oauth2_consent' ) ); ?>">
			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			foreach ( $_GET as $key => $value ) {
				if ( is_scalar( $value ) ) {
					echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( wp_unslash( $value ) ) . '">';
				}
			}
			?>
			<div class="mcp-oauth-actions">
				<button type="submit" name="approval_action" value="approve" class="button button-primary">
					<?php esc_html_e( 'Approve', 'simple-wp-mcp-adapter-oauth' ); ?>
				</button>
				<button type="submit" name="approval_action" value="deny" class="button">
					<?php esc_html_e( 'Deny', 'simple-wp-mcp-adapter-oauth' ); ?>
				</button>
			</div>
		</form>
	</div>

	<p class="privacy-policy-page-link" style="text-align:center;margin-top:16px;">
		<?php bloginfo( 'name' ); ?>
	</p>
</div>
</body>
</html>
		<?php
	}

	/**
	 * Build current request URL for redirects and form actions.
	 *
	 * @return string
	 */
	private function get_current_url() {
		$scheme = is_ssl() ? 'https://' : 'http://';
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
		// Keep the raw URI so percent-encoded OAuth params (for example redirect_uri) are not mangled.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';

		return $scheme . $host . $uri;
	}
}
