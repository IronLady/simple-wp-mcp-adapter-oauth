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
		?>
<div
	style="max-width: 500px; margin: 50px auto; font-family: sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
	<h1>
		<?php esc_html_e( 'Authorize Access', 'simple-wp-mcp-adapter-oauth' ); ?>
	</h1>
	<p>
		<?php
		/* translators: %s: Client Name */
		echo wp_kses_post( sprintf( __( 'The application <strong>%s</strong> is requesting access to your account.', 'simple-wp-mcp-adapter-oauth' ), esc_html( $auth_request->getClient()->getName() ) ) );
		?>
	</p>
	<hr>

	<form method="post" action="<?php echo esc_url( $form_action_url ); ?>">
		<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'oauth2_consent' ) ); ?>">

		<?php
		// Also pass them as hidden fields for good measure/standard form handling.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( $_GET as $key => $value ) {
			if ( is_scalar( $value ) ) {
				echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( wp_unslash( $value ) ) . '">';
			}
		}
		?>

		<div style="display: flex; gap: 10px; margin-top: 20px;">
			<button type="submit" name="approval_action" value="approve"
				style="background: #2271b1; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; font-size: 16px;">
				<?php esc_html_e( 'Approve', 'simple-wp-mcp-adapter-oauth' ); ?>
			</button>
			<button type="submit" name="approval_action" value="deny"
				style="background: #f6f7f7; color: #d63638; padding: 10px 20px; border: 1px solid #d63638; cursor: pointer; border-radius: 4px; font-size: 16px;">
				<?php esc_html_e( 'Deny', 'simple-wp-mcp-adapter-oauth' ); ?>
			</button>
		</div>
	</form>
</div>
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
