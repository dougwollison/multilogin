<?php
/**
 * MultiLogin Backend Functionality
 *
 * @package MultiLogin
 * @subpackage Handlers
 *
 * @since 1.0.0
 */

namespace MultiLogin;

/**
 * The Backend Functionality
 *
 * Hooks into various backend systems to load
 * custom assets and add the editor interface.
 *
 * @internal Used by the System.
 *
 * @since 1.0.0
 */
final class System extends Handler {
	// =========================
	// ! Properties
	// =========================

	/**
	 * Record of added hooks.
	 *
	 * @internal Used by the Handler enable/disable methods.
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	protected static $implemented_hooks = array();

	// =========================
	// ! Utilities
	// =========================

	/**
	 * Generate a semi-unique ID for the visitor.
	 *
	 * Based on their IP address and User Agent.
	 *
	 * @since 1.0.0
	 *
	 * @return string The SHA1 encoded visitor ID.
	 */
	private static function visitor_id() {
		return sha1( $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . AUTH_SALT );
	}

	/**
	 * Test if remote login related actions should proceed.
	 *
	 * @since 1.0.0
	 *
	 * @param string $session_key Optional. Additionally check if a $_SESSION key exists.
	 */
	private static function should_do_remote_login( $session_key = null ) {
		// Skip if specified session key is present
		if ( $session_key && ! isset( $_SESSION[ $session_key ] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Generate a set of tokens.
	 *
	 * @since 1.0.0
	 *
	 * @param string  $type The type of tokens to generate ('login', 'logout').
	 * @param WP_User $user The user to generate tokens for.
	 * @param array   $data Optional. The data to store the secret with.
	 */
	private static function generate_tokens( $type, \WP_User $user, $data = array() ) {
		global $blog_id;

		// Check if we should proceed
		if ( ! self::should_do_remote_login() ) {
			return;
		}

		// Get the visitor ID
		$visitor_id = self::visitor_id();

		$tokens = array();

		// Loop through all sites the user belongs to
		$sites = get_blogs_of_user( $user->ID );
		foreach ( $sites as $site ) {
			// Skip for current blog
			if ( $site->userblog_id == $blog_id ) {
				continue;
			}

			// Generate a unique key and token
			$key = str_replace( '.', '', microtime( true ) );
			$secret = wp_generate_password( 40, false, false );

			switch_to_blog( $site->userblog_id );

			// Store the data as a transient
			$data['secret'] = wp_hash_password( $secret . $visitor_id );
			set_transient( "multilogin-{$type}-" . sha1( $key ), $data, 30 );

			restore_current_blog();

			$tokens[ $site->userblog_id ] = "{$key}-{$secret}";
		}

		$_SESSION[ "multilogin-{$type}-tokens" ] = $tokens;
	}

	/**
	 * Print a set of tokens.
	 *
	 * @since 1.0.0
	 *
	 * @param string $type The type of tokens to print ('login', 'logout').
	 */
	private static function print_tokens( $type ) {
		global $blog_id;

		$action = "multilogin-{$type}";
		$key = "{$action}-tokens";

		// Check if we should proceed
		if ( ! self::should_do_remote_login( $key ) ) {
			return;
		}

		$urls = array();
		foreach ( $_SESSION[ $key ] as $site => $token ) {
			// Skip if for the current blog somehow
			if ( $site == $blog_id ) {
				continue;
			}

			switch_to_blog( $site );

			$url = admin_url( 'admin-post.php' );
			$url = add_query_arg( array(
				'action' => $action,
				'token' => $token,
			), $url );

			printf( '<script class="multilogin-auth-url" data-url="%s"></script>', esc_attr( $url ) );

			restore_current_blog();
		}

		unset( $_SESSION[ $key ] );
	}

	/**
	 * Verify a token.
	 *
	 * @since 1.0.0
	 *
	 * @param string $type The type of token to verify ('login', 'logout').
	 */
	private static function verify_token( $type ) {
		// Fail if no token is present
		if ( ! isset( $_REQUEST['token'] ) ) {
			header( 'HTTP/1.1 401 Unauthorized' );
			die( "/* remote $type token missing */" );
		}

		// Get the visitor ID
		$visitor_id = self::visitor_id();

		// Get the key/secret parts
		list( $key, $secret ) = explode( '-', $_REQUEST['token'] );
		$key = sha1( $key );

		$transient = "multilogin-$type-$key";
		$data = get_transient( $transient );
		delete_transient( $transient );

		// Fail if the data could not be found
		if ( ! $data ) {
			header( 'HTTP/1.1 401 Unauthorized' );
			die( "/* remote $type data not found */" );
		}

		// If specified, fail if the user does not exist or does not belong to this site
		if ( isset( $data['user'] ) && ( ! get_userdata( $data['user'] ) || ! is_user_member_of_blog( $data['user'] ) ) ) {
			header( 'HTTP/1.1 401 Unauthorized' );
			die( "/* user not authorized for " . COOKIE_DOMAIN . " */" );
		}

		// Fail if the secret is missing
		if ( ! isset( $data['secret'] ) ) {
			header( 'HTTP/1.1 401 Unauthorized' );
			die( "/* remote $type secret not found */" );
		}

		// Fail if the secret doesn't pass
		if ( ! wp_check_password( $secret . $visitor_id, $data['secret'] ) ) {
			header( 'HTTP/1.1 401 Unauthorized' );
			die( "/* $type token invalid */" );
		}

		return $data;
	}

	// =========================
	// ! Hook Registration
	// =========================

	/**
	 * Register hooks.
	 *
	 * @since 1.0.0
	 */
	public static function setup() {
		// Don't do anything if not in the backend
		if ( ! is_backend() ) {
			return;
		}

		// Setup stuff
		self::add_hook( 'plugins_loaded', 'load_textdomain', 10, 0 );

		// Plugin information
		self::add_hook( 'in_plugin_update_message-' . plugin_basename( MULTILOGIN_PLUGIN_FILE ), 'update_notice' );

		// Script/Style Enqueues
		self::add_hook( 'login_enqueue_scripts', 'enqueue_assets', 10, 0 );
		self::add_hook( 'admin_enqueue_scripts', 'enqueue_assets', 10, 0 );

		// Shared remote login/logout handling
		self::add_hook( 'admin_notices', 'print_message_template', 10, 0 );
		self::add_hook( 'login_header', 'print_message_template', 10, 0 );

		// Remote login handling
		self::add_hook( 'wp_login', 'generate_login_tokens', 10, 2 );
		self::add_hook( 'admin_head', 'print_login_links', 10, 0 );
		self::add_hook( 'admin_post_multilogin-login', 'verify_login_token', 10, 0 );
		self::add_hook( 'admin_post_nopriv_multilogin-login', 'verify_login_token', 10, 0 );
		self::add_hook( 'admin_notices', 'print_login_notice', 10, 0 );

		// Remote logout handling
		self::add_hook( 'login_form_logout', 'generate_logout_tokens', 10, 0 );
		self::add_hook( 'login_head', 'print_logout_links', 10, 0 );
		self::add_hook( 'admin_post_multilogin-logout', 'verify_logout_token', 10, 0 );
		self::add_hook( 'admin_post_nopriv_multilogin-logout', 'verify_logout_token', 10, 0 );
		self::add_hook( 'login_header', 'print_logout_notice', 10, 0 );

		// Session Handling
		self::add_hook( 'login_init', 'start_session', 10, 0 );
		self::add_hook( 'admin_init', 'start_session', 10, 0 );
		self::add_hook( 'login_footer', 'end_session', 10, 0 );
		self::add_hook( 'admin_footer', 'end_session', 10, 0 );
	}

	// =========================
	// ! Setup Stuff
	// =========================

	/**
	 * Load the text domain.
	 *
	 * @since 1.0.0
	 */
	public static function load_textdomain() {
		// Load the textdomain
		load_plugin_textdomain( 'multilogin', false, dirname( MULTILOGIN_PLUGIN_FILE ) . '/languages' );
	}

	// =========================
	// ! Plugin Information
	// =========================

	/**
	 * In case of update, check for notice about the update.
	 *
	 * @since 1.0.0
	 *
	 * @param array $plugin The information about the plugin and the update.
	 */
	public static function update_notice( $plugin ) {
		// Get the version number that the update is for
		$version = $plugin['new_version'];

		// Check if there's a notice about the update
		$transient = "multilogin-update-notice-{$version}";
		$notice = get_transient( $transient );
		if ( $notice === false ) {
			// Hasn't been saved, fetch it from the SVN repo
			$notice = file_get_contents( "http://plugins.svn.wordpress.org/multilogin/assets/notice-{$version}.txt" ) ?: '';

			// Save the notice
			set_transient( $transient, $notice, YEAR_IN_SECONDS );
		}

		// Print out the notice if there is one
		if ( $notice ) {
			echo apply_filters( 'the_content', $notice );
		}
	}

	// =========================
	// ! Script/Style Enqueues
	// =========================

	/**
	 * Enqueue necessary styles and scripts.
	 *
	 * @since 1.0.0
	 */
	public static function enqueue_assets() {
		// Notice styling for admin/login screens
		wp_enqueue_style( 'multilogin-notice', plugins_url( 'css/notice.css', MULTILOGIN_PLUGIN_FILE ), array(), MULTILOGIN_PLUGIN_VERSION, 'screen' );

		// Login/Logout URL handling on admin/login screens
		wp_enqueue_script( 'multilogin-authenticate', plugins_url( 'js/authenticate.js', MULTILOGIN_PLUGIN_FILE ), array( 'jquery' ), MULTILOGIN_PLUGIN_VERSION, 'in footer' );

		// Determine which phrasing to use based on context
		if ( current_action() == 'login_enqueue_scripts' ) {
			$waiting = __( 'Attempting remote logout on %s...', 'multilogin' );
			$success = __( 'Remote logout on %s successful.', 'multilogin' );
			$error = __( 'Remote logout on %s failed.', 'multilogin' );
		} else {
			$waiting = __( 'Attempting remote login on %s...', 'multilogin' );
			$success = __( 'Remote login on %s successful.', 'multilogin' );
			$error = __( 'Remote login on %s failed.', 'multilogin' );
		}

		// Localization of authenticate script
		wp_localize_script( 'multilogin-authenticate', 'multiloginL10n', array(
			'waiting' => $waiting,
			'success' => $success,
			'error' => $error,
		) );
	}

	// =========================
	// ! Login/Logout Handling
	// =========================

	/**
	 * Print the template for notice messages.
	 *
	 * @since 1.0.0
	 */
	public static function print_message_template() {
		// Check if we should proceed
		if ( ! self::should_do_remote_login() ) {
			return;
		}

		?>
		<script type="text/template" id="multilogin_message_template">
			<p><span class="icon dashicons"></span> <span class="text"></span></p>
		</script>
		<?php
	}

	// =========================
	// ! Remote Login Handling
	// =========================

	/**
	 * Generate login tokens for all sites the user belongs to.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $username The user's login name.
	 * @param \WP_User $user     The user object.
	 */
	public static function generate_login_tokens( $username, $user ) {
		self::generate_tokens( 'login', $user, array(
			'user' => $user->ID,
			'remember' => isset( $_POST['rememberme'] ) && $_POST['rememberme'],
		) );
	}

	/**
	 * Print <script> tags for login links.
	 *
	 * @since 1.0.0
	 */
	public static function print_login_links() {
		self::print_tokens( 'login' );
	}

	/**
	 * Print an empty notice box for the remote login results.
	 *
	 * @since 1.0.0
	 */
	public static function print_login_notice() {
		// Check if we should proceed
		if ( ! self::should_do_remote_login() ) {
			return;
		}

		echo '<div class="notice is-dismissible multilogin-notice"></div>';
	}

	/**
	 * Verify the login token and authenticate the user.
	 *
	 * @since 1.0.0
	 */
	public static function verify_login_token() {
		$data = self::verify_token( 'login' );

		wp_set_auth_cookie( $data['user'], $data['remember'] );
		header( 'HTTP/1.1 200 OK' );
		die( '/* logged in on ' . COOKIE_DOMAIN . ' */' );
	}

	// =========================
	// ! Remote Logout Handling
	// =========================

	/**
	 * Generate logout tokens for all sites the user belongs to.
	 *
	 * @since 1.0.0
	 */
	public static function generate_logout_tokens() {
		$user = wp_get_current_user();
		self::generate_tokens( 'logout', $user );
	}

	/**
	 * Print <script> tags for logout links.
	 *
	 * @since 1.0.0
	 */
	public static function print_logout_links() {
		self::print_tokens( 'logout' );
	}

	/**
	 * Print an empty notice box for the remote logout results.
	 *
	 * @since 1.0.0
	 */
	public static function print_logout_notice() {
		// Check if we should proceed
		if ( ! self::should_do_remote_login() ) {
			return;
		}

		echo '<div class="message multilogin-notice"></div>';
	}

	/**
	 * Verify the logout token and end the users session.
	 *
	 * @since 1.0.0
	 */
	public static function verify_logout_token() {
		self::verify_token( 'logout' );

		// Logout the user
		wp_logout();
		header( 'HTTP/1.1 200 OK' );
		die( '/* logged out on ' . COOKIE_DOMAIN . ' */' );
	}

	// =========================
	// ! Session Handling
	// =========================

	/**
	 * Start the session if not already started.
	 *
	 * @since 1.0.0
	 */
	public static function start_session() {
		// Don't start session for ajax requests
		if ( ! defined( 'DOING_AJAX' ) && session_status() == PHP_SESSION_NONE ) {
		    session_start();
		}
	}

	/**
	 * If a session is active, write and close it.
	 *
	 * @since 1.0.0
	 */
	public static function end_session() {
		if ( session_status() == PHP_SESSION_ACTIVE ) {
			session_write_close();
		}
	}
}
