<?php
/*
Plugin Name: MultiLogin
Plugin URI: https://github.com/dougwollison/multilogin
Description: Cross-Domain login solution for multisite installations.
Version: 1.0.0
Author: Doug Wollison
Author URI: http://dougw.me
Tags: multisite, login, signin, singon
License: GPL2
Text Domain: multilogin
Domain Path: /languages
Network: true
*/

// =========================
// ! Constants
// =========================

/**
 * Reference to the plugin file.
 *
 * @since 1.0.0
 *
 * @var string
 */
define( 'MULTILOGIN_PLUGIN_FILE', __FILE__ );

/**
 * Reference to the plugin directory.
 *
 * @since 1.0.0
 *
 * @var string
 */
define( 'MULTILOGIN_PLUGIN_DIR', dirname( MULTILOGIN_PLUGIN_FILE ) );

/**
 * Identifies the current plugin version.
 *
 * @since 1.1.0
 *
 * @var string
 */
define( 'MULTILOGIN_PLUGIN_VERSION', '1.0.0' );

// =========================
// ! Includes
// =========================

require( MULTILOGIN_PLUGIN_DIR . '/includes/autoloader.php' );
require( MULTILOGIN_PLUGIN_DIR . '/includes/functions-multilogin.php' );

// =========================
// ! Setup
// =========================

MultiLogin\System::setup();
