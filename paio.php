<?php
/**
 * Plugin Name: PAIO Migration
 * Plugin URI:  https://police.go.th/
 * Description: In-house full-site migration (database + wp-content) for the RTP fleet. A clean, authenticated replacement for the cracked "All-In-One WP Migration With Import" plugin. Export/import from WP-CLI or the wp-admin GUI using one shared engine.
 * Version:     0.1.2
 * Author:      RTP NSOC
 * License:     GPL-2.0-or-later
 * Requires PHP: 7.0
 *
 * SECURITY DESIGN (why this exists):
 *   The cracked AIO plugin registered wp_ajax_nopriv_ai1wm_import = unauthenticated
 *   arbitrary archive restore = remote code execution, and shipped with a backdoor.
 *   PAIO fixes both:
 *     - NO wp_ajax_nopriv_* hooks exist anywhere. Every entry point requires a logged-in
 *       user with `manage_options` plus a valid nonce.
 *     - Archive storage lives in a protected directory (deny-all .htaccess, no PHP exec,
 *       random token subdir, index.php guard).
 *     - Import validates the archive magic, confines every extracted path under wp-content,
 *       and rejects path traversal / absolute paths / null bytes.
 *     - No obfuscation, no eval, no remote calls, no proc_open (works under snuffleupagus).
 */

if (!defined('ABSPATH')) {
    exit;
}

define('PAIO_VERSION', '0.1.2');
define('PAIO_FILE', __FILE__);
define('PAIO_DIR', plugin_dir_path(__FILE__));
define('PAIO_URL', plugin_dir_url(__FILE__));
define('PAIO_ARCHIVE_MAGIC', 'PAIO1');          // first line of every .paio archive
define('PAIO_ARCHIVE_EXT', 'paio');
define('PAIO_CAP', 'manage_options');           // capability required for every action

require_once PAIO_DIR . 'includes/class-paio-security.php';
require_once PAIO_DIR . 'includes/class-paio-archive-writer.php';
require_once PAIO_DIR . 'includes/class-paio-archive-reader.php';
require_once PAIO_DIR . 'includes/class-paio-database.php';
require_once PAIO_DIR . 'includes/class-paio-exporter.php';
require_once PAIO_DIR . 'includes/class-paio-importer.php';

register_activation_hook(__FILE__, array('PAIO_Security', 'ensure_storage'));

// wp-admin GUI (loaded only in admin; still capability- and nonce-gated internally).
if (is_admin()) {
    require_once PAIO_DIR . 'includes/class-paio-admin.php';
    add_action('plugins_loaded', array('PAIO_Admin', 'init'));
}

// WP-CLI commands share the exact same engine as the GUI.
if (defined('WP_CLI') && WP_CLI) {
    require_once PAIO_DIR . 'includes/class-paio-cli.php';
    WP_CLI::add_command('paio', 'PAIO_CLI');
}
