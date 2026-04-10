<?php
/**
 * Plugin Name: DB Login Guard
 * Plugin URI: https://github.com/dadebertolino/db-login-guard
 * Description: Protezione brute force per WordPress. Registra i tentativi di login, blocca gli IP dopo troppi errori, notifica via email. Niente servizi esterni, niente abbonamenti.
 * Version: 1.1.0
 * Author: Davide Bertolino
 * Author URI: https://www.davidebertolino.it
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: db-login-guard
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) exit;

define('DBLG_VERSION', '1.1.0');
define('DBLG_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('DBLG_PLUGIN_URL', plugin_dir_url(__FILE__));
define('DBLG_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Include classes
require_once DBLG_PLUGIN_DIR . 'inc/class-database.php';
require_once DBLG_PLUGIN_DIR . 'inc/class-guard.php';
require_once DBLG_PLUGIN_DIR . 'inc/class-admin.php';
require_once DBLG_PLUGIN_DIR . 'inc/class-cron.php';
require_once DBLG_PLUGIN_DIR . 'inc/class-hardening.php';

/**
 * Main plugin class — singleton
 */
final class DB_Login_Guard {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Init components
        DBLG_Database::instance();
        DBLG_Guard::instance();
        DBLG_Cron::instance();
        DBLG_Hardening::instance();

        if (is_admin()) {
            DBLG_Admin::instance();
        }

        // Settings link
        add_filter('plugin_action_links_' . DBLG_PLUGIN_BASENAME, [$this, 'settings_link']);
    }

    /**
     * Default settings
     */
    public static function get_defaults() {
        return [
            'dblg_max_attempts'      => 5,
            'dblg_lockout_minutes'   => 30,
            'dblg_lockout_window'    => 10,       // minuti in cui contare i tentativi
            'dblg_log_successful'    => 1,
            'dblg_log_retention_days'=> 30,
            'dblg_email_notify'      => 1,
            'dblg_email_address'     => '',        // vuoto = admin email
            'dblg_whitelist_ips'     => '',        // uno per riga
            'dblg_enabled'           => 1,
            'dblg_disable_xmlrpc'    => 0,
            'dblg_restrict_rest_users' => 0,
        ];
    }

    /**
     * Get option with default fallback
     */
    public static function get_option($key) {
        $defaults = self::get_defaults();
        $default = isset($defaults[$key]) ? $defaults[$key] : '';
        return get_option($key, $default);
    }

    /**
     * Settings link in plugin list
     */
    public function settings_link($links) {
        $url = admin_url('tools.php?page=db-login-guard');
        $settings = '<a href="' . esc_url($url) . '">' . __('Impostazioni', 'db-login-guard') . '</a>';
        array_unshift($links, $settings);
        return $links;
    }

    /* ─── Activation ─── */

    public static function activate() {
        // Create/update tables
        DBLG_Database::create_tables();

        // Set defaults
        $defaults = self::get_defaults();
        foreach ($defaults as $key => $value) {
            if (get_option($key) === false) {
                add_option($key, $value);
            }
        }

        // Schedule cron
        if (!wp_next_scheduled('dblg_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'dblg_cleanup_logs');
        }
    }

    /* ─── Deactivation ─── */

    public static function deactivate() {
        wp_clear_scheduled_hook('dblg_cleanup_logs');
    }

    /* ─── Uninstall ─── */

    public static function uninstall() {
        global $wpdb;

        // Remove options
        $defaults = self::get_defaults();
        foreach (array_keys($defaults) as $key) {
            delete_option($key);
        }

        // Remove tables
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}dblg_login_log");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}dblg_blocked_ips");

        // Remove transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_dblg_%' OR option_name LIKE '_transient_timeout_dblg_%'");

        // Clear cron
        wp_clear_scheduled_hook('dblg_cleanup_logs');
    }
}

register_activation_hook(__FILE__, ['DB_Login_Guard', 'activate']);
register_deactivation_hook(__FILE__, ['DB_Login_Guard', 'deactivate']);

DB_Login_Guard::instance();
