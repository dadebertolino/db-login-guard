<?php
/**
 * DB Login Guard — Uninstall
 */

if (!defined('WP_UNINSTALL_PLUGIN')) exit;

global $wpdb;

// Remove options
$options = [
    'dblg_max_attempts',
    'dblg_lockout_minutes',
    'dblg_lockout_window',
    'dblg_log_successful',
    'dblg_log_retention_days',
    'dblg_email_notify',
    'dblg_email_address',
    'dblg_whitelist_ips',
    'dblg_enabled',
    'dblg_disable_xmlrpc',
    'dblg_restrict_rest_users',
    'dblg_db_version',
];

foreach ($options as $option) {
    delete_option($option);
}

// Remove tables
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}dblg_login_log");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}dblg_blocked_ips");

// Remove transients
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_dblg_%' OR option_name LIKE '_transient_timeout_dblg_%'");

// Clear cron
wp_clear_scheduled_hook('dblg_cleanup_logs');
