<?php
if (!defined('ABSPATH')) exit;

/**
 * Cron jobs — log cleanup and expired block cleanup
 */
class DBLG_Cron {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('dblg_cleanup_logs', [$this, 'run_cleanup']);
    }

    /**
     * Daily cleanup
     */
    public function run_cleanup() {
        $days = intval(DB_Login_Guard::get_option('dblg_log_retention_days'));
        if ($days > 0) {
            DBLG_Database::purge_old_logs($days);
        }

        // Also cleanup expired blocks
        DBLG_Database::cleanup_expired_blocks();
    }
}
