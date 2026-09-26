<?php
if (!defined('ABSPATH')) exit;

/**
 * Cron jobs — log cleanup and expired block cleanup
 */
class DBLG_Cron {

    const HOOK = 'dblg_cleanup_logs';

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action(self::HOOK, [$this, 'run_cleanup']);

        // 1.2.0: schedulazione idempotente. Prima l'evento veniva creato solo
        // in attivazione: un aggiornamento via upload ZIP / updater senza
        // riattivazione poteva lasciare il sito senza pulizia automatica.
        add_action('init', [__CLASS__, 'maybe_schedule']);
    }

    /**
     * Schedule the daily cleanup if missing (safe to call on every request).
     */
    public static function maybe_schedule() {
        if (!wp_next_scheduled(self::HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK);
        }
    }

    /**
     * Effective log retention in days (0 = nessuna pulizia automatica).
     *
     * Sorgente: impostazione "Conservazione log (giorni)" (default 30),
     * sovrascrivibile dal filter `dblg_log_retention_days`.
     *
     * @return int
     */
    public static function get_retention_days() {
        $days = absint(DB_Login_Guard::get_option('dblg_log_retention_days'));

        /**
         * Filtra i giorni di conservazione del log accessi.
         *
         * @since 1.2.0
         * @param int $days Giorni (0 = disattiva la pulizia automatica).
         */
        return absint(apply_filters('dblg_log_retention_days', $days));
    }

    /**
     * Daily cleanup
     */
    public function run_cleanup() {
        $days = self::get_retention_days();
        if ($days > 0) {
            DBLG_Database::purge_old_logs($days);
        }

        // Also cleanup expired blocks
        DBLG_Database::cleanup_expired_blocks();
    }
}
