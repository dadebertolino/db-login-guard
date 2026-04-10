<?php
if (!defined('ABSPATH')) exit;

/**
 * Database management — tables and queries
 */
class DBLG_Database {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Just-in-time table check
        add_action('admin_init', [$this, 'maybe_create_tables']);
    }

    /**
     * Create or update tables via dbDelta
     */
    public static function create_tables() {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset = $wpdb->get_charset_collate();

        // Login log table
        $log_table = $wpdb->prefix . 'dblg_login_log';
        $sql_log = "CREATE TABLE $log_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(200) NOT NULL DEFAULT '',
            user_agent varchar(500) NOT NULL DEFAULT '',
            status varchar(20) NOT NULL DEFAULT 'failed',
            error_message varchar(500) NOT NULL DEFAULT '',
            created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY status (status),
            KEY created_at (created_at),
            KEY ip_status_created (ip_address, status, created_at)
        ) $charset;";

        // Blocked IPs table
        $blocked_table = $wpdb->prefix . 'dblg_blocked_ips';
        $sql_blocked = "CREATE TABLE $blocked_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(200) NOT NULL DEFAULT 'brute_force',
            attempts int(11) NOT NULL DEFAULT 0,
            blocked_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
            expires_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
            is_permanent tinyint(1) NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY expires_at (expires_at)
        ) $charset;";

        dbDelta($sql_log);
        dbDelta($sql_blocked);

        update_option('dblg_db_version', DBLG_VERSION);
    }

    /**
     * Check and create tables if missing
     */
    public function maybe_create_tables() {
        global $wpdb;
        $log_table = $wpdb->prefix . 'dblg_login_log';
        if ($wpdb->get_var("SHOW TABLES LIKE '$log_table'") !== $log_table) {
            self::create_tables();
        }
    }

    /* ─── Login Log ─── */

    /**
     * Insert a login attempt
     */
    public static function log_attempt($data) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        return $wpdb->insert($table, [
            'ip_address'    => sanitize_text_field($data['ip']),
            'username'      => sanitize_text_field($data['username']),
            'user_agent'    => sanitize_text_field(substr($data['user_agent'] ?? '', 0, 500)),
            'status'        => sanitize_key($data['status']),
            'error_message' => sanitize_text_field($data['error'] ?? ''),
            'created_at'    => current_time('mysql'),
        ], ['%s', '%s', '%s', '%s', '%s', '%s']);
    }

    /**
     * Count failed attempts from an IP in a time window
     */
    public static function count_recent_failures($ip, $minutes) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table
             WHERE ip_address = %s
             AND status = 'failed'
             AND created_at > DATE_SUB(%s, INTERVAL %d MINUTE)",
            $ip,
            current_time('mysql'),
            $minutes
        ));
    }

    /**
     * Get log entries with pagination
     */
    public static function get_log($args = []) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        $defaults = [
            'per_page' => 50,
            'page'     => 1,
            'status'   => '',
            'ip'       => '',
            'username' => '',
            'orderby'  => 'created_at',
            'order'    => 'DESC',
        ];
        $args = wp_parse_args($args, $defaults);

        $where = '1=1';
        $values = [];

        if ($args['status']) {
            $where .= ' AND status = %s';
            $values[] = $args['status'];
        }
        if ($args['ip']) {
            $where .= ' AND ip_address LIKE %s';
            $values[] = '%' . $wpdb->esc_like($args['ip']) . '%';
        }
        if ($args['username']) {
            $where .= ' AND username LIKE %s';
            $values[] = '%' . $wpdb->esc_like($args['username']) . '%';
        }

        $allowed_orderby = ['created_at', 'ip_address', 'username', 'status'];
        $orderby = in_array($args['orderby'], $allowed_orderby) ? $args['orderby'] : 'created_at';
        $order = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';

        $offset = max(0, ($args['page'] - 1) * $args['per_page']);

        $query = "SELECT * FROM $table WHERE $where ORDER BY $orderby $order LIMIT %d OFFSET %d";
        $values[] = $args['per_page'];
        $values[] = $offset;

        if (!empty($values)) {
            $query = $wpdb->prepare($query, $values);
        }

        return $wpdb->get_results($query);
    }

    /**
     * Count total log entries (for pagination)
     */
    public static function count_log($args = []) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        $where = '1=1';
        $values = [];

        if (!empty($args['status'])) {
            $where .= ' AND status = %s';
            $values[] = $args['status'];
        }
        if (!empty($args['ip'])) {
            $where .= ' AND ip_address LIKE %s';
            $values[] = '%' . $wpdb->esc_like($args['ip']) . '%';
        }
        if (!empty($args['username'])) {
            $where .= ' AND username LIKE %s';
            $values[] = '%' . $wpdb->esc_like($args['username']) . '%';
        }

        $query = "SELECT COUNT(*) FROM $table WHERE $where";
        if (!empty($values)) {
            $query = $wpdb->prepare($query, $values);
        }

        return (int) $wpdb->get_var($query);
    }

    /**
     * Delete old log entries
     */
    public static function purge_old_logs($days) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        return $wpdb->query($wpdb->prepare(
            "DELETE FROM $table WHERE created_at < DATE_SUB(%s, INTERVAL %d DAY)",
            current_time('mysql'),
            $days
        ));
    }

    /**
     * Clear all log entries
     */
    public static function clear_log() {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';
        return $wpdb->query("TRUNCATE TABLE $table");
    }

    /**
     * Get log stats
     */
    public static function get_stats() {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_login_log';

        $stats = [];

        $stats['total'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table");
        $stats['failed'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE status = 'failed'");
        $stats['success'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE status = 'success'");
        $stats['blocked'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE status = 'blocked'");

        // Last 24h
        $stats['failed_24h'] = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE status = 'failed' AND created_at > DATE_SUB(%s, INTERVAL 24 HOUR)",
            current_time('mysql')
        ));

        // Unique IPs failed last 24h
        $stats['unique_ips_24h'] = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM $table WHERE status = 'failed' AND created_at > DATE_SUB(%s, INTERVAL 24 HOUR)",
            current_time('mysql')
        ));

        // Top attacked username
        $stats['top_username'] = $wpdb->get_var(
            "SELECT username FROM $table WHERE status = 'failed' GROUP BY username ORDER BY COUNT(*) DESC LIMIT 1"
        );

        return $stats;
    }

    /* ─── Blocked IPs ─── */

    /**
     * Block an IP
     */
    public static function block_ip($ip, $minutes, $attempts = 0, $permanent = false) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_blocked_ips';

        $now = current_time('mysql');
        $expires = $permanent ? '2099-12-31 23:59:59' : gmdate('Y-m-d H:i:s', strtotime($now) + ($minutes * 60));

        // Upsert
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table WHERE ip_address = %s",
            $ip
        ));

        if ($existing) {
            return $wpdb->update($table, [
                'attempts'     => $attempts,
                'blocked_at'   => $now,
                'expires_at'   => $expires,
                'is_permanent' => $permanent ? 1 : 0,
            ], ['id' => $existing], ['%d', '%s', '%s', '%d'], ['%d']);
        }

        return $wpdb->insert($table, [
            'ip_address'   => sanitize_text_field($ip),
            'reason'       => 'brute_force',
            'attempts'     => $attempts,
            'blocked_at'   => $now,
            'expires_at'   => $expires,
            'is_permanent' => $permanent ? 1 : 0,
        ], ['%s', '%s', '%d', '%s', '%s', '%d']);
    }

    /**
     * Check if an IP is currently blocked
     */
    public static function is_ip_blocked($ip) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_blocked_ips';

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE ip_address = %s AND (expires_at > %s OR is_permanent = 1)",
            $ip,
            current_time('mysql')
        ));

        return $row ? $row : false;
    }

    /**
     * Unblock an IP
     */
    public static function unblock_ip($id) {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_blocked_ips';
        return $wpdb->delete($table, ['id' => $id], ['%d']);
    }

    /**
     * Get all blocked IPs
     */
    public static function get_blocked_ips() {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_blocked_ips';
        return $wpdb->get_results("SELECT * FROM $table ORDER BY blocked_at DESC");
    }

    /**
     * Cleanup expired blocks
     */
    public static function cleanup_expired_blocks() {
        global $wpdb;
        $table = $wpdb->prefix . 'dblg_blocked_ips';
        return $wpdb->query($wpdb->prepare(
            "DELETE FROM $table WHERE is_permanent = 0 AND expires_at <= %s",
            current_time('mysql')
        ));
    }
}
