<?php
if (!defined('ABSPATH')) exit;

/**
 * Login guard — intercepts login attempts, blocks IPs, sends notifications
 */
class DBLG_Guard {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        if (!DB_Login_Guard::get_option('dblg_enabled')) {
            return;
        }

        // Check block BEFORE WordPress processes the login (priority 1)
        add_filter('authenticate', [$this, 'check_blocked'], 1, 3);

        // Log failed attempts
        add_action('wp_login_failed', [$this, 'on_login_failed'], 10, 2);

        // Log successful logins
        add_action('wp_login', [$this, 'on_login_success'], 10, 2);

        // Custom error message for blocked IPs
        add_filter('login_errors', [$this, 'blocked_error_message']);
    }

    /**
     * Get client IP address
     */
    public static function get_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',    // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // X-Forwarded-For can contain multiple IPs
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Check if IP is whitelisted
     */
    private function is_whitelisted($ip) {
        $whitelist = DB_Login_Guard::get_option('dblg_whitelist_ips');
        if (empty($whitelist)) {
            return false;
        }

        $ips = array_filter(array_map('trim', explode("\n", $whitelist)));
        foreach ($ips as $wip) {
            // Exact match
            if ($wip === $ip) {
                return true;
            }
            // CIDR match (e.g. 192.168.1.0/24)
            if (strpos($wip, '/') !== false && $this->ip_in_cidr($ip, $wip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range
     */
    private function ip_in_cidr($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        $mask = intval($mask);
        if ($mask < 0 || $mask > 32) return false;

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) return false;

        $mask_long = -1 << (32 - $mask);
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }

    /**
     * Check if blocked — runs before WP processes login
     */
    public function check_blocked($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }

        $ip = self::get_client_ip();

        if ($this->is_whitelisted($ip)) {
            return $user;
        }

        $blocked = DBLG_Database::is_ip_blocked($ip);
        if ($blocked) {
            // Log the blocked attempt
            DBLG_Database::log_attempt([
                'ip'         => $ip,
                'username'   => $username,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'status'     => 'blocked',
                'error'      => 'IP bloccato',
            ]);

            // Calculate remaining time
            $remaining = '';
            if (!$blocked->is_permanent) {
                $diff = strtotime($blocked->expires_at) - strtotime(current_time('mysql'));
                if ($diff > 0) {
                    $remaining = sprintf(
                        __(' Riprova tra %d minuti.', 'db-login-guard'),
                        ceil($diff / 60)
                    );
                }
            }

            return new WP_Error(
                'dblg_blocked',
                sprintf(
                    __('Troppi tentativi di accesso. Il tuo IP è stato temporaneamente bloccato.%s', 'db-login-guard'),
                    $remaining
                )
            );
        }

        return $user;
    }

    /**
     * Handle failed login
     */
    public function on_login_failed($username, $error = null) {
        $ip = self::get_client_ip();

        if ($this->is_whitelisted($ip)) {
            // Log but don't block
            DBLG_Database::log_attempt([
                'ip'         => $ip,
                'username'   => $username,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'status'     => 'failed',
                'error'      => __('Whitelisted — non bloccato', 'db-login-guard'),
            ]);
            return;
        }

        $error_msg = '';
        if ($error instanceof WP_Error) {
            $codes = $error->get_error_codes();
            $error_msg = implode(', ', $codes);
        }

        // Log the attempt
        DBLG_Database::log_attempt([
            'ip'         => $ip,
            'username'   => $username,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'status'     => 'failed',
            'error'      => $error_msg,
        ]);

        // Check if we should block
        $max_attempts = intval(DB_Login_Guard::get_option('dblg_max_attempts'));
        $window = intval(DB_Login_Guard::get_option('dblg_lockout_window'));
        $lockout_minutes = intval(DB_Login_Guard::get_option('dblg_lockout_minutes'));

        $recent_failures = DBLG_Database::count_recent_failures($ip, $window);

        if ($recent_failures >= $max_attempts) {
            DBLG_Database::block_ip($ip, $lockout_minutes, $recent_failures);

            // Send notification
            $this->maybe_notify_block($ip, $username, $recent_failures);
        }
    }

    /**
     * Handle successful login
     */
    public function on_login_success($username, $user) {
        if (!DB_Login_Guard::get_option('dblg_log_successful')) {
            return;
        }

        $ip = self::get_client_ip();

        DBLG_Database::log_attempt([
            'ip'         => $ip,
            'username'   => $username,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'status'     => 'success',
            'error'      => '',
        ]);
    }

    /**
     * Custom error message for blocked IP
     */
    public function blocked_error_message($error) {
        $ip = self::get_client_ip();
        $blocked = DBLG_Database::is_ip_blocked($ip);

        if ($blocked) {
            $remaining = '';
            if (!$blocked->is_permanent) {
                $diff = strtotime($blocked->expires_at) - strtotime(current_time('mysql'));
                if ($diff > 0) {
                    $remaining = sprintf(
                        __(' Riprova tra %d minuti.', 'db-login-guard'),
                        ceil($diff / 60)
                    );
                }
            }

            return '<strong>' . __('Accesso bloccato', 'db-login-guard') . '</strong>: '
                . __('Troppi tentativi di accesso falliti.', 'db-login-guard')
                . $remaining;
        }

        // Show remaining attempts warning
        if (!$this->is_whitelisted($ip)) {
            $max_attempts = intval(DB_Login_Guard::get_option('dblg_max_attempts'));
            $window = intval(DB_Login_Guard::get_option('dblg_lockout_window'));
            $recent = DBLG_Database::count_recent_failures($ip, $window);

            if ($recent > 0 && $recent < $max_attempts) {
                $remaining = $max_attempts - $recent;
                $error .= '<br><small>' . sprintf(
                    _n(
                        'Attenzione: hai ancora %d tentativo prima del blocco.',
                        'Attenzione: hai ancora %d tentativi prima del blocco.',
                        $remaining,
                        'db-login-guard'
                    ),
                    $remaining
                ) . '</small>';
            }
        }

        return $error;
    }

    /**
     * Send email notification on block
     */
    private function maybe_notify_block($ip, $username, $attempts) {
        if (!DB_Login_Guard::get_option('dblg_email_notify')) {
            return;
        }

        $email = DB_Login_Guard::get_option('dblg_email_address');
        if (empty($email)) {
            $email = get_option('admin_email');
        }

        if (!is_email($email)) {
            return;
        }

        // Rate limit: max 1 email every 10 minutes per IP
        $transient_key = 'dblg_notified_' . md5($ip);
        if (get_transient($transient_key)) {
            return;
        }
        set_transient($transient_key, 1, 10 * MINUTE_IN_SECONDS);

        $site_name = get_bloginfo('name');
        $lockout_minutes = intval(DB_Login_Guard::get_option('dblg_lockout_minutes'));

        $subject = sprintf(
            __('[%s] IP bloccato per tentativi di login falliti', 'db-login-guard'),
            $site_name
        );

        $body = sprintf(
            __("Un indirizzo IP è stato bloccato sul sito %s.\n\n" .
               "IP: %s\n" .
               "Username tentato: %s\n" .
               "Tentativi falliti: %d\n" .
               "Durata blocco: %d minuti\n" .
               "Data/ora: %s\n\n" .
               "Gestisci gli IP bloccati: %s\n\n" .
               "— DB Login Guard v%s",
               'db-login-guard'),
            $site_name,
            $ip,
            $username,
            $attempts,
            $lockout_minutes,
            current_time('d/m/Y H:i:s'),
            admin_url('tools.php?page=db-login-guard&tab=blocked'),
            DBLG_VERSION
        );

        wp_mail($email, $subject, $body);
    }
}
