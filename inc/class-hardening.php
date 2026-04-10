<?php
if (!defined('ABSPATH')) exit;

/**
 * Hardening — disable XML-RPC, restrict REST API /users endpoint
 */
class DBLG_Hardening {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Disable XML-RPC
        if (DB_Login_Guard::get_option('dblg_disable_xmlrpc')) {
            $this->disable_xmlrpc();
        }

        // Restrict REST API /users for anonymous
        if (DB_Login_Guard::get_option('dblg_restrict_rest_users')) {
            add_filter('rest_pre_dispatch', [$this, 'restrict_rest_users'], 10, 3);
        }
    }

    /* ─── XML-RPC ─── */

    /**
     * Completely disable XML-RPC
     */
    private function disable_xmlrpc() {
        // Disable XML-RPC methods
        add_filter('xmlrpc_enabled', '__return_false');

        // Disable X-Pingback header
        add_filter('wp_headers', [$this, 'remove_pingback_header']);

        // Disable XML-RPC methods list (return empty)
        add_filter('xmlrpc_methods', [$this, 'remove_xmlrpc_methods']);

        // Block direct access to xmlrpc.php
        add_action('init', [$this, 'block_xmlrpc_access'], 1);

        // Remove RSD link from head
        remove_action('wp_head', 'rsd_link');

        // Remove wlwmanifest link
        remove_action('wp_head', 'wlwmanifest_link');
    }

    /**
     * Remove X-Pingback header
     */
    public function remove_pingback_header($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * Remove all XML-RPC methods
     */
    public function remove_xmlrpc_methods($methods) {
        return [];
    }

    /**
     * Block direct access to xmlrpc.php with 403
     */
    public function block_xmlrpc_access() {
        if (!isset($_SERVER['REQUEST_URI'])) {
            return;
        }

        $request = $_SERVER['REQUEST_URI'];

        // Check if request is for xmlrpc.php
        if (preg_match('/xmlrpc\.php/i', $request)) {
            // Log the attempt if guard is enabled
            if (DB_Login_Guard::get_option('dblg_enabled')) {
                DBLG_Database::log_attempt([
                    'ip'         => DBLG_Guard::get_client_ip(),
                    'username'   => 'xmlrpc',
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'status'     => 'blocked',
                    'error'      => 'XML-RPC disabilitato',
                ]);
            }

            status_header(403);
            header('Content-Type: text/plain; charset=UTF-8');
            die('XML-RPC è disabilitato su questo sito.');
        }
    }

    /* ─── REST API /users restriction ─── */

    /**
     * Block /wp/v2/users and /wp/v2/users/N for anonymous requests
     */
    public function restrict_rest_users($result, $server, $request) {
        // Only restrict anonymous users
        if (is_user_logged_in()) {
            return $result;
        }

        $route = $request->get_route();

        // Block /wp/v2/users and /wp/v2/users/{id}
        if (preg_match('#^/wp/v2/users(?:/|$)#', $route)) {
            // Log the attempt
            if (DB_Login_Guard::get_option('dblg_enabled')) {
                DBLG_Database::log_attempt([
                    'ip'         => DBLG_Guard::get_client_ip(),
                    'username'   => 'rest-api',
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'status'     => 'blocked',
                    'error'      => 'REST API /users bloccato per anonimi',
                ]);
            }

            return new WP_Error(
                'dblg_rest_forbidden',
                __('Accesso non autorizzato.', 'db-login-guard'),
                ['status' => 403]
            );
        }

        // Also block ?rest_route=/wp/v2/users and author enumeration via oembed
        if (preg_match('#^/oembed/1\.0/embed#', $route)) {
            // oEmbed is OK, but we strip author info — handled elsewhere
        }

        return $result;
    }
}
