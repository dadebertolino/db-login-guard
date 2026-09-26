<?php
if (!defined('ABSPATH')) exit;

/**
 * Admin interface — settings, log viewer, blocked IPs management
 */
class DBLG_Admin {

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'handle_actions']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);

        // AJAX handlers
        add_action('wp_ajax_dblg_unblock_ip', [$this, 'ajax_unblock_ip']);
        add_action('wp_ajax_dblg_block_ip', [$this, 'ajax_block_ip']);
        add_action('wp_ajax_dblg_clear_log', [$this, 'ajax_clear_log']);
        add_action('wp_ajax_dblg_export_log', [$this, 'ajax_export_log']);
    }

    /* ─── Menu ─── */

    public function add_menu() {
        add_management_page(
            __('Login Guard', 'db-login-guard'),
            __('Login Guard', 'db-login-guard'),
            'manage_options',
            'db-login-guard',
            [$this, 'render_page']
        );
    }

    /* ─── Settings Registration ─── */

    public function register_settings() {
        $fields = array_keys(DB_Login_Guard::get_defaults());
        foreach ($fields as $field) {
            register_setting('dblg_settings', $field, [
                'sanitize_callback' => [$this, 'sanitize_field'],
            ]);
        }
    }

    public function sanitize_field($value) {
        if (is_numeric($value)) {
            return intval($value);
        }
        return sanitize_text_field($value);
    }

    /* ─── Scripts ─── */

    public function enqueue_scripts($hook) {
        if ($hook !== 'tools_page_db-login-guard') {
            return;
        }

        wp_enqueue_style(
            'db-admin-ui',
            DBLG_PLUGIN_URL . 'assets/css/db-admin-ui.css',
            [],
            DBLG_VERSION
        );

        wp_enqueue_style(
            'dblg-admin',
            DBLG_PLUGIN_URL . 'assets/css/admin.css',
            ['db-admin-ui'],
            DBLG_VERSION
        );

        wp_enqueue_script(
            'dblg-admin',
            DBLG_PLUGIN_URL . 'assets/js/admin.js',
            ['jquery'],
            DBLG_VERSION,
            true
        );

        wp_localize_script('dblg-admin', 'dblg', [
            'ajax_url'       => admin_url('admin-ajax.php'),
            'nonce'          => wp_create_nonce('dblg_nonce'),
            'confirm_clear'  => __('Sei sicuro di voler svuotare tutto il log? Questa azione è irreversibile.', 'db-login-guard'),
            'confirm_unblock'=> __('Sbloccare questo IP?', 'db-login-guard'),
        ]);
    }

    /* ─── Handle bulk/admin actions (before output) ─── */

    public function handle_actions() {
        if (!isset($_GET['page']) || $_GET['page'] !== 'db-login-guard') {
            return;
        }
        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle manual block from log
        if (isset($_GET['action']) && $_GET['action'] === 'dblg_block' && isset($_GET['ip'])) {
            if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'dblg_block_ip')) {
                wp_die(__('Nonce non valido.', 'db-login-guard'));
            }
            $ip = sanitize_text_field($_GET['ip']);
            $lockout = intval(DB_Login_Guard::get_option('dblg_lockout_minutes'));
            DBLG_Database::block_ip($ip, $lockout, 0);
            wp_safe_redirect(admin_url('tools.php?page=db-login-guard&tab=blocked&dblg_notice=blocked'));
            exit;
        }

        // Handle unblock
        if (isset($_GET['action']) && $_GET['action'] === 'dblg_unblock' && isset($_GET['id'])) {
            if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'dblg_unblock_ip')) {
                wp_die(__('Nonce non valido.', 'db-login-guard'));
            }
            DBLG_Database::unblock_ip(intval($_GET['id']));
            wp_safe_redirect(admin_url('tools.php?page=db-login-guard&tab=blocked&dblg_notice=unblocked'));
            exit;
        }
    }

    /* ─── Render Page ─── */

    public function render_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $tab = sanitize_key($_GET['tab'] ?? 'dashboard');
        $tabs = [
            'dashboard' => __('Dashboard', 'db-login-guard'),
            'log'       => __('Log accessi', 'db-login-guard'),
            'blocked'   => __('IP bloccati', 'db-login-guard'),
            'settings'  => __('Impostazioni', 'db-login-guard'),
        ];

        // Notices
        if (isset($_GET['dblg_notice'])) {
            $notice = sanitize_key($_GET['dblg_notice']);
            $messages = [
                'blocked'   => __('IP bloccato.', 'db-login-guard'),
                'unblocked' => __('IP sbloccato.', 'db-login-guard'),
                'cleared'   => __('Log svuotato.', 'db-login-guard'),
            ];
            if (isset($messages[$notice])) {
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($messages[$notice]) . '</p></div>';
            }
        }
        ?>
        <div class="wrap dblg-wrap">
            <h1><?php _e('DB Login Guard', 'db-login-guard'); ?></h1>

            <nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e('Sezioni', 'db-login-guard'); ?>">
                <?php foreach ($tabs as $slug => $label): ?>
                    <a href="<?php echo esc_url(admin_url('tools.php?page=db-login-guard&tab=' . $slug)); ?>"
                       class="nav-tab <?php echo $tab === $slug ? 'nav-tab-active' : ''; ?>"
                       <?php echo $tab === $slug ? 'aria-current="page"' : ''; ?>>
                        <?php echo esc_html($label); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <div class="dblg-tab-content">
                <?php
                switch ($tab) {
                    case 'log':
                        $this->render_log_tab();
                        break;
                    case 'blocked':
                        $this->render_blocked_tab();
                        break;
                    case 'settings':
                        $this->render_settings_tab();
                        break;
                    default:
                        $this->render_dashboard_tab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    /* ─── Dashboard Tab ─── */

    private function render_dashboard_tab() {
        $stats = DBLG_Database::get_stats();
        $enabled = DB_Login_Guard::get_option('dblg_enabled');
        $blocked_ips = DBLG_Database::get_blocked_ips();
        $active_blocks = 0;
        $now = current_time('mysql');
        foreach ($blocked_ips as $b) {
            if ($b->is_permanent || $b->expires_at > $now) {
                $active_blocks++;
            }
        }
        ?>
        <div class="dblg-dashboard">
            <div class="dblg-status-bar <?php echo $enabled ? 'dblg-status-active' : 'dblg-status-inactive'; ?>">
                <span class="dblg-status-dot"></span>
                <?php echo $enabled
                    ? __('Protezione attiva', 'db-login-guard')
                    : __('Protezione disattivata', 'db-login-guard');
                ?>
            </div>

            <div class="dblg-stats-grid">
                <div class="dblg-stat-card">
                    <div class="dblg-stat-number"><?php echo esc_html($stats['failed_24h']); ?></div>
                    <div class="dblg-stat-label"><?php _e('Tentativi falliti (24h)', 'db-login-guard'); ?></div>
                </div>
                <div class="dblg-stat-card">
                    <div class="dblg-stat-number"><?php echo esc_html($stats['unique_ips_24h']); ?></div>
                    <div class="dblg-stat-label"><?php _e('IP unici attaccanti (24h)', 'db-login-guard'); ?></div>
                </div>
                <div class="dblg-stat-card">
                    <div class="dblg-stat-number"><?php echo esc_html($active_blocks); ?></div>
                    <div class="dblg-stat-label"><?php _e('IP bloccati ora', 'db-login-guard'); ?></div>
                </div>
                <div class="dblg-stat-card">
                    <div class="dblg-stat-number"><?php echo esc_html($stats['total']); ?></div>
                    <div class="dblg-stat-label"><?php _e('Eventi totali nel log', 'db-login-guard'); ?></div>
                </div>
            </div>

            <?php if ($stats['top_username']): ?>
            <div class="dblg-info-box">
                <strong><?php _e('Username più attaccato:', 'db-login-guard'); ?></strong>
                <code><?php echo esc_html($stats['top_username']); ?></code>
            </div>
            <?php endif; ?>

            <div class="dblg-info-box">
                <strong><?php _e('Il tuo IP:', 'db-login-guard'); ?></strong>
                <code><?php echo esc_html(DBLG_Guard::get_client_ip()); ?></code>
                <?php
                $my_ip = DBLG_Guard::get_client_ip();
                $whitelist = DB_Login_Guard::get_option('dblg_whitelist_ips');
                $wl_ips = array_filter(array_map('trim', explode("\n", $whitelist)));
                if (in_array($my_ip, $wl_ips)) {
                    echo ' <span class="dblg-badge dblg-badge-green">' . __('Whitelisted', 'db-login-guard') . '</span>';
                } else {
                    echo ' <span class="dblg-badge dblg-badge-yellow">' . __('Non in whitelist', 'db-login-guard') . '</span>';
                }
                ?>
            </div>

            <p class="dblg-config-summary">
                <?php printf(
                    __('Configurazione: blocco dopo %d tentativi falliti in %d minuti, durata blocco %d minuti.', 'db-login-guard'),
                    intval(DB_Login_Guard::get_option('dblg_max_attempts')),
                    intval(DB_Login_Guard::get_option('dblg_lockout_window')),
                    intval(DB_Login_Guard::get_option('dblg_lockout_minutes'))
                ); ?>
            </p>

            <div class="dblg-hardening-status">
                <h3><?php _e('Hardening', 'db-login-guard'); ?></h3>
                <p>
                    <strong>XML-RPC:</strong>
                    <?php if (DB_Login_Guard::get_option('dblg_disable_xmlrpc')): ?>
                        <span class="dblg-badge dblg-badge-green"><?php _e('Disabilitato', 'db-login-guard'); ?></span>
                    <?php else: ?>
                        <span class="dblg-badge dblg-badge-yellow"><?php _e('Attivo', 'db-login-guard'); ?></span>
                    <?php endif; ?>

                    &nbsp;&nbsp;
                    <strong>REST API /users:</strong>
                    <?php if (DB_Login_Guard::get_option('dblg_restrict_rest_users')): ?>
                        <span class="dblg-badge dblg-badge-green"><?php _e('Protetto', 'db-login-guard'); ?></span>
                    <?php else: ?>
                        <span class="dblg-badge dblg-badge-yellow"><?php _e('Pubblico', 'db-login-guard'); ?></span>
                    <?php endif; ?>
                </p>
            </div>
        </div>
        <?php
    }

    /* ─── Log Tab ─── */

    private function render_log_tab() {
        $per_page = 50;
        $current_page = max(1, intval($_GET['paged'] ?? 1));
        $filter_status = sanitize_key($_GET['status'] ?? '');
        $filter_ip = sanitize_text_field($_GET['filter_ip'] ?? '');
        $filter_user = sanitize_text_field($_GET['filter_user'] ?? '');

        $args = [
            'per_page' => $per_page,
            'page'     => $current_page,
            'status'   => $filter_status,
            'ip'       => $filter_ip,
            'username' => $filter_user,
        ];

        $entries = DBLG_Database::get_log($args);
        $total = DBLG_Database::count_log($args);
        $total_pages = ceil($total / $per_page);
        ?>

        <!-- Filters -->
        <div class="dblg-filters">
            <form method="get" action="">
                <input type="hidden" name="page" value="db-login-guard">
                <input type="hidden" name="tab" value="log">

                <label for="dblg-filter-status" class="screen-reader-text"><?php _e('Filtra per stato', 'db-login-guard'); ?></label>
                <select name="status" id="dblg-filter-status">
                    <option value=""><?php _e('Tutti gli stati', 'db-login-guard'); ?></option>
                    <option value="failed" <?php selected($filter_status, 'failed'); ?>><?php _e('Falliti', 'db-login-guard'); ?></option>
                    <option value="success" <?php selected($filter_status, 'success'); ?>><?php _e('Riusciti', 'db-login-guard'); ?></option>
                    <option value="blocked" <?php selected($filter_status, 'blocked'); ?>><?php _e('Bloccati', 'db-login-guard'); ?></option>
                </select>

                <label for="dblg-filter-ip" class="screen-reader-text"><?php _e('Filtra per IP', 'db-login-guard'); ?></label>
                <input type="text" name="filter_ip" id="dblg-filter-ip" value="<?php echo esc_attr($filter_ip); ?>" placeholder="<?php esc_attr_e('Filtra IP...', 'db-login-guard'); ?>" class="regular-text" style="width:150px;">

                <label for="dblg-filter-user" class="screen-reader-text"><?php _e('Filtra per username', 'db-login-guard'); ?></label>
                <input type="text" name="filter_user" id="dblg-filter-user" value="<?php echo esc_attr($filter_user); ?>" placeholder="<?php esc_attr_e('Filtra username...', 'db-login-guard'); ?>" class="regular-text" style="width:150px;">

                <button type="submit" class="button"><?php _e('Filtra', 'db-login-guard'); ?></button>

                <?php if ($filter_status || $filter_ip || $filter_user): ?>
                    <a href="<?php echo esc_url(admin_url('tools.php?page=db-login-guard&tab=log')); ?>" class="button"><?php _e('Reset', 'db-login-guard'); ?></a>
                <?php endif; ?>

                <span class="dblg-filter-actions">
                    <button type="button" class="button" id="dblg-clear-log"><?php _e('Svuota log', 'db-login-guard'); ?></button>
                    <button type="button" class="button" id="dblg-export-log"><?php _e('Esporta CSV', 'db-login-guard'); ?></button>
                </span>
            </form>
        </div>

        <p class="dblg-count">
            <?php printf(
                _n('%s evento trovato', '%s eventi trovati', $total, 'db-login-guard'),
                number_format_i18n($total)
            ); ?>
        </p>

        <table class="wp-list-table widefat fixed striped" role="table">
            <thead>
                <tr>
                    <th scope="col" style="width:140px;"><?php _e('Data/ora', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:130px;"><?php _e('IP', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:150px;"><?php _e('Username', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:90px;"><?php _e('Stato', 'db-login-guard'); ?></th>
                    <th scope="col"><?php _e('User Agent', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:100px;"><?php _e('Azioni', 'db-login-guard'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($entries)): ?>
                    <tr><td colspan="6"><?php _e('Nessun evento registrato.', 'db-login-guard'); ?></td></tr>
                <?php else: ?>
                    <?php foreach ($entries as $entry): ?>
                        <tr>
                            <td><?php echo esc_html(wp_date('d/m/Y H:i:s', strtotime($entry->created_at))); ?></td>
                            <td><code><?php echo esc_html($entry->ip_address); ?></code></td>
                            <td><?php echo esc_html($entry->username ?: '—'); ?></td>
                            <td>
                                <?php
                                $status_classes = [
                                    'failed'  => 'dblg-badge-red',
                                    'success' => 'dblg-badge-green',
                                    'blocked' => 'dblg-badge-orange',
                                ];
                                $status_labels = [
                                    'failed'  => __('Fallito', 'db-login-guard'),
                                    'success' => __('Riuscito', 'db-login-guard'),
                                    'blocked' => __('Bloccato', 'db-login-guard'),
                                ];
                                $cls = $status_classes[$entry->status] ?? 'dblg-badge-gray';
                                $lbl = $status_labels[$entry->status] ?? $entry->status;
                                ?>
                                <span class="dblg-badge <?php echo esc_attr($cls); ?>"><?php echo esc_html($lbl); ?></span>
                            </td>
                            <td class="dblg-ua-cell" title="<?php echo esc_attr($entry->user_agent); ?>">
                                <?php echo esc_html(mb_strimwidth($entry->user_agent, 0, 60, '…')); ?>
                            </td>
                            <td>
                                <?php if ($entry->status === 'failed' || $entry->status === 'blocked'): ?>
                                    <?php
                                    $block_url = wp_nonce_url(
                                        admin_url('tools.php?page=db-login-guard&action=dblg_block&ip=' . urlencode($entry->ip_address)),
                                        'dblg_block_ip'
                                    );
                                    ?>
                                    <a href="<?php echo esc_url($block_url); ?>" class="button button-small" title="<?php esc_attr_e('Blocca IP', 'db-login-guard'); ?>">
                                        <?php _e('Blocca', 'db-login-guard'); ?>
                                    </a>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <?php
        // Pagination
        if ($total_pages > 1) {
            $base_url = admin_url('tools.php?page=db-login-guard&tab=log');
            if ($filter_status) $base_url .= '&status=' . urlencode($filter_status);
            if ($filter_ip) $base_url .= '&filter_ip=' . urlencode($filter_ip);
            if ($filter_user) $base_url .= '&filter_user=' . urlencode($filter_user);

            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links([
                'base'    => $base_url . '&paged=%#%',
                'format'  => '',
                'current' => $current_page,
                'total'   => $total_pages,
                'prev_text' => '&laquo;',
                'next_text' => '&raquo;',
            ]);
            echo '</div></div>';
        }
    }

    /* ─── Blocked IPs Tab ─── */

    private function render_blocked_tab() {
        $blocked = DBLG_Database::get_blocked_ips();
        $now = current_time('mysql');
        ?>

        <div class="dblg-manual-block">
            <h3><?php _e('Blocca IP manualmente', 'db-login-guard'); ?></h3>
            <form method="get" action="" class="dblg-inline-form">
                <input type="hidden" name="page" value="db-login-guard">
                <input type="hidden" name="action" value="dblg_block">
                <?php wp_nonce_field('dblg_block_ip'); ?>

                <label for="dblg-manual-ip" class="screen-reader-text"><?php _e('Indirizzo IP', 'db-login-guard'); ?></label>
                <input type="text" name="ip" id="dblg-manual-ip" placeholder="<?php esc_attr_e('Indirizzo IP', 'db-login-guard'); ?>" required class="regular-text" style="width:200px;">

                <button type="submit" class="button"><?php _e('Blocca', 'db-login-guard'); ?></button>
            </form>
        </div>

        <table class="wp-list-table widefat fixed striped" role="table">
            <thead>
                <tr>
                    <th scope="col" style="width:140px;"><?php _e('IP', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:80px;"><?php _e('Tentativi', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:150px;"><?php _e('Bloccato il', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:150px;"><?php _e('Scade il', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:100px;"><?php _e('Stato', 'db-login-guard'); ?></th>
                    <th scope="col" style="width:100px;"><?php _e('Azioni', 'db-login-guard'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($blocked)): ?>
                    <tr><td colspan="6"><?php _e('Nessun IP bloccato.', 'db-login-guard'); ?></td></tr>
                <?php else: ?>
                    <?php foreach ($blocked as $b): ?>
                        <?php
                        $is_active = $b->is_permanent || $b->expires_at > $now;
                        $unblock_url = wp_nonce_url(
                            admin_url('tools.php?page=db-login-guard&tab=blocked&action=dblg_unblock&id=' . $b->id),
                            'dblg_unblock_ip'
                        );
                        ?>
                        <tr class="<?php echo $is_active ? '' : 'dblg-expired-row'; ?>">
                            <td><code><?php echo esc_html($b->ip_address); ?></code></td>
                            <td><?php echo esc_html($b->attempts); ?></td>
                            <td><?php echo esc_html(wp_date('d/m/Y H:i', strtotime($b->blocked_at))); ?></td>
                            <td>
                                <?php
                                if ($b->is_permanent) {
                                    _e('Permanente', 'db-login-guard');
                                } else {
                                    echo esc_html(wp_date('d/m/Y H:i', strtotime($b->expires_at)));
                                }
                                ?>
                            </td>
                            <td>
                                <?php if ($is_active): ?>
                                    <span class="dblg-badge dblg-badge-red"><?php _e('Attivo', 'db-login-guard'); ?></span>
                                <?php else: ?>
                                    <span class="dblg-badge dblg-badge-gray"><?php _e('Scaduto', 'db-login-guard'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <a href="<?php echo esc_url($unblock_url); ?>" class="button button-small">
                                    <?php _e('Sblocca', 'db-login-guard'); ?>
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
    }

    /* ─── Settings Tab ─── */

    private function render_settings_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('dblg_settings'); ?>

            <div class="dblg-section">
                <h2><?php _e('Protezione', 'db-login-guard'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Protezione attiva', 'db-login-guard'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="dblg_enabled" value="1" <?php checked(DB_Login_Guard::get_option('dblg_enabled'), 1); ?>>
                                <?php _e('Abilita protezione brute force', 'db-login-guard'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="dblg_max_attempts"><?php _e('Tentativi massimi', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <input type="number" name="dblg_max_attempts" id="dblg_max_attempts" value="<?php echo esc_attr(DB_Login_Guard::get_option('dblg_max_attempts')); ?>" min="1" max="100" class="small-text">
                            <p class="description"><?php _e('Numero di tentativi falliti prima del blocco.', 'db-login-guard'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="dblg_lockout_window"><?php _e('Finestra temporale (minuti)', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <input type="number" name="dblg_lockout_window" id="dblg_lockout_window" value="<?php echo esc_attr(DB_Login_Guard::get_option('dblg_lockout_window')); ?>" min="1" max="1440" class="small-text">
                            <p class="description"><?php _e('I tentativi vengono contati in questa finestra temporale.', 'db-login-guard'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="dblg_lockout_minutes"><?php _e('Durata blocco (minuti)', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <input type="number" name="dblg_lockout_minutes" id="dblg_lockout_minutes" value="<?php echo esc_attr(DB_Login_Guard::get_option('dblg_lockout_minutes')); ?>" min="1" max="10080" class="small-text">
                            <p class="description"><?php _e('Per quanto tempo l\'IP resta bloccato.', 'db-login-guard'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="dblg-section">
                <h2><?php _e('Whitelist IP', 'db-login-guard'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">
                            <label for="dblg_whitelist_ips"><?php _e('IP esclusi dal blocco', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <textarea name="dblg_whitelist_ips" id="dblg_whitelist_ips" rows="5" class="large-text code" placeholder="<?php esc_attr_e("192.168.1.1\n10.0.0.0/8", 'db-login-guard'); ?>"><?php echo esc_textarea(DB_Login_Guard::get_option('dblg_whitelist_ips')); ?></textarea>
                            <p class="description">
                                <?php _e('Un IP per riga. Supporta notazione CIDR (es: 192.168.1.0/24).', 'db-login-guard'); ?>
                                <br>
                                <?php printf(
                                    __('Il tuo IP attuale: %s', 'db-login-guard'),
                                    '<code>' . esc_html(DBLG_Guard::get_client_ip()) . '</code>'
                                ); ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="dblg-section">
                <h2><?php _e('Log', 'db-login-guard'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Login riusciti', 'db-login-guard'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="dblg_log_successful" value="1" <?php checked(DB_Login_Guard::get_option('dblg_log_successful'), 1); ?>>
                                <?php _e('Registra anche i login riusciti', 'db-login-guard'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="dblg_log_retention_days"><?php _e('Conservazione log (giorni)', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <input type="number" name="dblg_log_retention_days" id="dblg_log_retention_days" value="<?php echo esc_attr(DB_Login_Guard::get_option('dblg_log_retention_days')); ?>" min="1" max="365" class="small-text">
                            <p class="description"><?php _e('I record più vecchi vengono eliminati automaticamente ogni giorno.', 'db-login-guard'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="dblg-section">
                <h2><?php _e('Notifiche', 'db-login-guard'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('Email su blocco', 'db-login-guard'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="dblg_email_notify" value="1" <?php checked(DB_Login_Guard::get_option('dblg_email_notify'), 1); ?>>
                                <?php _e('Invia email quando un IP viene bloccato', 'db-login-guard'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="dblg_email_address"><?php _e('Indirizzo email', 'db-login-guard'); ?></label>
                        </th>
                        <td>
                            <input type="email" name="dblg_email_address" id="dblg_email_address" value="<?php echo esc_attr(DB_Login_Guard::get_option('dblg_email_address')); ?>" class="regular-text" placeholder="<?php echo esc_attr(get_option('admin_email')); ?>">
                            <p class="description"><?php _e('Lascia vuoto per usare l\'email dell\'amministratore.', 'db-login-guard'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="dblg-section">
                <h2><?php _e('Hardening', 'db-login-guard'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php _e('XML-RPC', 'db-login-guard'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="dblg_disable_xmlrpc" value="1" <?php checked(DB_Login_Guard::get_option('dblg_disable_xmlrpc'), 1); ?>>
                                <?php _e('Disabilita XML-RPC completamente', 'db-login-guard'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Blocca xmlrpc.php con errore 403. Rimuove l\'header X-Pingback e i link RSD/WLW.', 'db-login-guard'); ?>
                                <br>
                                <?php _e('XML-RPC è un protocollo legacy usato da vecchie app e dai pingback. I bot lo sfruttano per brute force via system.multicall. Se non usi l\'app WordPress desktop (quella vecchia) o integrazioni che richiedono xmlrpc.php esplicitamente, disabilitalo.', 'db-login-guard'); ?>
                            </p>
                            <?php
                            // Show current status
                            $xmlrpc_disabled = DB_Login_Guard::get_option('dblg_disable_xmlrpc');
                            if ($xmlrpc_disabled) {
                                echo '<p><span class="dblg-badge dblg-badge-green">' . esc_html__('XML-RPC disabilitato', 'db-login-guard') . '</span></p>';
                            } else {
                                echo '<p><span class="dblg-badge dblg-badge-yellow">' . esc_html__('XML-RPC attivo', 'db-login-guard') . '</span></p>';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('REST API /users', 'db-login-guard'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="dblg_restrict_rest_users" value="1" <?php checked(DB_Login_Guard::get_option('dblg_restrict_rest_users'), 1); ?>>
                                <?php _e('Blocca /wp/v2/users per utenti non autenticati', 'db-login-guard'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Impedisce ai visitatori anonimi di elencare gli utenti del sito tramite la REST API. Gli utenti loggati e Gutenberg continuano a funzionare normalmente.', 'db-login-guard'); ?>
                                <br>
                                <?php _e('Per default WordPress espone la lista degli username su /wp-json/wp/v2/users — un regalo per chi fa brute force.', 'db-login-guard'); ?>
                            </p>
                            <?php
                            $rest_restricted = DB_Login_Guard::get_option('dblg_restrict_rest_users');
                            if ($rest_restricted) {
                                echo '<p><span class="dblg-badge dblg-badge-green">' . esc_html__('Endpoint /users protetto', 'db-login-guard') . '</span></p>';
                            } else {
                                echo '<p><span class="dblg-badge dblg-badge-yellow">' . esc_html__('Endpoint /users pubblico', 'db-login-guard') . '</span></p>';
                            }
                            ?>
                        </td>
                    </tr>
                </table>
            </div>

            <?php submit_button(__('Salva impostazioni', 'db-login-guard')); ?>
        </form>
        <?php
    }

    public function ajax_unblock_ip() {
        check_ajax_referer('dblg_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permesso negato.', 'db-login-guard'));
        }

        $id = intval($_POST['id'] ?? 0);
        if ($id > 0) {
            DBLG_Database::unblock_ip($id);
            wp_send_json_success();
        }
        wp_send_json_error();
    }

    /* ─── AJAX: Block IP ─── */

    public function ajax_block_ip() {
        check_ajax_referer('dblg_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permesso negato.', 'db-login-guard'));
        }

        $ip = sanitize_text_field($_POST['ip'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $lockout = intval(DB_Login_Guard::get_option('dblg_lockout_minutes'));
            DBLG_Database::block_ip($ip, $lockout, 0);
            wp_send_json_success();
        }
        wp_send_json_error(__('IP non valido.', 'db-login-guard'));
    }

    /* ─── AJAX: Clear Log ─── */

    public function ajax_clear_log() {
        check_ajax_referer('dblg_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permesso negato.', 'db-login-guard'));
        }

        DBLG_Database::clear_log();
        wp_send_json_success();
    }

    /* ─── AJAX: Export CSV ─── */

    public function ajax_export_log() {
        check_ajax_referer('dblg_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permesso negato.', 'db-login-guard'));
        }

        $entries = DBLG_Database::get_log(['per_page' => 10000, 'page' => 1]);

        $csv = "Data/ora,IP,Username,Stato,User Agent,Errore\n";
        foreach ($entries as $e) {
            $csv .= sprintf(
                '"%s","%s","%s","%s","%s","%s"' . "\n",
                $e->created_at,
                $e->ip_address,
                $e->username,
                $e->status,
                str_replace('"', '""', $e->user_agent),
                str_replace('"', '""', $e->error_message)
            );
        }

        wp_send_json_success(['csv' => $csv, 'filename' => 'login-guard-log-' . wp_date('Y-m-d') . '.csv']);
    }
}
