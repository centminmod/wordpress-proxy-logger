<?php
/**
 * Plugin Name: WordPress Proxy Logger
 * Description: Enables and logs HTTP forward proxy for WordPress cURL requests, with WP-CLI support for unattended configuration and dynamic log levels.
 * Version: 0.3
 * Author: George Liu
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WORDPRESS_PROXY_LOGGER_LOG_LEVELS', ['DEBUG', 'INFO', 'ERROR']);

/**
 * Set the proxy constants based on options or fallbacks.
 * These constants will configure the WordPress HTTP API to use a proxy server.
 */
function wordpress_proxy_logger_define_constants() {
    // Only define proxy settings if the user has explicitly set them.
    $proxy_host = get_option('wordpress_proxy_host');
    $proxy_port = get_option('wordpress_proxy_port');

    if ($proxy_host && $proxy_port) {
        if (!defined('WP_PROXY_HOST')) {
            define('WP_PROXY_HOST', $proxy_host);
        }

        if (!defined('WP_PROXY_PORT')) {
            define('WP_PROXY_PORT', $proxy_port);
        }

        // Define username and password only if set by the user.
        $proxy_user = get_option('wordpress_proxy_user');
        $proxy_pass = get_option('wordpress_proxy_pass');

        if (!defined('WP_PROXY_USERNAME') && !empty($proxy_user)) {
            define('WP_PROXY_USERNAME', sanitize_text_field($proxy_user));
        }

        if (!defined('WP_PROXY_PASSWORD') && !empty($proxy_pass)) {
            define('WP_PROXY_PASSWORD', sanitize_text_field($proxy_pass));
        }
    }
}
add_action('plugins_loaded', 'wordpress_proxy_logger_define_constants');

/**
 * Get the path where log files should be saved.
 *
 * @return string The path where logs will be saved.
 */
function wordpress_proxy_logger_get_log_path() {
    $log_path = get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log');

    $log_dir = dirname($log_path);
    if (!file_exists($log_dir)) {
        mkdir($log_dir, 0700, true); // Use restrictive permissions
    }

    return $log_path;
}

/**
 * Retrieve the configured log level.
 *
 * @return string The log level (e.g., 'DEBUG', 'INFO', 'ERROR').
 */
function wordpress_proxy_logger_get_log_level() {
    $log_level = get_option('wordpress_proxy_log_level', 'INFO');
    return in_array($log_level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS) ? $log_level : 'INFO';
}

/**
 * Get the configured maximum log file size.
 *
 * @return int|null The maximum log size in bytes or null if no limit is set.
 */
function wordpress_proxy_logger_get_max_log_size() {
    $max_size = get_option('wordpress_proxy_log_max_size');
    return !empty($max_size) ? absint($max_size) : null;
}

/**
 * Rotate the log file if it exceeds the maximum allowed size.
 *
 * @param string $log_path The path to the log file.
 */
function wordpress_proxy_logger_rotate_log_file($log_path) {
    $max_size = wordpress_proxy_logger_get_max_log_size();

    if ($max_size && file_exists($log_path) && filesize($log_path) >= $max_size) {
        rename($log_path, $log_path . '.' . time());
    }
}

/**
 * Log messages based on the current log level.
 *
 * @param string $level The log level for this message ('DEBUG', 'INFO', 'ERROR').
 * @param string $message The message to log.
 */
function wordpress_proxy_logger_log($level, $message) {
    $current_level = wordpress_proxy_logger_get_log_level();
    $log_priority = array_search($current_level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS);
    $message_priority = array_search($level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS);

    if ($message_priority >= $log_priority) {
        $log_path = wordpress_proxy_logger_get_log_path();
        wordpress_proxy_logger_rotate_log_file($log_path); // Check for log rotation

        $log_message = sprintf("[%s] %s: %s\n", date('Y-m-d H:i:s'), $level, $message);
        error_log($log_message, 3, $log_path);
    }
}

/**
 * Hook into the HTTP API to log details of each outgoing request.
 *
 * @param array|WP_Error $response The HTTP response or WP_Error object.
 * @param string $type The type of response ('response' or 'request').
 * @param string $class The transport used (e.g., 'WP_Http_Curl').
 * @param array $args Arguments for the HTTP request.
 * @param string $url The URL the request was made to.
 */
function wordpress_proxy_logger_http_request_log($response, $type, $class, $args, $url) {
    if ($type === 'response') {
        $response_code = is_wp_error($response) ? 'WP_Error' : $response['response']['code'];
        $log_message = sprintf("HTTP Request to: %s | Response Code: %s | Request Args: %s", esc_url_raw($url), $response_code, json_encode($args));

        wordpress_proxy_logger_log('DEBUG', $log_message);
    }
}
add_action('http_api_debug', 'wordpress_proxy_logger_http_request_log', 10, 5);

/**
 * Register WP-CLI commands for configuring the proxy, log level, log path, and log size.
 */
if (defined('WP_CLI') && WP_CLI) {
    class WordPress_Proxy_Logger_CLI {
        /**
         * Configure proxy settings.
         *
         * ## OPTIONS
         *
         * <host>
         * : The proxy host.
         *
         * <port>
         * : The proxy port.
         *
         * [--username=<username>]
         * : The proxy username (optional).
         *
         * [--password=<password>]
         * : The proxy password (optional).
         *
         * ## EXAMPLES
         *
         * wp wordpress-proxy-logger configure proxy.example.com 8080 --username=myuser --password=mypass
         */
        public function configure($args, $assoc_args) {
            list($host, $port) = $args;

            update_option('wordpress_proxy_host', sanitize_text_field($host));
            update_option('wordpress_proxy_port', absint($port));

            if (!empty($assoc_args['username'])) {
                update_option('wordpress_proxy_user', sanitize_text_field($assoc_args['username']));
            }
            if (!empty($assoc_args['password'])) {
                update_option('wordpress_proxy_pass', sanitize_text_field($assoc_args['password']));
            }

            WP_CLI::success('Proxy settings updated successfully.');
        }

        /**
         * Configure log level.
         *
         * ## OPTIONS
         *
         * <level>
         * : The log level (DEBUG, INFO, ERROR).
         *
         * ## EXAMPLES
         *
         * wp wordpress-proxy-logger set-log-level DEBUG
         */
        public function set_log_level($args) {
            $level = strtoupper($args[0]);

            if (in_array($level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS)) {
                update_option('wordpress_proxy_log_level', $level);
                WP_CLI::success("Log level set to $level.");
            } else {
                WP_CLI::error("Invalid log level. Choose from: DEBUG, INFO, ERROR.");
            }
        }

        /**
         * Set the path for saving log files.
         *
         * ## OPTIONS
         *
         * <path>
         * : The file path where logs should be saved.
         *
         * ## EXAMPLES
         *
         * wp wordpress-proxy-logger set-log-path /var/log/proxy.log
         */
        public function set_log_path($args) {
            $path = sanitize_text_field($args[0]);

            $log_dir = dirname($path);
            if (!file_exists($log_dir)) {
                mkdir($log_dir, 0700, true);
            }

            update_option('wordpress_proxy_log_path', $path);
            WP_CLI::success("Log path set to $path.");
        }

        /**
         * Set the maximum log file size.
         *
         * ## OPTIONS
         *
         * <size>
         * : The maximum log file size in bytes (e.g., 1048576 for 1MB).
         *
         * ## EXAMPLES
         *
         * wp wordpress-proxy-logger set-max-log-size 1048576
         */
        public function set_max_log_size($args) {
            $size = absint($args[0]);

            if ($size > 0) {
                update_option('wordpress_proxy_log_max_size', $size);
                WP_CLI::success("Max log size set to $size bytes.");
            } else {
                WP_CLI::error("Invalid size. Please enter a positive integer.");
            }
        }
    }

    WP_CLI::add_command('wordpress-proxy-logger', 'WordPress_Proxy_Logger_CLI');
}

/**
 * Add the WordPress Proxy Logger settings page in the WordPress admin.
 */
function wordpress_proxy_logger_settings_page() {
    add_options_page(
        'WordPress Proxy Logger Settings',
        'WordPress Proxy Logger',
        'manage_options',
        'wordpress-proxy-logger',
        'wordpress_proxy_logger_settings_html'
    );
}
add_action('admin_menu', 'wordpress_proxy_logger_settings_page');

/**
 * Display the settings page HTML.
 */
function wordpress_proxy_logger_settings_html() {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (isset($_POST['submit'])) {
        check_admin_referer('wordpress_proxy_logger_settings');

        update_option('wordpress_proxy_host', sanitize_text_field($_POST['wordpress_proxy_host']));
        update_option('wordpress_proxy_port', absint($_POST['wordpress_proxy_port']));
        update_option('wordpress_proxy_user', sanitize_text_field($_POST['wordpress_proxy_user']));
        update_option('wordpress_proxy_pass', sanitize_text_field($_POST['wordpress_proxy_pass']));
        update_option('wordpress_proxy_log_level', strtoupper(sanitize_text_field($_POST['wordpress_proxy_log_level'])));
        update_option('wordpress_proxy_log_path', sanitize_text_field($_POST['wordpress_proxy_log_path']));
        update_option('wordpress_proxy_log_max_size', absint($_POST['wordpress_proxy_log_max_size']));

        echo '<div class="updated"><p>Settings saved.</p></div>';
    }

    $proxy_host = esc_attr(get_option('wordpress_proxy_host'));
    $proxy_port = esc_attr(get_option('wordpress_proxy_port'));
    $proxy_user = esc_attr(get_option('wordpress_proxy_user'));
    $proxy_pass = esc_attr(get_option('wordpress_proxy_pass'));
    $proxy_log_level = esc_attr(get_option('wordpress_proxy_log_level', 'INFO'));
    $proxy_log_path = esc_attr(get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log'));
    $proxy_log_max_size = esc_attr(get_option('wordpress_proxy_log_max_size', ''));

    ?>
    <div class="wrap">
        <h1>WordPress Proxy Logger Settings</h1>
        <form method="post">
            <?php wp_nonce_field('wordpress_proxy_logger_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="wordpress_proxy_host">Proxy Host</label></th>
                    <td><input name="wordpress_proxy_host" type="text" id="wordpress_proxy_host" value="<?php echo $proxy_host; ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_port">Proxy Port</label></th>
                    <td><input name="wordpress_proxy_port" type="number" id="wordpress_proxy_port" value="<?php echo $proxy_port; ?>" class="small-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_user">Proxy Username</label></th>
                    <td><input name="wordpress_proxy_user" type="text" id="wordpress_proxy_user" value="<?php echo $proxy_user; ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_pass">Proxy Password</label></th>
                    <td><input name="wordpress_proxy_pass" type="password" id="wordpress_proxy_pass" value="<?php echo $proxy_pass; ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_log_level">Log Level</label></th>
                    <td>
                        <select name="wordpress_proxy_log_level" id="wordpress_proxy_log_level">
                            <?php foreach (WORDPRESS_PROXY_LOGGER_LOG_LEVELS as $level) : ?>
                                <option value="<?php echo $level; ?>" <?php selected($proxy_log_level, $level); ?>><?php echo $level; ?></option>
                            <?php endforeach; ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_log_path">Log Path</label></th>
                    <td><input name="wordpress_proxy_log_path" type="text" id="wordpress_proxy_log_path" value="<?php echo $proxy_log_path; ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wordpress_proxy_log_max_size">Max Log Size (bytes)</label></th>
                    <td><input name="wordpress_proxy_log_max_size" type="number" id="wordpress_proxy_log_max_size" value="<?php echo $proxy_log_max_size; ?>" class="regular-text"></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

/**
 * Register settings fields for WordPress Proxy Logger.
 */
function wordpress_proxy_logger_register_settings() {
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_host', ['sanitize_callback' => 'sanitize_text_field']);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_port', ['sanitize_callback' => 'absint']);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_user', ['sanitize_callback' => 'sanitize_text_field']);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_pass', ['sanitize_callback' => 'sanitize_text_field']);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_level', [
        'sanitize_callback' => function($value) {
            $value = strtoupper(sanitize_text_field($value));
            return in_array($value, WORDPRESS_PROXY_LOGGER_LOG_LEVELS) ? $value : 'INFO';
        }
    ]);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_path', ['sanitize_callback' => 'sanitize_text_field']);
    register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_max_size', ['sanitize_callback' => 'absint']);
}
add_action('admin_init', 'wordpress_proxy_logger_register_settings');

