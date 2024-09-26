<?php
/**
 * Plugin Name: WordPress Proxy Logger
 * Description: Enables and logs HTTP forward proxy for WordPress cURL requests, with WP-CLI support for unattended configuration and dynamic log levels.
 * Version: 0.4
 * Author: George Liu
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WORDPRESS_PROXY_LOGGER_LOG_LEVELS', ['DEBUG', 'INFO', 'ERROR']);

if (!class_exists('WordPress_Proxy_Logger')) {
    class WordPress_Proxy_Logger {

        /**
         * Log priority level.
         *
         * @var int
         */
        private $log_priority = null;

        /**
         * Indicates whether the log directory has been initialized.
         *
         * @var bool
         */
        private $log_directory_initialized = false;

        /**
         * Singleton instance.
         *
         * @var WordPress_Proxy_Logger
         */
        private static $instance = null;

        /**
         * Get the singleton instance.
         *
         * @return WordPress_Proxy_Logger
         */
        public static function get_instance() {
            if (self::$instance === null) {
                self::$instance = new self();
                self::$instance->setup();
            }
            return self::$instance;
        }

        /**
         * Setup plugin functionalities.
         */
        public function setup() {
            add_action('plugins_loaded', [$this, 'define_constants']);
            add_action('http_api_debug', [$this, 'http_request_log'], 10, 5);
            add_action('admin_menu', [$this, 'settings_page']);
            add_action('admin_init', [$this, 'register_settings']);
        }

        /**
         * Define proxy constants based on options or fallbacks.
         */
        public function define_constants() {
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
                $proxy_pass_encrypted = get_option('wordpress_proxy_pass');

                if (!defined('WP_PROXY_USERNAME') && !empty($proxy_user)) {
                    define('WP_PROXY_USERNAME', sanitize_text_field($proxy_user));
                }

                if (!defined('WP_PROXY_PASSWORD') && !empty($proxy_pass_encrypted)) {
                    $proxy_pass = $this->decrypt_password($proxy_pass_encrypted);
                    define('WP_PROXY_PASSWORD', sanitize_text_field($proxy_pass));
                }
            }

            // Set log priority once to avoid multiple checks in logging function.
            $this->log_priority = array_search($this->get_log_level(), WORDPRESS_PROXY_LOGGER_LOG_LEVELS);
        }

        /**
         * Get the path where log files should be saved.
         *
         * @return string The path where logs will be saved.
         */
        public function get_log_path() {
            $log_path = get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log');

            // Validate the log path to prevent directory traversal attacks.
            $log_path = wp_normalize_path($log_path);

            // Ensure the log path is within allowed directories.
            $allowed_dirs = [
                wp_normalize_path(WP_CONTENT_DIR),
                wp_normalize_path(WP_PLUGIN_DIR),
                wp_normalize_path(get_home_path()),
            ];

            $is_allowed = false;
            foreach ($allowed_dirs as $dir) {
                if (strpos($log_path, $dir) === 0) {
                    $is_allowed = true;
                    break;
                }
            }

            if (!$is_allowed) {
                // Fallback to default log path.
                $log_path = WP_CONTENT_DIR . '/logs/wordpress-proxy.log';
            }

            return $log_path;
        }

        /**
         * Initialize the log directory if not already done.
         */
        private function initialize_log_directory() {
            if ($this->log_directory_initialized) {
                return;
            }

            $log_path = $this->get_log_path();
            $log_dir = dirname($log_path);
            if (!file_exists($log_dir)) {
                wp_mkdir_p($log_dir);
                // Set directory permissions to 0755.
                chmod($log_dir, 0755);
            }

            $this->log_directory_initialized = true;
        }

        /**
         * Retrieve the configured log level.
         *
         * @return string The log level (e.g., 'DEBUG', 'INFO', 'ERROR').
         */
        public function get_log_level() {
            $log_level = get_option('wordpress_proxy_log_level', 'INFO');
            return in_array($log_level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS) ? $log_level : 'INFO';
        }

        /**
         * Get the configured maximum log file size.
         *
         * @return int|null The maximum log size in bytes or null if no limit is set.
         */
        public function get_max_log_size() {
            $max_size = get_option('wordpress_proxy_log_max_size');
            return !empty($max_size) ? absint($max_size) : null;
        }

        /**
         * Rotate the log file if it exceeds the maximum allowed size.
         *
         * @param string $log_path The path to the log file.
         */
        public function rotate_log_file($log_path) {
            $max_size = $this->get_max_log_size();

            if ($max_size && file_exists($log_path) && filesize($log_path) >= $max_size) {
                $rotated = @rename($log_path, $log_path . '.' . time());
                if (!$rotated) {
                    $this->log_priority = array_search('ERROR', WORDPRESS_PROXY_LOGGER_LOG_LEVELS);
                    $this->log('ERROR', 'Failed to rotate log file.');
                }
            }
        }

        /**
         * Log messages based on the current log level.
         *
         * @param string $level The log level for this message ('DEBUG', 'INFO', 'ERROR').
         * @param string $message The message to log.
         */
        public function log($level, $message) {
            $message_priority = array_search($level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS);

            if ($message_priority >= $this->log_priority) {
                $this->initialize_log_directory();

                $log_path = $this->get_log_path();
                $this->rotate_log_file($log_path); // Check for log rotation

                $log_message = sprintf("[%s] %s: %s\n", date('Y-m-d H:i:s'), $level, $message);
                $logged = @error_log($log_message, 3, $log_path);

                if (!$logged) {
                    // Handle logging failure
                    if (is_admin() && current_user_can('manage_options')) {
                        add_action('admin_notices', function() {
                            echo '<div class="error"><p>WordPress Proxy Logger: Failed to write to log file. Please check file permissions.</p></div>';
                        });
                    }
                }
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
        public function http_request_log($response, $type, $class, $args, $url) {
            if ($type === 'response') {
                $response_code = is_wp_error($response) ? 'WP_Error' : $response['response']['code'];

                // Scrub sensitive data from args
                $scrubbed_args = $this->scrub_sensitive_data($args);

                $log_message = sprintf(
                    "HTTP Request to: %s | Response Code: %s | Request Args: %s",
                    esc_url_raw($url),
                    $response_code,
                    json_encode($scrubbed_args)
                );

                $this->log('DEBUG', $log_message);
            }
        }

        /**
         * Scrub sensitive information from request arguments before logging.
         *
         * @param array $args The original request arguments.
         * @return array The sanitized request arguments.
         */
        private function scrub_sensitive_data($args) {
            $sensitive_keys = ['body', 'headers', 'cookies'];
            foreach ($sensitive_keys as $key) {
                if (isset($args[$key])) {
                    $args[$key] = '[REDACTED]';
                }
            }
            return $args;
        }

        /**
         * Encrypt the proxy password before storing it.
         *
         * @param string $password The plain text password.
         * @return string The encrypted password.
         */
        private function encrypt_password($password) {
            if (empty($password)) {
                return '';
            }
            $key = wp_salt('auth');
            return base64_encode(openssl_encrypt($password, 'AES-256-CBC', $key, 0, substr($key, 0, 16)));
        }

        /**
         * Decrypt the proxy password when retrieving it.
         *
         * @param string $encrypted_password The encrypted password.
         * @return string The decrypted password.
         */
        private function decrypt_password($encrypted_password) {
            if (empty($encrypted_password)) {
                return '';
            }
            $key = wp_salt('auth');
            return openssl_decrypt(base64_decode($encrypted_password), 'AES-256-CBC', $key, 0, substr($key, 0, 16));
        }

        /**
         * Add the settings page to the WordPress admin.
         */
        public function settings_page() {
            add_options_page(
                'WordPress Proxy Logger Settings',
                'WordPress Proxy Logger',
                'manage_options',
                'wordpress-proxy-logger',
                [$this, 'settings_page_html']
            );
        }

        /**
         * Display the settings page HTML.
         */
        public function settings_page_html() {
            if (!current_user_can('manage_options')) {
                return;
            }

            if (isset($_POST['submit'])) {
                check_admin_referer('wordpress_proxy_logger_settings');

                update_option('wordpress_proxy_host', sanitize_text_field($_POST['wordpress_proxy_host']));
                update_option('wordpress_proxy_port', absint($_POST['wordpress_proxy_port']));
                update_option('wordpress_proxy_user', sanitize_text_field($_POST['wordpress_proxy_user']));

                // Encrypt the password before storing
                if (!empty($_POST['wordpress_proxy_pass'])) {
                    $encrypted_pass = $this->encrypt_password($_POST['wordpress_proxy_pass']);
                    update_option('wordpress_proxy_pass', $encrypted_pass);
                }

                update_option('wordpress_proxy_log_level', strtoupper(sanitize_text_field($_POST['wordpress_proxy_log_level'])));
                update_option('wordpress_proxy_log_path', sanitize_text_field($_POST['wordpress_proxy_log_path']));
                update_option('wordpress_proxy_log_max_size', absint($_POST['wordpress_proxy_log_max_size']));

                echo '<div class="updated"><p>Settings saved.</p></div>';
            }

            $proxy_host = esc_attr(get_option('wordpress_proxy_host'));
            $proxy_port = esc_attr(get_option('wordpress_proxy_port'));
            $proxy_user = esc_attr(get_option('wordpress_proxy_user'));
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
                            <td>
                                <input name="wordpress_proxy_pass" type="password" id="wordpress_proxy_pass" value="" class="regular-text" autocomplete="off">
                                <p class="description">Leave blank to keep the current password.</p>
                            </td>
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
        public function register_settings() {
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_host', ['sanitize_callback' => 'sanitize_text_field']);
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_port', ['sanitize_callback' => 'absint']);
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_user', ['sanitize_callback' => 'sanitize_text_field']);
            // Password is encrypted, so no need for a sanitize callback here
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_pass');
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_level', [
                'sanitize_callback' => function ($value) {
                    $value = strtoupper(sanitize_text_field($value));
                    return in_array($value, WORDPRESS_PROXY_LOGGER_LOG_LEVELS) ? $value : 'INFO';
                }
            ]);
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_path', ['sanitize_callback' => 'sanitize_text_field']);
            register_setting('wordpress_proxy_logger_settings', 'wordpress_proxy_log_max_size', ['sanitize_callback' => 'absint']);
        }
    }

    // Initialize the plugin.
    WordPress_Proxy_Logger::get_instance();
}

/**
 * Register WP-CLI commands for configuring the proxy, log level, log path, and log size.
 */
if (defined('WP_CLI') && WP_CLI && !class_exists('WordPress_Proxy_Logger_CLI')) {
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
                $logger = WordPress_Proxy_Logger::get_instance();
                $encrypted_pass = $logger->encrypt_password($assoc_args['password']);
                update_option('wordpress_proxy_pass', $encrypted_pass);
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

            // Validate the log path to prevent directory traversal attacks.
            $path = wp_normalize_path($path);

            // Ensure the log path is within allowed directories.
            $allowed_dirs = [
                wp_normalize_path(WP_CONTENT_DIR),
                wp_normalize_path(WP_PLUGIN_DIR),
                wp_normalize_path(get_home_path()),
            ];

            $is_allowed = false;
            foreach ($allowed_dirs as $dir) {
                if (strpos($path, $dir) === 0) {
                    $is_allowed = true;
                    break;
                }
            }

            if (!$is_allowed) {
                WP_CLI::error("Invalid log path. The path must be within the WordPress content or plugin directories.");
                return;
            }

            $log_dir = dirname($path);
            if (!file_exists($log_dir)) {
                wp_mkdir_p($log_dir);
                // Set directory permissions to 0755.
                chmod($log_dir, 0755);
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
