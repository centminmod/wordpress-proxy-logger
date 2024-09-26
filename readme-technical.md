# WordPress Proxy Logger - Technical Documentation

This document explains the technical workings of the **WordPress Proxy Logger** plugin, including how the plugin handles HTTP proxying, logging, and integration with the WordPress core functions and WP-CLI.

---

## Overview

The **WordPress Proxy Logger** plugin allows:
1. Routing all outgoing HTTP requests through a proxy server (if configured by the user).
2. Logging of HTTP requests, responses, and errors.
3. Dynamic log levels (`DEBUG`, `INFO`, `ERROR`) and user-defined logging paths.
4. Configuration through both the WordPress Admin GUI and WP-CLI commands.

### Plugin Architecture

The plugin uses the following key components:
- **Proxy Configuration**: Proxy details such as host, port, username, and password are set by the user and passed to the WordPress HTTP API.
- **Logging Mechanism**: All HTTP requests are logged based on the configured log level.
- **WP-CLI Integration**: Allows the proxy and logging settings to be configured via the command line.

---

## Key Functionalities

### 1. Proxy Configuration (Conditional Setup)

To prevent the plugin from using a proxy by default, the proxy settings are defined **only if the user has provided values**. This ensures that until the user enters the proxy settings, WordPress behaves as usual, sending requests without a proxy.

#### Code Breakdown:

```php
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
add_action('init', 'wordpress_proxy_logger_define_constants');
```

- **get_option()**: Retrieves the proxy settings from the WordPress database. If no settings are found, it means the user has not set them.
- **define()**: The proxy constants (`WP_PROXY_HOST`, `WP_PROXY_PORT`, etc.) are only defined if both the proxy host and port are set by the user.
- **sanitize_text_field()**: Ensures that input is sanitized to prevent potential security issues (like XSS).
  
By making the constants conditional, the plugin only activates proxy routing once the user has explicitly set up a proxy server. Until then, WordPress makes normal, direct HTTP requests.

### 2. Logging Mechanism

The plugin supports logging HTTP requests, responses, and errors based on the log level (`DEBUG`, `INFO`, `ERROR`) and logs messages to a file specified by the user. The log file is created at the specified path, and the directory is automatically created if it does not exist.

#### Code Breakdown:

```php
function wordpress_proxy_logger_log($level, $message) {
    $current_level = wordpress_proxy_logger_get_log_level();
    $log_priority = array_search($current_level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS);
    $message_priority = array_search($level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS);

    if ($message_priority >= $log_priority) {
        $log_message = sprintf("[%s] %s: %s\n", date('Y-m-d H:i:s'), $level, $message);
        error_log($log_message, 3, wordpress_proxy_logger_get_log_path());
    }
}
```

- **wordpress_proxy_logger_get_log_level()**: Retrieves the current log level set by the user. It defaults to `INFO` if not set.
- **array_search()**: Determines the priority of log levels, ensuring that lower-priority levels (like `ERROR`) still get logged if the log level is set to a higher priority (like `DEBUG`).
- **error_log()**: Logs the message to a file. The `3` flag indicates that the third parameter is a file path, so the message is appended to that file.

#### Log Path

```php
function wordpress_proxy_logger_get_log_path() {
    $log_path = get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log');

    $log_dir = dirname($log_path);
    if (!file_exists($log_dir)) {
        mkdir($log_dir, 0755, true);
    }

    return $log_path;
}
```

- **get_option()**: Retrieves the custom log path from the database. If no log path is set, it defaults to `wp-content/logs/wordpress-proxy.log`.
- **mkdir()**: Creates the log directory if it does not exist.

### 3. HTTP API Logging Hook

The plugin uses the `http_api_debug` action hook to capture all HTTP requests and responses made by WordPress. This allows detailed logging of HTTP request information, including URL, response codes, and request arguments.

#### Code Breakdown:

```php
function wordpress_proxy_logger_http_request_log($response, $type, $class, $args, $url) {
    if ($type === 'response') {
        $response_code = is_wp_error($response) ? 'WP_Error' : $response['response']['code'];
        $log_message = sprintf("HTTP Request to: %s | Response Code: %s | Request Args: %s", esc_url_raw($url), $response_code, json_encode($args));

        wordpress_proxy_logger_log('DEBUG', $log_message);
    }
}
add_action('http_api_debug', 'wordpress_proxy_logger_http_request_log', 10, 5);
```

- **http_api_debug**: This action fires during any HTTP request made through the WordPress HTTP API.
- **is_wp_error()**: Checks whether the response was an error or a successful response.
- **esc_url_raw()**: Escapes the URL for safe logging.
- **json_encode()**: Encodes the request arguments to a JSON string for easier logging.

### 4. WP-CLI Integration

The plugin provides a set of WP-CLI commands for configuring the proxy settings, log levels, and log paths. This allows for automation and remote configuration without accessing the WordPress admin interface.

#### WP-CLI Command Breakdown:

1. **Configure Proxy**:
   ```php
   wp wordpress-proxy-logger configure <host> <port> [--username=<username>] [--password=<password>]
   ```

2. **Set Log Level**:
   ```php
   wp wordpress-proxy-logger set-log-level <level>
   ```

3. **Set Log Path**:
   ```php
   wp wordpress-proxy-logger set-log-path <path>
   ```

#### Code Breakdown:

```php
if (defined('WP_CLI') && WP_CLI) {
    class WordPress_Proxy_Logger_CLI {
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

        public function set_log_level($args) {
            $level = strtoupper($args[0]);

            if (in_array($level, WORDPRESS_PROXY_LOGGER_LOG_LEVELS)) {
                update_option('wordpress_proxy_log_level', $level);
                WP_CLI::success("Log level set to $level.");
            } else {
                WP_CLI::error("Invalid log level. Choose from: DEBUG, INFO, ERROR.");
            }
        }

        public function set_log_path($args) {
            $path = sanitize_text_field($args[0]);

            $log_dir = dirname($path);
            if (!file_exists($log_dir)) {
                mkdir($log_dir, 0755, true);
            }

            update_option('wordpress_proxy_log_path', $path);
            WP_CLI::success("Log path set to $path.");
        }
    }

    WP_CLI::add_command('wordpress-proxy-logger', 'WordPress_Proxy_Logger_CLI');
}
```

- **WP_CLI::add_command()**: Registers the custom WP-CLI commands.
- **update_option()**: Stores the proxy, log level, or log path settings in the WordPress database.
- **sanitize_text_field()** and **absint()**: Sanitize the input to prevent security issues.

### 5. Admin Settings Page

The plugin adds a settings page to the WordPress admin area where the user can configure proxy settings, log levels, and log paths through a form.

#### Code Breakdown:

```php
function wordpress_proxy_logger_settings_page() {
    add_options_page(
        'WordPress Proxy Logger Settings',
        'WordPress Proxy Logger',
        'manage_options', 'wordpress-proxy-logger', 'wordpress_proxy_logger_settings_html'
    );
}
add_action('admin_menu', 'wordpress_proxy_logger_settings_page');
```

- **add_options_page()**: Adds a new settings page under the "Settings" section of the WordPress admin dashboard. It allows users to access and configure the plugin’s options from the WordPress GUI.

#### Rendering the Settings Page:

```php
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

        echo '<div class="updated"><p>Settings saved.</p></div>';
    }

    $proxy_host = esc_attr(get_option('wordpress_proxy_host'));
    $proxy_port = esc_attr(get_option('wordpress_proxy_port'));
    $proxy_user = esc_attr(get_option('wordpress_proxy_user'));
    $proxy_pass = esc_attr(get_option('wordpress_proxy_pass'));
    $proxy_log_level = esc_attr(get_option('wordpress_proxy_log_level', 'INFO'));
    $proxy_log_path = esc_attr(get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log'));

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
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}
```

- **current_user_can()**: Checks if the current user has the necessary permission to manage settings.
- **wp_nonce_field()**: Adds a security nonce to the form to prevent CSRF attacks.
- **esc_attr()**: Escapes the retrieved options to ensure they are safe for use in HTML output.
- **submit_button()**: Outputs the default WordPress "Save" button for the form.

The form allows users to configure proxy settings, log levels, and log paths directly from the WordPress dashboard. Upon submission, the input is sanitized, validated, and saved using `update_option()`.

---

### 6. Settings Registration

The plugin uses `register_setting()` to securely handle the saving and validation of settings input via both the admin settings page and WP-CLI.

#### Code Breakdown:

```php
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
}
add_action('admin_init', 'wordpress_proxy_logger_register_settings');
```

- **register_setting()**: Registers settings for the plugin, with a corresponding sanitization callback to ensure data integrity.
- **sanitize_callback**: This ensures that the user input is cleaned before being stored in the database.

This function ensures that when users save settings via either the admin page or WP-CLI, the data is properly sanitized and securely stored.

---

## Conclusion

The **WordPress Proxy Logger** plugin is a flexible solution for managing and logging WordPress HTTP requests through a proxy. The proxy setup is only enabled once the user specifies proxy details, ensuring no defaults are applied that could affect performance or privacy. It also provides detailed logging capabilities and supports WP-CLI commands for advanced users and automation tasks.

Key features:
- **Proxy Configuration**: Users can configure HTTP proxy settings via the dashboard or WP-CLI.
- **Dynamic Logging**: Users can control log verbosity and specify where logs are saved.
- **Admin and WP-CLI Support**: Both user-friendly GUI and powerful command-line options are available for configuring the plugin.

This setup ensures that the plugin only influences WordPress behavior when explicitly configured, making it a lightweight, secure, and user-friendly tool for managing HTTP requests.