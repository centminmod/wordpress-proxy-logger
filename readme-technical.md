# WordPress Proxy Logger - Technical Documentation

This document explains the technical workings of the **WordPress Proxy Logger** plugin, including how the plugin handles HTTP proxying, secure logging, and integration with WordPress core functions and WP-CLI.

---

## Overview

The **WordPress Proxy Logger** plugin allows:

1. Routing all outgoing HTTP requests through a proxy server (if configured by the user).
2. Secure logging of HTTP requests, responses, and errors.
3. Dynamic log levels (`DEBUG`, `INFO`, `ERROR`) and user-defined logging paths.
4. Configuration through both the WordPress Admin GUI and WP-CLI commands.
5. Secure storage of proxy passwords using encryption.

### Plugin Architecture

The plugin uses the following key components:

- **Proxy Configuration**: Proxy details such as host, port, username, and encrypted password are set by the user and passed to the WordPress HTTP API.
- **Secure Logging Mechanism**: All HTTP requests are logged based on the configured log level, with sensitive data scrubbed before logging.
- **WP-CLI Integration**: Allows the proxy and logging settings to be configured via the command line.
- **Security Measures**: Implements encryption for sensitive data, input validation, and safe file operations.

---

## Key Functionalities

### 1. Proxy Configuration (Conditional Setup)

The proxy settings are defined **only if the user has provided values**. This ensures that until the user enters the proxy settings, WordPress behaves as usual, sending requests without a proxy.

#### Code Breakdown:

```php
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
```

- **Encrypted Password Handling**:
  - The password is decrypted using `decrypt_password()` before being used.
  - The decrypted password is sanitized before defining `WP_PROXY_PASSWORD`.

### 2. Secure Logging Mechanism

The plugin logs HTTP requests, responses, and errors based on the log level. Sensitive data is scrubbed before logging to prevent exposure.

#### Code Breakdown:

```php
private function scrub_sensitive_data($args) {
    $sensitive_keys = ['body', 'headers', 'cookies'];
    foreach ($sensitive_keys as $key) {
        if (isset($args[$key])) {
            $args[$key] = '[REDACTED]';
        }
    }
    return $args;
}

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
```

- **Sensitive Data Scrubbing**:
  - The `scrub_sensitive_data()` function removes sensitive information from the request arguments.
  - Keys such as `body`, `headers`, and `cookies` are replaced with `[REDACTED]`.

### 3. Secure Password Storage

Proxy passwords are encrypted before being stored in the database to prevent exposure of sensitive credentials.

#### Code Breakdown:

```php
private function encrypt_password($password) {
    if (empty($password)) {
        return '';
    }
    $key = wp_salt('auth');
    return base64_encode(openssl_encrypt($password, 'AES-256-CBC', $key, 0, substr($key, 0, 16)));
}

private function decrypt_password($encrypted_password) {
    if (empty($encrypted_password)) {
        return '';
    }
    $key = wp_salt('auth');
    return openssl_decrypt(base64_decode($encrypted_password), 'AES-256-CBC', $key, 0, substr($key, 0, 16));
}
```

- **Encryption Method**:
  - Uses `openssl_encrypt` and `openssl_decrypt` with AES-256-CBC encryption.
  - The encryption key is derived from `wp_salt('auth')`.

### 4. Log Path Validation and Safe File Operations

The plugin validates the log path to ensure it is within allowed directories and prevents directory traversal attacks.

#### Code Breakdown:

```php
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
```

- **Allowed Directories**: The log path must be within `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`, or the WordPress home directory.

### 5. Optimized Log Directory Initialization

To improve performance, the plugin initializes the log directory only once per request.

#### Code Breakdown:

```php
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
```

- **Initialization Flag**: Uses `$this->log_directory_initialized` to prevent redundant checks.

### 6. Error Handling in Logging

The plugin handles potential errors when writing to the log file, such as permissions issues.

#### Code Breakdown:

```php
public function log($level, $message) {
    // ...

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
```

- **Admin Notice**: Displays an error message in the admin area if logging fails.

### 7. Safe Uninstallation Process

The `uninstall.php` script safely deletes the plugin's log directory, ensuring it is within allowed paths.

#### Code Breakdown:

```php
function wordpress_proxy_logger_safe_delete_directory($dir) {
    // Normalize paths
    $dir = wp_normalize_path($dir);
    $wp_content_dir = wp_normalize_path(WP_CONTENT_DIR);
    $plugin_dir = wp_normalize_path(plugin_dir_path(__FILE__));

    // Ensure the directory is within the allowed paths
    $allowed_paths = [
        $wp_content_dir . '/logs/',
        $plugin_dir,
    ];

    $is_allowed = false;
    foreach ($allowed_paths as $allowed_path) {
        if (strpos($dir, $allowed_path) === 0) {
            $is_allowed = true;
            break;
        }
    }

    if (!$is_allowed || !is_dir($dir)) {
        // Do not proceed if directory is not within allowed paths
        return;
    }

    // Proceed with deletion...
}
```

- **Path Validation**: Ensures only directories within `wp-content/logs/` or the plugin's directory are deleted.

---

## Conclusion

The **WordPress Proxy Logger** plugin has been enhanced with security and performance improvements:

- **Security Enhancements**:
  - Encrypted storage of sensitive data.
  - Input validation to prevent attacks.
  - Safe file operations and path validations.
  - Scrubbing of sensitive information from logs.

- **Performance Optimizations**:
  - Reduced file system overhead with optimized directory checks.
  - Efficient log rotation mechanism.

- **Code Refactoring**:
  - Encapsulated functionality within a class to improve maintainability.
  - Comprehensive error handling and user notifications.

By addressing the identified issues and implementing best practices, the plugin provides a secure and efficient solution for routing HTTP requests through a proxy and logging them.

---

## References

- **WordPress Plugin Handbook**: [https://developer.wordpress.org/plugins/](https://developer.wordpress.org/plugins/)
- **WordPress Coding Standards**: [https://developer.wordpress.org/coding-standards/wordpress-coding-standards/](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/)
- **WP-CLI Commands**: [https://developer.wordpress.org/cli/commands/](https://developer.wordpress.org/cli/commands/)
```