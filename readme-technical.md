# WordPress Proxy Logger - Technical Documentation

This document explains the technical workings of the **WordPress Proxy Logger** plugin, including how the plugin handles HTTP proxying, secure logging, selective proxying based on domains, and integration with WordPress core functions and WP-CLI.

---

## Overview

The **WordPress Proxy Logger** plugin allows:

1. **Selective HTTP Proxying**: Routing outgoing HTTP requests through a proxy server based on user-defined domains or patterns.
2. **Secure Logging**: Logging of HTTP requests, responses, and errors, with sensitive data scrubbed.
3. **Dynamic Log Levels**: User-defined logging verbosity (`DEBUG`, `INFO`, `ERROR`).
4. **Configuration**: Through both the WordPress Admin GUI and WP-CLI commands.
5. **Secure Password Storage**: Encryption of proxy passwords before storage.

### Plugin Architecture

The plugin uses the following key components:

- **Proxy Configuration**: User-provided proxy settings and domains/patterns determine which requests are routed through the proxy.
- **Selective Proxying**: Utilizes the `pre_http_send_through_proxy` filter to decide per-request proxy usage.
- **Secure Logging Mechanism**: Logs are written based on the configured log level, with sensitive data removed.
- **WP-CLI Integration**: Commands to configure proxy settings, log levels, log paths, max log size, and proxy domains.
- **Security Measures**: Encryption for sensitive data, input validation, safe file operations, and error handling.

---

## Key Functionalities

### 1. Selective Proxying Using `pre_http_send_through_proxy`

The plugin allows users to specify domains or patterns for which HTTP requests should be routed through the proxy.

#### Code Breakdown:

```php
public function filter_send_through_proxy($preempt, $uri) {
    // If no proxy domains are set, default to the existing behavior.
    if (empty($this->proxy_domains)) {
        return $preempt;
    }

    $use_proxy = false;
    $parsed_url = parse_url($uri);
    $host = isset($parsed_url['host']) ? $parsed_url['host'] : '';

    foreach ($this->proxy_domains as $pattern) {
        $pattern = trim($pattern);

        // Convert wildcard patterns to regex.
        $regex = '/' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '/i';

        if (preg_match($regex, $host)) {
            $use_proxy = true;
            break;
        }
    }

    return $use_proxy;
}
```

- **Pattern Matching**:
  - Supports wildcards (`*`) in domain patterns.
  - Converts patterns to regular expressions for matching against request hosts.

- **Filter Hook**:
  - Hooked into `pre_http_send_through_proxy`.
  - Determines per-request whether to use the proxy.

### 2. Loading and Managing Proxy Domains

#### Code Breakdown:

```php
private function load_proxy_domains() {
    $domains_option = get_option('wordpress_proxy_domains', '');
    $domains_option = sanitize_textarea_field($domains_option);

    if (!empty($domains_option)) {
        $domains = explode("\n", $domains_option);
        $domains = array_map('trim', $domains);
        $domains = array_filter($domains);
        $this->proxy_domains = $domains;
    } else {
        $this->proxy_domains = [];
    }
}
```

- **Sanitization and Parsing**:
  - Sanitizes the stored domains.
  - Splits the input by new lines and trims whitespace.
  - Stores the domains in the `$proxy_domains` property.

### 3. Updated Settings Page

#### Code Breakdown:

```php
// In settings_page_html()
<tr>
    <th scope="row"><label for="wordpress_proxy_domains">Proxy Domains</label></th>
    <td>
        <textarea name="wordpress_proxy_domains" id="wordpress_proxy_domains" rows="5" class="large-text code"><?php echo $proxy_domains; ?></textarea>
        <p class="description">Enter one domain or pattern per line. Use '*' as a wildcard. For example: '*.wordpress.org'</p>
    </td>
</tr>
```

- **User Input**:
  - Allows users to input domains or patterns in a textarea.
  - Provides guidance on using wildcards.

- **Handling Form Submission**:
  - Sanitizes and saves the input.
  - Calls `load_proxy_domains()` to update the domains in use.

### 4. WP-CLI Integration for Proxy Domains

#### Code Breakdown:

```php
public function set_proxy_domains($args) {
    if (empty($args)) {
        WP_CLI::error("Please provide at least one domain or pattern.");
        return;
    }

    $domains = array_map('sanitize_text_field', $args);
    $domains_string = implode("\n", $domains);

    update_option('wordpress_proxy_domains', $domains_string);

    // Reload proxy domains in the logger instance
    $logger = WordPress_Proxy_Logger::get_instance();
    $logger->load_proxy_domains();

    WP_CLI::success("Proxy domains updated successfully.");
}
```

- **Command Usage**:
  - Allows setting multiple domains or patterns via command-line arguments.
  - Sanitizes inputs and updates the option.

### 5. Security Enhancements

- **Encrypted Password Storage**:
  - Uses `openssl_encrypt` and `openssl_decrypt` with AES-256-CBC.
  - Key derived from `wp_salt('auth')`.

- **Input Validation**:
  - All inputs are sanitized using appropriate WordPress functions.
  - Log paths are validated to be within allowed directories.

- **Sensitive Data Scrubbing**:
  - Sensitive request data (e.g., `body`, `headers`, `cookies`) are redacted before logging.

- **Safe File Operations**:
  - Log directory initialization is optimized and permissions are set appropriately.
  - Uninstall script safely deletes plugin-specific directories.

### 6. Performance Optimizations

- **Optimized Log Directory Initialization**:
  - Checks and creates the log directory only once per request.
  - Reduces file system overhead.

- **Efficient Log Rotation**:
  - Log file size is checked before writing logs.
  - Logs are rotated when they exceed the specified maximum size.

---

## Conclusion

The **WordPress Proxy Logger** plugin provides a secure and flexible solution for managing HTTP requests through a proxy, with the added ability to selectively route requests based on domains or patterns. The plugin incorporates security best practices and performance optimizations to ensure safe and efficient operation.
