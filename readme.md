# WordPress Proxy Logger

WordPress Proxy Logger is a plugin that allows you to route outgoing HTTP requests via an HTTP forward proxy and log those requests securely. You can configure log verbosity (`DEBUG`, `INFO`, `ERROR`), specify the path where logs should be saved, set a maximum log file size, and selectively route requests through the proxy based on user-defined domains or patterns. This plugin supports both WordPress Admin configuration and WP-CLI commands for headless environments.

## Features

- **Selective HTTP Forward Proxy**: Route specific outgoing WordPress HTTP requests via a proxy based on domains or patterns.
- **Secure Logging**: Capture detailed logs of HTTP requests while scrubbing sensitive data.
- **Dynamic Log Levels**: Choose between `DEBUG`, `INFO`, and `ERROR` for logging.
- **Custom Log File Path**: Specify the path where logs should be saved, with validation to prevent directory traversal attacks.
- **Maximum Log File Size**: Set a limit on the log file size to enable log rotation.
- **WP-CLI Support**: Configure proxy settings, log levels, log paths, max log size, and proxy domains via WP-CLI.
- **Secure Password Storage**: Proxy passwords are encrypted before storing in the database.

## Installation

1. **Download or Clone the Repository**:
   ```bash
   git clone https://github.com/centminmod/wordpress-proxy-logger.git wp-content/plugins/wordpress-proxy-logger
   ```

2. **Activate the Plugin**:
   - **Via WordPress Admin Dashboard**:
     - Log in to your WordPress admin panel.
     - Navigate to **Plugins > Installed Plugins**.
     - Find **WordPress Proxy Logger** in the list and click **Activate**.
   - **Via WP-CLI**:
     ```bash
     wp plugin activate wordpress-proxy-logger
     ```

## Configuration

### Admin Dashboard

1. **Navigate to the Settings**:
   - Go to your WordPress dashboard and navigate to **Settings > WordPress Proxy Logger**.

2. **Configure Proxy Settings**:
   - **Proxy Host**: Enter the host of your proxy server (e.g., `proxy.example.com`).
   - **Proxy Port**: Enter the port your proxy server is using (e.g., `8080`).
   - **Proxy Username** (optional): If your proxy requires authentication, enter your username.
   - **Proxy Password** (optional): Enter your proxy password. This field will be blank when you revisit the settings for security reasons. Leave it blank to keep the existing password.

3. **Set Proxy Domains**:
   - **Proxy Domains**: Enter one domain or pattern per line. Use `*` as a wildcard.
     - Example:
       ```
       *.wordpress.org
       api.example.com
       ```

4. **Set Log Level**:
   - **DEBUG**: Logs all HTTP requests and responses.
   - **INFO**: Logs general information, such as successful requests.
   - **ERROR**: Logs only errors and failures.

5. **Set Log Path**:
   - Enter the file path where you want to save the log entries (e.g., `wp-content/logs/proxy.log`).
   - **Note**: The log path must be within the WordPress content or plugin directories for security reasons.

6. **Set Maximum Log File Size**:
   - Specify the maximum size (in bytes) for the log file before it rotates (e.g., `1048576` for 1MB).

7. **Save Settings**: Click the **Save Changes** button to apply your settings.

### WP-CLI Usage

#### Set Proxy Settings

You can configure the proxy settings via the command line using WP-CLI:

```bash
wp wordpress-proxy-logger configure <host> <port> [--username=<username>] [--password=<password>]
```

**Examples**:

- Configure a proxy without authentication:
  ```bash
  wp wordpress-proxy-logger configure proxy.example.com 8080
  ```

- Configure a proxy with authentication:
  ```bash
  wp wordpress-proxy-logger configure proxy.example.com 8080 --username=myuser --password=mypass
  ```

#### Set Proxy Domains

To specify the domains or patterns for which requests should be routed through the proxy:

```bash
wp wordpress-proxy-logger set-proxy-domains <domain1> [<domain2> ...]
```

**Examples**:

- Set proxy domains:
  ```bash
  wp wordpress-proxy-logger set-proxy-domains "*.wordpress.org" "api.example.com"
  ```

- Clear proxy domains (use empty quotes):
  ```bash
  wp wordpress-proxy-logger set-proxy-domains ""
  ```

#### Set Log Level

To set the log level using WP-CLI:

```bash
wp wordpress-proxy-logger set-log-level <level>
```

Where `<level>` can be one of:

- `DEBUG`: Logs all requests and responses.
- `INFO`: Logs general information.
- `ERROR`: Logs only errors and failures.

**Example**:

- Set log level to `DEBUG`:
  ```bash
  wp wordpress-proxy-logger set-log-level DEBUG
  ```

#### Set Log Path

To specify where the logs should be saved:

```bash
wp wordpress-proxy-logger set-log-path <path>
```

**Note**: The log path must be within the WordPress content or plugin directories.

**Example**:

- Set log path to `wp-content/logs/proxy.log`:
  ```bash
  wp wordpress-proxy-logger set-log-path wp-content/logs/proxy.log
  ```

#### Set Max Log Size

To limit the maximum size of the log file in bytes:

```bash
wp wordpress-proxy-logger set-max-log-size <size>
```

**Example**:

- Set max log size to 1MB (1,048,576 bytes):
  ```bash
  wp wordpress-proxy-logger set-max-log-size 1048576
  ```

### Log File

The log file will be saved at the specified path. By default, it is located at `wp-content/logs/wordpress-proxy.log`.

To view logs in real-time, you can use the following command on Linux/macOS:

```bash
tail -f /path/to/log/file.log
```

## Security

- **Encrypted Password Storage**: Proxy passwords are encrypted before being stored in the WordPress options table.
- **Protected Admin Settings**: The proxy password field is not pre-populated in the settings page to prevent exposure.
- **Input Validation**: All user inputs are sanitized and validated to prevent security vulnerabilities.
- **Safe File Operations**: The plugin validates file paths to prevent directory traversal attacks and only allows operations within specific directories.
- **Selective Proxying**: Only requests to specified domains are routed through the proxy, reducing unnecessary exposure.
- **Sensitive Data Scrubbing**: Logs are scrubbed to remove sensitive information from request arguments.

## Example Scenarios

### Use Case: Proxying Requests to Specific Domains

1. Define the domains or patterns you want to route through the proxy in the settings or via WP-CLI.
2. Only HTTP requests to those domains will be routed through the proxy, while others bypass it.

### Use Case: Debugging HTTP Requests

1. Set the log level to `DEBUG` to capture all HTTP requests and responses.
2. Monitor the logs at the specified path to inspect details such as request URLs and response codes. Sensitive data in request arguments will be redacted.

### Use Case: Proxy Authentication

1. Configure the proxy settings via the admin panel or WP-CLI with your proxy's host, port, username, and password.
2. Ensure all outgoing HTTP requests to specified domains are routed through your authenticated proxy server.

## Changelog

### v0.5

- **Selective Proxying**:
  - Added ability to route only specific domains through the proxy using `pre_http_send_through_proxy` filter.
  - Users can define domains or patterns in settings or via WP-CLI.
- **Security Enhancements**:
  - Encrypted storage of proxy passwords.
  - Password field in settings is no longer pre-populated.
  - Input validation for log paths to prevent directory traversal.
  - Safe deletion of log directories during uninstallation.
  - Scrubbing of sensitive data from logs.
- **Performance Improvements**:
  - Optimized file system checks for log directory initialization.
  - Improved log rotation mechanism.
- **Code Refactoring**:
  - Encapsulated functionality within a class.
  - Added comprehensive error handling.
  - Enhanced documentation and comments.