# WordPress Proxy Logger

WordPress Proxy Logger is a plugin that allows you to route outgoing HTTP requests via an HTTP forward proxy, and log those requests. You can also configure log verbosity (`DEBUG`, `INFO`, `ERROR`) and specify the path where logs should be saved. This plugin supports both WordPress Admin configuration and WP-CLI commands for headless environments.

## Features

- **HTTP Forward Proxy**: Route outgoing WordPress HTTP requests via a proxy.
- **Logging**: Capture detailed logs of HTTP requests, responses, and errors.
- **Dynamic Log Levels**: Choose between `DEBUG`, `INFO`, and `ERROR` for logging.
- **Custom Log File Path**: Specify the path where logs should be saved.
- **WP-CLI Support**: Configure proxy settings, log levels, and log paths via WP-CLI.

## Installation

1. Clone or download the repository and upload it to the `wp-content/plugins` directory.
   ```bash
   git clone https://github.com/centminmod/wordpress-proxy-logger.git wp-content/plugins/wordpress-proxy-logger
   ```

2. **Activate the Plugin**:
   - Activate via the WordPress Admin Dashboard.
   - Or use WP-CLI:

     ```bash
     wp plugin activate wordpress-proxy-logger
     ```

## Configuration

### Admin Dashboard

1. **Navigate to the Settings**:
   - Go to your WordPress dashboard and navigate to **Settings > Wordpress Proxy Logger**.
   
2. **Configure Proxy Settings**:
   - **Proxy Host**: Enter the host of your proxy server (e.g., `proxy.example.com`).
   - **Proxy Port**: Enter the port your proxy server is using (e.g., `8080`).
   - **Proxy Username** (optional): If your proxy requires authentication, enter your username.
   - **Proxy Password** (optional): Enter your proxy password.
   
3. **Set Log Level**:
   - **DEBUG**: Logs all HTTP requests, responses, and additional details.
   - **INFO**: Logs general information, such as successful requests.
   - **ERROR**: Logs only errors and failures.

4. **Set Log Path**:
   - Enter the file path where you want to save the log entries (e.g., `/var/log/proxy.log`).

5. **Save Settings**: Click the **Save Changes** button to apply your settings.

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

**Example**:
- Set log path to `/var/log/proxy.log`:
  ```bash
  wp wordpress-proxy-logger set-log-path /var/log/proxy.log
  ```

### Log File

The log file will be saved at the specified path. By default, it is located at `wp-content/logs/proxy.log`.

To view logs in real-time, you can use the following command on Linux/macOS:

```bash
tail -f /path/to/log/file.log
```

## Example Scenarios

### Use Case: Debugging HTTP Requests

1. Set the log level to `DEBUG` to capture all HTTP requests and responses.
2. Navigate to the logs at the specified path to inspect details such as request headers, responses, and error codes.

### Use Case: Proxy Authentication

1. Configure the proxy settings via the admin panel or WP-CLI with your proxy's host, port, username, and password.
2. Ensure all outgoing HTTP requests from WordPress are routed through your proxy server.

### Use Case: Custom Log Path

1. Set the custom log path in the admin panel or WP-CLI to store logs in a secure or external location.
2. Use the new path to monitor logs as needed.

## Security

- Proxy passwords are stored securely in the WordPress options table and are sanitized before being saved.
- Nonces are used to protect the admin settings page from unauthorized changes.
- Sensitive information, such as proxy credentials, should be carefully handled and monitored for security risks.

## Changelog

### v0.2
- Added support for custom log paths.
- Added WP-CLI command to configure log path.
- Improved logging functionality.