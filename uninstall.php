<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete plugin options from the database
delete_option('wordpress_proxy_host');
delete_option('wordpress_proxy_port');
delete_option('wordpress_proxy_user');
delete_option('wordpress_proxy_pass');
delete_option('wordpress_proxy_log_level');
delete_option('wordpress_proxy_log_path');
delete_option('wordpress_proxy_log_max_size');
delete_option('wordpress_proxy_domains');

/**
 * Function to safely delete the plugin's log directory and its contents.
 *
 * @param string $dir The directory to delete.
 */
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

    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item == '.' || $item == '..') {
            continue;
        }

        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            // Recursively delete subdirectories
            wordpress_proxy_logger_safe_delete_directory($path);
        } else {
            // Delete individual files
            @unlink($path);
        }
    }

    // Remove the directory itself
    @rmdir($dir);
}

// Get the log directory path
$log_path = get_option('wordpress_proxy_log_path', WP_CONTENT_DIR . '/logs/wordpress-proxy.log');
$log_dir = dirname($log_path);

// Safely remove the log directory and all its contents
wordpress_proxy_logger_safe_delete_directory($log_dir);
