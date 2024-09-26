<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete plugin options on uninstall
delete_option('wordpress_proxy_host');
delete_option('wordpress_proxy_port');
delete_option('wordpress_proxy_user');
delete_option('wordpress_proxy_pass');
delete_option('wordpress_proxy_log_level');
delete_option('wordpress_proxy_log_path');
delete_option('wordpress_proxy_log_max_size');
