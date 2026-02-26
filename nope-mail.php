<?php
/**
 * Plugin Name: NopeMail
 * Description: Blocks account registrations that use disallowed email patterns.
 * Version: 1.0.0
 * Author: NopeMail
 * Text Domain: nopemail
 */

if (!defined('ABSPATH')) {
    exit;
}

final class NopeMail_Plugin
{
    private const OPTION_KEY = 'nopemail_blocked_patterns';

    public static function init(): void
    {
        add_action('admin_menu', [__CLASS__, 'add_settings_page']);
        add_action('admin_init', [__CLASS__, 'register_setting']);

        if (is_multisite()) {
            add_action('network_admin_menu', [__CLASS__, 'add_network_settings_page']);
            add_action('network_admin_edit_nopemail_save_network_settings', [__CLASS__, 'save_network_settings']);
        }

        add_filter('registration_errors', [__CLASS__, 'filter_registration_errors'], 10, 3);
        add_filter('wpmu_validate_user_signup', [__CLASS__, 'filter_multisite_signup_errors']);
        add_filter('woocommerce_registration_errors', [__CLASS__, 'filter_woocommerce_registration_errors'], 10, 3);
    }

    public static function add_settings_page(): void
    {
        add_options_page(
            __('NopeMail', 'nopemail'),
            __('NopeMail', 'nopemail'),
            'manage_options',
            'nopemail',
            [__CLASS__, 'render_settings_page']
        );
    }

    public static function register_setting(): void
    {
        register_setting(
            'nopemail_settings',
            self::OPTION_KEY,
            [
                'type' => 'string',
                'sanitize_callback' => [__CLASS__, 'sanitize_patterns_input'],
                'default' => '',
            ]
        );

        add_settings_section(
            'nopemail_main_section',
            __('Blocked email rules', 'nopemail'),
            static function (): void {
                echo '<p>' . esc_html__('Enter one rule per line. Rules can be full addresses (test@example.com), domains (@spam.com), or partial matches (.ru).', 'nopemail') . '</p>';
            },
            'nopemail'
        );

        add_settings_field(
            self::OPTION_KEY,
            __('Rules', 'nopemail'),
            [__CLASS__, 'render_rules_field'],
            'nopemail',
            'nopemail_main_section'
        );
    }

    public static function render_rules_field(): void
    {
        $value = get_option(self::OPTION_KEY, '');
        echo '<textarea name="' . esc_attr(self::OPTION_KEY) . '" rows="12" cols="60" class="large-text code">' . esc_textarea($value) . '</textarea>';
    }

    public static function render_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('NopeMail Settings', 'nopemail') . '</h1>';
        echo '<form method="post" action="options.php">';
        settings_fields('nopemail_settings');
        do_settings_sections('nopemail');
        submit_button();
        echo '</form>';
        echo '</div>';
    }

    public static function add_network_settings_page(): void
    {
        add_submenu_page(
            'settings.php',
            __('NopeMail', 'nopemail'),
            __('NopeMail', 'nopemail'),
            'manage_network_options',
            'nopemail-network',
            [__CLASS__, 'render_network_settings_page']
        );
    }

    public static function render_network_settings_page(): void
    {
        if (!current_user_can('manage_network_options')) {
            return;
        }

        $value = get_site_option(self::OPTION_KEY, '');

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('NopeMail Network Settings', 'nopemail') . '</h1>';
        echo '<form method="post" action="edit.php?action=nopemail_save_network_settings">';
        wp_nonce_field('nopemail_network_settings');
        echo '<p>' . esc_html__('Enter one rule per line. Network rules are applied on every site.', 'nopemail') . '</p>';
        echo '<textarea name="' . esc_attr(self::OPTION_KEY) . '" rows="12" cols="60" class="large-text code">' . esc_textarea($value) . '</textarea>';
        submit_button(__('Save Changes', 'nopemail'));
        echo '</form>';
        echo '</div>';
    }

    public static function save_network_settings(): void
    {
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'nopemail'));
        }

        check_admin_referer('nopemail_network_settings');

        $raw = isset($_POST[self::OPTION_KEY]) ? wp_unslash((string) $_POST[self::OPTION_KEY]) : '';
        $sanitized = self::sanitize_patterns_input($raw);
        update_site_option(self::OPTION_KEY, $sanitized);

        wp_safe_redirect(add_query_arg(['page' => 'nopemail-network', 'updated' => 'true'], network_admin_url('settings.php')));
        exit;
    }

    public static function sanitize_patterns_input(string $value): string
    {
        $rules = self::normalize_rules($value);
        return implode("\n", $rules);
    }

    /**
     * @return string[]
     */
    private static function normalize_rules(string $raw): array
    {
        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        $rules = [];

        foreach ($parts as $part) {
            $rule = strtolower(trim((string) $part));
            if ($rule === '') {
                continue;
            }
            $rules[$rule] = $rule;
        }

        return array_values($rules);
    }

    /**
     * @return string[]
     */
    private static function get_all_rules(): array
    {
        $site_rules = self::normalize_rules((string) get_option(self::OPTION_KEY, ''));
        if (!is_multisite()) {
            return $site_rules;
        }

        $network_rules = self::normalize_rules((string) get_site_option(self::OPTION_KEY, ''));
        return array_values(array_unique(array_merge($network_rules, $site_rules)));
    }

    private static function is_email_blocked(string $email): bool
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return false;
        }

        foreach (self::get_all_rules() as $rule) {
            if (self::matches_rule($email, $rule)) {
                return true;
            }
        }

        return false;
    }

    private static function matches_rule(string $email, string $rule): bool
    {
        if ($rule === '') {
            return false;
        }

        if (strpos($rule, '@') !== false && $rule[0] !== '@') {
            return $email === $rule;
        }

        if (strpos($rule, '@') === 0) {
            return substr($email, -strlen($rule)) === $rule;
        }

        return strpos($email, $rule) !== false;
    }

    public static function filter_registration_errors(WP_Error $errors, string $sanitized_user_login, string $user_email): WP_Error
    {
        if (self::is_email_blocked($user_email)) {
            $errors->add('nopemail_blocked_email', self::blocked_message());
        }

        return $errors;
    }

    public static function filter_multisite_signup_errors(array $result): array
    {
        if (!isset($result['user_email'])) {
            return $result;
        }

        if (self::is_email_blocked((string) $result['user_email'])) {
            if (!isset($result['errors']) || !($result['errors'] instanceof WP_Error)) {
                $result['errors'] = new WP_Error();
            }
            $result['errors']->add('nopemail_blocked_email', self::blocked_message());
        }

        return $result;
    }

    public static function filter_woocommerce_registration_errors(WP_Error $errors, string $username, string $email): WP_Error
    {
        if (self::is_email_blocked($email)) {
            $errors->add('nopemail_blocked_email', self::blocked_message());
        }

        return $errors;
    }

    private static function blocked_message(): string
    {
        return (string) apply_filters(
            'nopemail_blocked_message',
            __('Sorry, registrations with that email address are not allowed.', 'nopemail')
        );
    }
}

NopeMail_Plugin::init();
