<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Moodle message notifications for terminal scan outcomes.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_verdict\local;

use antivirus_verdict\scan_status;


/**
 * Sends configurable administrator notifications through the Moodle messaging API.
 */
class scan_notifications {
    /** Minimum seconds between identical notifications for one scan id. */
    public const THROTTLE_SECONDS = 3600;

    /** @var plugin_config Operational settings. */
    private plugin_config $config;

    /**
     * Create a notification service.
     *
     * @param plugin_config $config Operational settings.
     */
    public function __construct(plugin_config $config) {
        $this->config = $config;
    }

    /**
     * Production service using site configuration.
     *
     * @return self
     */
    public static function from_site_config(): self {
        return new self(plugin_config::from_site_config());
    }

    /**
     * Notify administrators when a scan reaches a terminal state.
     *
     * @param \stdClass $record Scan row after persistence.
     */
    public function scan_finished(\stdClass $record): void {
        try {
            $this->dispatch_scan_finished($record);
        } catch (\Throwable $e) {
            debugging('antivirus_verdict notification hook failed', \DEBUG_DEVELOPER);
        }
    }

    /**
     * Build and send messages for a persisted terminal scan.
     *
     * @param \stdClass $record Scan row after persistence.
     */
    private function dispatch_scan_finished(\stdClass $record): void {
        $status = (string) $record->status;
        $provider = $this->provider_for_status($status);
        if ($provider === '') {
            return;
        }
        if (!$this->should_notify($status)) {
            return;
        }
        if ($this->is_throttled((int) $record->id, $provider)) {
            return;
        }

        $admins = get_admins();
        if ($admins === []) {
            return;
        }

        $content = scan_notification_content::compose($record);

        foreach ($admins as $admin) {
            if (!$this->user_can_receive($admin, $provider)) {
                continue;
            }
            $message = new \core\message\message();
            $message->component = 'antivirus_verdict';
            $message->name = $provider;
            $message->userfrom = \core_user::get_noreply_user();
            $message->userto = $admin;
            $message->subject = $content['subject'];
            $message->fullmessage = $content['bodyplain'];
            $message->fullmessageformat = FORMAT_HTML;
            $message->fullmessagehtml = $content['bodyhtml'];
            $message->smallmessage = $content['smallmessage'];
            $message->notification = 1;
            $message->contexturl = (new \moodle_url('/lib/antivirus/verdict/view.php', ['id' => (int) $record->id]))->out(false);
            $message->contexturlname = $content['contextlabel'];

            try {
                message_send($message);
            } catch (\Throwable $e) {
                debugging('antivirus_verdict notification failed', \DEBUG_DEVELOPER);
            }
        }

        $this->mark_sent((int) $record->id, $provider);
    }

    /**
     * Whether Moodle will deliver this plugin provider to the administrator.
     *
     * Calling message_send() when the provider is inactive emits a Moodle
     * DEBUG_NORMAL debugging() notice. Skip those users instead.
     *
     * @param \stdClass $user Administrator.
     * @param string $providername Message provider name.
     * @return bool
     */
    private function user_can_receive(\stdClass $user, string $providername): bool {
        foreach (message_get_providers_for_user((int) $user->id) as $available) {
            if ($available->component === 'antivirus_verdict' && $available->name === $providername) {
                return true;
            }
        }
        return false;
    }

    /**
     * Map scan status to a message provider name.
     *
     * @param string $status Terminal status.
     * @return string Provider name or empty.
     */
    private function provider_for_status(string $status): string {
        return match ($status) {
            scan_status::MALICIOUS => 'scan_malicious',
            scan_status::SUSPICIOUS => 'scan_suspicious',
            scan_status::ERROR => 'scan_error',
            default => '',
        };
    }

    /**
     * Whether site settings allow this status to notify.
     *
     * @param string $status Terminal status.
     * @return bool
     */
    private function should_notify(string $status): bool {
        return match ($status) {
            scan_status::MALICIOUS => $this->config->notifymalicious,
            scan_status::SUSPICIOUS => $this->config->notifysuspicious,
            scan_status::ERROR => $this->config->notifyerror,
            default => false,
        };
    }

    /**
     * Throttle duplicate notifications per scan and provider.
     *
     * @param int $scanid Scan id.
     * @param string $provider Message provider.
     * @return bool
     */
    private function is_throttled(int $scanid, string $provider): bool {
        $key = $scanid . '_' . $provider;
        $cache = \cache::make('antivirus_verdict', 'providerhealth');
        $last = (int) $cache->get('notify_' . $key);
        return $last > 0 && (time() - $last) < self::THROTTLE_SECONDS;
    }

    /**
     * Record a sent notification timestamp.
     *
     * @param int $scanid Scan id.
     * @param string $provider Message provider.
     */
    private function mark_sent(int $scanid, string $provider): void {
        $key = $scanid . '_' . $provider;
        $cache = \cache::make('antivirus_verdict', 'providerhealth');
        $cache->set('notify_' . $key, time());
    }
}
