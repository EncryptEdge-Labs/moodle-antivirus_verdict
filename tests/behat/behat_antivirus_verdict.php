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
 * Behat step definitions for Verdict for Moodle.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// Junctioned plugins often resolve __DIR__ to the source repo; optional VERDICT_BEHAT_MOODLEROOT from harness.
$behatbase = null;
$moodleroot = getenv('VERDICT_BEHAT_MOODLEROOT') ?: '';
if ($moodleroot !== '') {
    $moodleroot = realpath($moodleroot) ?: $moodleroot;
    foreach (
        [
        $moodleroot . '/lib/behat/behat_base.php',
        $moodleroot . '/public/lib/behat/behat_base.php',
        ] as $candidate
    ) {
        if (is_readable($candidate)) {
            $behatbase = $candidate;
            break;
        }
    }
}
if ($behatbase === null) {
    $dir = __DIR__;
    for ($i = 0; $i < 12; $i++) {
        foreach (
            [
            $dir . '/lib/behat/behat_base.php',
            $dir . '/public/lib/behat/behat_base.php',
            ] as $candidate
        ) {
            if (is_readable($candidate)) {
                $behatbase = $candidate;
                break 2;
            }
        }
        $parent = dirname($dir);
        if ($parent === $dir) {
            break;
        }
        $dir = $parent;
    }
}
if ($behatbase === null) {
    throw new Exception('Moodle behat_base.php not found (set VERDICT_BEHAT_MOODLEROOT or install without junction)');
}
require_once($behatbase);

use Behat\Gherkin\Node\TableNode;

/**
 * Browser steps for Verdict plugin pages.
 *
 * @package   antivirus_verdict
 * @copyright 2026 M. AFZAL RIAZ, POWERED BY ENCRYPTEDGE LABS LIMITED
 * @license   https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_antivirus_verdict extends behat_base {
    /** @var array<string,string> Friendly page name to script mapping. */
    private const PAGES = [
        'overview' => 'index.php',
        'history' => 'history.php',
        'scan' => 'scan.php',
        'configure' => 'configure.php',
        'settings' => 'configure.php',
        'coverage' => 'coverage.php',
        'quarantine' => 'quarantine.php',
        'bulk' => 'bulk.php',
    ];

    /**
     * Open a Verdict plugin page by name.
     *
     * @When /^I open the Verdict "(?P<pagename>[^"]*)" page$/
     * @param string $pagename overview|history|scan|configure|coverage|quarantine|bulk
     */
    public function i_open_the_verdict_page(string $pagename): void {
        $this->visit_verdict_page($pagename);
    }

    /**
     * Navigate to a Verdict admin page by friendly name.
     *
     * @param string $pagename Friendly page name.
     */
    private function visit_verdict_page(string $pagename): void {
        $key = strtolower(trim($pagename));
        if (!isset(self::PAGES[$key])) {
            throw new Exception('Unknown Verdict page: ' . $pagename);
        }
        $script = self::PAGES[$key];
        $url = new moodle_url('/lib/antivirus/verdict/' . $script);
        $this->execute('behat_general::i_visit', [$url->out(false)]);
    }

    /**
     * Assert a user lacks a Moodle capability in the system context.
     *
     * @Then /^the user "(?P<username>[^"]*)" should not have the "(?P<capability>[^"]*)" capability$/
     */
    public function the_user_should_not_have_the_capability(string $username, string $capability): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => $username], '*', MUST_EXIST);
        $context = \context_system::instance();
        if (has_capability($capability, $context, $user)) {
            throw new Exception("User {$username} unexpectedly has capability {$capability}");
        }
    }

    /**
     * Assert the response body does not expose API key material.
     *
     * @Then /^the Verdict page must not expose provider credentials$/
     */
    public function the_verdict_page_must_not_expose_provider_credentials(): void {
        $body = $this->getSession()->getPage()->getContent();
        $lower = strtolower($body);
        if (str_contains($lower, 'x-apikey') || str_contains($body, 'apikey_desc')) {
            throw new Exception('Verdict page appears to expose provider credential material');
        }
    }

    /**
     * Open a Verdict page scoped to a course (course-level capabilities).
     *
     * @When /^I open the Verdict "(?P<pagename>[^"]*)" page for course "(?P<shortname>[^"]*)"$/
     */
    public function i_open_the_verdict_page_for_course(string $pagename, string $shortname): void {
        global $DB;
        $course = $DB->get_record('course', ['shortname' => $shortname], '*', MUST_EXIST);
        $key = strtolower(trim($pagename));
        if (!isset(self::PAGES[$key])) {
            throw new Exception('Unknown Verdict page: ' . $pagename);
        }
        $url = new moodle_url('/lib/antivirus/verdict/' . self::PAGES[$key], ['courseid' => $course->id]);
        $this->execute('behat_general::i_visit', [$url->out(false)]);
    }

    /**
     * Open scan detail for a fixture filename.
     *
     * @When /^I open Verdict scan detail for "(?P<filename>[^"]*)"$/
     */
    public function i_open_verdict_scan_detail_for(string $filename): void {
        global $DB;
        $record = $DB->get_record('antivirus_verdict_scans', ['filename' => $filename], '*', MUST_EXIST);
        $url = new moodle_url('/lib/antivirus/verdict/view.php', ['id' => $record->id]);
        $this->execute('behat_general::i_visit', [$url->out(false)]);
    }

    /**
     * Assert scan_access denies a user (same rules as view.php / history.php).
     *
     * @Then /^the user "(?P<username>[^"]*)" must not be allowed to view Verdict scan "(?P<filename>[^"]*)"$/
     */
    public function the_user_must_not_be_allowed_to_view_verdict_scan(string $username, string $filename): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => $username], '*', MUST_EXIST);
        $scan = $DB->get_record('antivirus_verdict_scans', ['filename' => $filename], '*', MUST_EXIST);
        if (\antivirus_verdict\local\scan_access::can_view_scan($scan, (int) $user->id)) {
            throw new Exception("User {$username} unexpectedly may view scan {$filename}");
        }
    }

    /**
     * Assert a user cannot open a Verdict page (capability + teacher_access gates).
     *
     * @Then /^the user "(?P<username>[^"]*)" must not be allowed to open Verdict page "(?P<pagename>[^"]*)"$/
     */
    public function the_user_must_not_be_allowed_to_open_verdict_page(string $username, string $pagename): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => $username], '*', MUST_EXIST);
        $key = strtolower(trim($pagename));
        if (!isset(self::PAGES[$key])) {
            throw new Exception('Unknown Verdict page: ' . $pagename);
        }
        $allowed = $this->user_may_open_verdict_page($key, (int) $user->id);
        if ($allowed) {
            throw new Exception("User {$username} unexpectedly may open Verdict page {$pagename}");
        }
    }

    /**
     * Enable administrator switches that expose Verdict pages to teachers.
     *
     * @Given /^Verdict teacher access is enabled$/
     */
    public function verdict_teacher_access_is_enabled(): void {
        set_config('teacheraccess', 1, 'antivirus_verdict');
        set_config('teacherpagescan', 1, 'antivirus_verdict');
        set_config('teacherpagehistory', 1, 'antivirus_verdict');
    }

    /**
     * Whether a user would pass the same gates as page.php for a Verdict script.
     *
     * @param string $pagename Page key from {@see self::PAGES}.
     * @param int $userid User id.
     * @return bool
     */
    private function user_may_open_verdict_page(string $pagename, int $userid): bool {
        $script = self::PAGES[$pagename];
        $system = \context_system::instance();

        if ($script === 'history.php') {
            return \antivirus_verdict\local\scan_access::can_view_history_page($system, $userid);
        }
        if ($script === 'configure.php') {
            return has_capability('antivirus/verdict:manage', $system, $userid);
        }
        if ($script === 'scan.php') {
            return \antivirus_verdict\local\teacher_access::allows('manualscan', $userid)
                && \antivirus_verdict\local\scan_access::has_capability_in_any_course(
                    'antivirus/verdict:scan',
                    $userid
                );
        }

        return \antivirus_verdict\local\scan_access::can_manage_site($userid);
    }

    /**
     * Clear saved VirusTotal API key for the plugin (Behat isolation only).
     *
     * @Given /^Verdict provider credentials are not configured$/
     */
    public function verdict_provider_credentials_are_not_configured(): void {
        unset_config('apikey', 'antivirus_verdict');
    }

    /**
     * Assert a user has a capability in the system context.
     *
     * @Then /^the user "(?P<username>[^"]*)" should have the "(?P<capability>[^"]*)" capability$/
     */
    public function the_user_should_have_the_capability(string $username, string $capability): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => $username], '*', MUST_EXIST);
        $context = \context_system::instance();
        if (!has_capability($capability, $context, $user)) {
            throw new Exception("User {$username} lacks capability {$capability}");
        }
    }
}
