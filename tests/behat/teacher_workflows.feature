@antivirus @antivirus_verdict @javascript
Feature: Verdict course-scoped teacher access
  As a course teacher
  I need course-scoped Verdict pages when I hold scan capabilities
  So that manual scanning is available in my course context

  Background:
    Given the following "courses" exist:
      | fullname              | shortname |
      | Verdict Behat Course  | vtcbehat  |
    And the following "users" exist:
      | username | firstname | lastname | email               |
      | vteacher | Verdict   | Teacher  | vteacher@example.com |
    And the following "course enrolments" exist:
      | user     | course   | role              |
      | vteacher | vtcbehat | editingteacher    |
    And Verdict teacher access is enabled

  Scenario: Editing teacher opens manual scan in course context
    Given I log in as "vteacher"
    When I open the Verdict "scan" page for course "vtcbehat"
    Then I should see "Scan a file"
    And the Verdict page must not expose provider credentials

  Scenario: Editing teacher with course scan can view own course scan detail
    Given the following "antivirus_verdict > Scans" exist:
      | filename          | status | user     | course   |
      | behat-teacher.pdf | clean  | vteacher | vtcbehat |
    And I log in as "vteacher"
    When I open Verdict scan detail for "behat-teacher.pdf"
    Then I should see "behat-teacher.pdf"
    And I should see "Clean"
