@antivirus @antivirus_verdict @javascript
Feature: Verdict scan detail presentation
  As a site administrator
  I need scan detail pages to show accurate status and outcomes
  So that I can audit results without calling VirusTotal in Behat

  Scenario: Clean scan detail shows filename and detection summary
    Given the following "antivirus_verdict > Scans" exist:
      | filename        | status | user  |
      | behat-clean.pdf | clean  | admin |
    And I log in as "admin"
    When I open Verdict scan detail for "behat-clean.pdf"
    Then I should see "behat-clean.pdf"
    And I should see "Clean"
    And I should see "0 / 70 engines detected"
    And the Verdict page must not expose provider credentials

  Scenario: Pending scan detail shows pending status
    Given the following "antivirus_verdict > Scans" exist:
      | filename          | status  | user  |
      | behat-pending.pdf | pending | admin |
    And I log in as "admin"
    When I open Verdict scan detail for "behat-pending.pdf"
    Then I should see "behat-pending.pdf"
    And I should see "Pending"

  Scenario: Error scan detail shows error status and message
    Given the following "antivirus_verdict > Scans" exist:
      | filename       | status | errorcode      | user  |
      | behat-error.pdf | error  | error_network | admin |
    And I log in as "admin"
    When I open Verdict scan detail for "behat-error.pdf"
    Then I should see "behat-error.pdf"
    And I should see "Error"
