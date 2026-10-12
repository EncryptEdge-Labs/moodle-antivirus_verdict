@antivirus @antivirus_verdict
Feature: Verdict authorization for protected pages and scan rows
  As a site administrator
  I need unauthorized users blocked by the same rules as production pages
  So that scan data and settings stay protected

  Background:
    Given the following "users" exist:
      | username | firstname | lastname | email                |
      | vstudent | Verdict   | Student  | vstudent@example.com |

  Scenario: Student lacks access to Verdict history and settings
    Then the user "vstudent" must not be allowed to open Verdict page "history"
    And the user "vstudent" must not be allowed to open Verdict page "configure"

  Scenario: Student cannot view another user's scan record
    Given the following "antivirus_verdict > Scans" exist:
      | filename             | status | user  |
      | behat-admin-only.pdf | clean  | admin |
    Then the user "vstudent" must not be allowed to view Verdict scan "behat-admin-only.pdf"
