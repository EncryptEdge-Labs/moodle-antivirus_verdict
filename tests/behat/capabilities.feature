@antivirus @antivirus_verdict
Feature: Verdict capability enforcement
  As a site administrator
  I need unauthorized users blocked from Verdict administration pages
  So that scan data and settings stay protected

  Background:
    Given the following "users" exist:
      | username | firstname | lastname | email                |
      | vstudent | Verdict   | Student  | vstudent@example.com |

  Scenario: Users without Verdict roles lack Verdict capabilities
    Given I log in as "vstudent"
    Then the user "vstudent" should not have the "antivirus/verdict:viewhistory" capability
    And the user "vstudent" should not have the "antivirus/verdict:manage" capability

  Scenario: Site administrator holds Verdict manage capability
    Given I log in as "admin"
    Then the user "admin" should have the "antivirus/verdict:manage" capability
