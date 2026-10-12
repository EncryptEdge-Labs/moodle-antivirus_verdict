@antivirus @antivirus_verdict @javascript
Feature: Verdict coverage and quarantine navigation
  As a site administrator
  I need coverage and quarantine pages to load safely
  So that monitoring surfaces are reachable in the browser

  Scenario: Administrator opens file coverage report
    Given I log in as "admin"
    When I open the Verdict "coverage" page
    Then I should see "File coverage"
    And the Verdict page must not expose provider credentials

  Scenario: Administrator opens quarantine inventory
    Given I log in as "admin"
    When I open the Verdict "quarantine" page
    Then I should see "Quarantine inventory"
    And the Verdict page must not expose provider credentials
