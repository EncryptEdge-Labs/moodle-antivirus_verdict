@antivirus @antivirus_verdict @javascript
Feature: Verdict scan history empty state
  As a site administrator
  I need an understandable empty history page
  So that I know no scans were recorded yet

  Scenario: Empty history shows guidance
    Given I log in as "admin"
    When I open the Verdict "history" page
    Then I should see "Scan history"
    And I should see "No scans found"
