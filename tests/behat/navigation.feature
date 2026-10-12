@antivirus @antivirus_verdict @javascript
Feature: Verdict navigation and overview for administrators
  As a site administrator
  I need to reach Verdict pages safely
  So that I can monitor scanning without credential leakage

  Scenario: Administrator opens the Verdict overview
    Given I log in as "admin"
    When I open the Verdict "overview" page
    Then I should see "Security overview"
    And the Verdict page must not expose provider credentials

  Scenario: Administrator opens scan history
    Given I log in as "admin"
    When I open the Verdict "history" page
    Then I should see "Scan history"
    And the Verdict page must not expose provider credentials

  Scenario: Administrator opens dedicated settings
    Given I log in as "admin"
    When I open the Verdict "configure" page
    Then I should see "Settings"
    And the Verdict page must not expose provider credentials
