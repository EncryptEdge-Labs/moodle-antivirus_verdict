@antivirus @antivirus_verdict @javascript
Feature: Verdict scan history lists persisted records
  As a site administrator
  I need completed scans to appear in history
  So that audit trails are visible in the browser

  Scenario: History table lists a seeded clean scan
    Given the following "antivirus_verdict > Scans" exist:
      | filename         | status | user  |
      | behat-history.pdf | clean  | admin |
    And I log in as "admin"
    When I open the Verdict "history" page
    Then I should see "Scan history"
    And I should see "behat-history.pdf"
    And I should see "Clean"
