@antivirus @antivirus_verdict @javascript
Feature: Verdict manual scan page
  As a site administrator
  I need the manual scan UI to load with clear guidance
  So that I can queue files without using live VirusTotal in Behat

  Scenario: Manual scan page renders
    Given I log in as "admin"
    When I open the Verdict "scan" page
    Then I should see "Scan a file"
    And the Verdict page must not expose provider credentials
