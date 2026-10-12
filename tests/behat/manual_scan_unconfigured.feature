@antivirus @antivirus_verdict @javascript
Feature: Verdict manual scan when credentials are missing
  As a site administrator
  I need clear feedback when scanning cannot be queued
  So that misconfiguration is obvious without calling VirusTotal

  Scenario: Manual scan page explains missing credentials
    Given Verdict provider credentials are not configured
    And I log in as "admin"
    When I open the Verdict "scan" page
    Then I should see "Scan a file"
    And I should see "Scanning cannot start because site VirusTotal credentials are not configured"
