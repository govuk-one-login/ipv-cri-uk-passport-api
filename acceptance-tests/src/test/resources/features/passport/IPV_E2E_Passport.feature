Feature: E2E

  @Staging @Integration
  Scenario Outline: Passport cri back button recovery page staging - <PassportSubject>
#   Auth
    Given I am on Orchestrator Stub
    And I click on Full journey route and Continue
    And clicks continue on the signed into your GOV.UK One Login page
##   Passport CRI
    When User enters data as a <PassportSubject>
    And User clicks on continue
##   Address CRI
    And user clicks on browser back button
    And User should be on page with with heading as Enter your details exactly as they appear on your UK passport
    And User should be on page with with heading as Sorry, you cannot go back
#    When I enter BA2 5AA in the Postcode field and find address
    When the user "<userName>" "Successfully" adds their Address Details
##   Fraud CRI
    Then the user completes the Fraud Cri Check
#    When User should be on KBV page and click continue
##    And user enters data in kbv stub and Click on submit data and generate auth code
##   KBV CRI
#    When the user "<userName>" "Successfully" passes the KBV CRI Check
##    Then user should be on Fraud Check (Stub)
##    When user enters data in fraud build stub and Click on submit data and generates auth code
##    Then User should be on KBV page and click continue
##    When user enters data in kbv stub and Click on submit data and generate auth code
##   ID Validation
#    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
#    And The test is complete and I close the driver
    Examples:
      | PassportSubject           |
      | PassportSubjectHappyBilly |