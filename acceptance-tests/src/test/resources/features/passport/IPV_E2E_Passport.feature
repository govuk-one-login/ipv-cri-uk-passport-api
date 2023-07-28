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
    And User should be on passport cri page with heading as Enter your details exactly as they appear on your UK passport
    And User should be on error recovery page with heading as Sorry, you cannot go back
#    When I enter BA2 5AA in the Postcode field and find address
    When the user "<userName>" "Successfully" adds their Address Details
##   Fraud CRI
    Then the user completes the Fraud Cri Check
    When User should be on kbv page with heading as Answer security questions
##    And user enters data in kbv stub and Click on submit data and generate auth code
##   KBV CRI
    When the user "<userName>" "Successfully" passes the KBV CRI Check
##    Then user should be on Fraud Check (Stub)
##    When user enters data in fraud build stub and Click on submit data and generates auth code
##    Then User should be on KBV page and click continue
##    When user enters data in kbv stub and Click on submit data and generate auth code
##   ID Validation
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |

  @Staging @Integration
  Scenario Outline: address cri back button recovery page staging  - <userName>
#   Auth
    Given I am on Orchestrator Stub
    And I click on Full journey route and Continue
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User enters data as a <PassportSubject>
    And User clicks on continue
#   Address CRI
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    And user clicks on browser back button
    And User should be on error recovery page with heading as Sorry, you cannot go back
    And the user completes the Fraud Cri Check
#   KBV CRI
    When User should be on kbv page with heading as Answer security questions
#    When user enters data in kbv stub and Click on submit data and generate auth code
    And the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
#    Then user should be on Fraud Check (Stub)
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |

  @Staging @Integration
  Scenario Outline: fraud cri back button recovery page staging  - <userName>
#   Auth
    Given I am on Orchestrator Stub
    And I click on Full journey route and Continue
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User enters data as a <PassportSubject>
    And User clicks on continue
#   Address CRI
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    And the user completes the Fraud Cri Check
    And user clicks on browser back button
    And the user completes the Fraud Cri Check
    And User should be on error recovery page with heading as Sorry, you cannot go back
#   KBV CRI
    Then User should be on kbv page with heading as Answer security questions
#    When user enters data in kbv stub and Click on submit data and generate auth code
    When the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
#    Then user should be on Fraud Check (Stub)
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#    Then User should be on KBV (Stub)
#    When user clicks on browser back button
#    Then user is redirected back to the fraud CRI Stub
#    When user Click on submit data and generates auth code
#    Then User should see error recovery page and clicks on continue
#    And User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |