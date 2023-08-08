Feature: E2E

  @E2E
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
    When the user "<userName>" "Successfully" adds their Address Details
##   Fraud CRI
    Then the user completes the Fraud Cri Check
    When User should be on kbv page with heading as Answer security questions
##   KBV CRI
    When the user "<userName>" "Successfully" passes the KBV CRI Check
##   ID Validation
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |

  @E2E
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
    And the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |

  @E2E
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
    When the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |

  @E2E
  Scenario Outline: Passport cri back button recovery page through hyperlink staging - <userName>
#   Auth
    Given I am on Orchestrator Stub
    And I click on Full journey route and Continue
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User enters data as a <PassportSubject>
    And User clicks on continue
#   Address CRI
    And user clicks on browser back button
    And User should be navigated to Passport CRI page with text Enter your details exactly as they appear on your UK passport
    And User click on ‘prove your identity another way' Link
    And User selects prove another way radio button
    And User should be on error recovery page with heading as Sorry, you cannot go back
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    When the user completes the Fraud Cri Check
#   KBV CRI
    And User should be on kbv page with heading as Answer security questions
    And the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
    Then User should be on  page with heading as Continue to the service you want to use
    And User should see message as Page Header not returned as expected and title should contain the text user information
    And The test is complete and I close the driver
    Examples:
      | PassportSubject           | userName                   |
      | PassportSubjectHappyBilly |   KennethDecerqueira       |