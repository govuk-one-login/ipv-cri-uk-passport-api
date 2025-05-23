@E2E
Feature: E2E

  Background:
#   Auth
    Given I am on Orchestrator Stub
    And The user chooses the environment STAGING from dropdown
    And I click on Full journey route and Continue
    And I click on `Continue to prove your identity this way` radio button
    And clicks continue on the signed into your GOV.UK One Login page

  @E2E
  Scenario Outline: Passport cri back button recovery page staging - <PassportSubject>
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
      | PassportSubject             | userName           |
      | PassportSubjectHappyKenneth | KennethDecerqueira |

  @E2E
  Scenario Outline: address cri back button recovery page staging  - <userName>
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
      | PassportSubject             | userName           |
      | PassportSubjectHappyKenneth | KennethDecerqueira |

  @E2E
  Scenario Outline: fraud cri back button recovery page staging  - <userName>
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
      | PassportSubject             | userName           |
      | PassportSubjectHappyKenneth | KennethDecerqueira |

  @E2E
  Scenario Outline: Passport cri back button recovery page through hyperlink staging - <userName>
#   Passport CRI
    When User enters data as a <PassportSubject>
    And User clicks on continue
#   Address CRI
    And user clicks on browser back button
    And User should be navigated to Passport CRI page with text Enter your details exactly as they appear on your UK passport
    And User click on ‘prove your identity another way' Link
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
      | PassportSubject             | userName           |
      | PassportSubjectHappyKenneth | KennethDecerqueira |

  @E2E
  Scenario Outline: Prove Your Identity Full Journey Route (STUB) happy Path
    When User enters data as a <PassportSubject>
    And User clicks on continue
    And I enter BA2 5AA in the Postcode field and find address
    And the user chooses their address 8 HADLEY ROAD, BATH, BA2 5AA from dropdown and click `Choose address`
    And the user enters the date 2014 they moved into their current address
    And the user clicks `I confirm my details are correct`
    Then I check the page title is We need to check your details – GOV.UK One Login
    When I check Continue button is enabled and click on the Continue button
    And the user clicks `Answer security questions`
    And kenneth answers the first question correctly
    And kenneth answers the second question correctly
    And kenneth answers the third question correctly
    And the user clicks `I confirm my details are correct`
    Then verify the users address credentials. current address 8 HADLEY ROAD, BATH, BA2 5AA
    And verify the users fraud credentials
    And The test is complete and I close the driver
    Examples:
      | PassportSubject             |
      | PassportSubjectHappyKenneth |

  @E2E
  Scenario: Prove Your Identity Full Journey Route (STUB) unhappy Path
    When User enters invalid passport details
    And User clicks on continue
    Then Proper error message for Could not find your details is displayed
    And The test is complete and I close the driver

  @E2E
  Scenario Outline: Prove Your Identity Full Journey Route (STUB) Passport User failed second attempt
    When User enters invalid passport details
    And User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User Re-enters data as a <PassportSubject>
    And User re-enters passport number as <InvalidPassportNumber>
    And User clicks on continue
    Then I check the page title is Sorry, we could not confirm your details – GOV.UK
    And I can see the heading Sorry, we cannot confirm your identity
    And The test is complete and I close the driver
    Examples:
      | PassportSubject             | InvalidPassportNumber |
      | PassportSubjectHappyKenneth | 887766551             |
