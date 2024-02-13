@hmpoDVAD
Feature: Passport Test

  Background:
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    And I search for passport user number 5 in the Experian table
    Then I check the page title is Enter your details exactly as they appear on your UK passport – Prove your identity – GOV.UK
    And I assert the url path contains details
    And I set the document checking route

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport details page happy path
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And JSON response should contain documentNumber 321654987 same as given passport
    And Passport VC should contain JTI field
    And exp should be absent in the JSON payload
    And The test is complete and I close the driver
    Examples:
      |PassportSubject             |
      |PassportSubjectHappyKenneth |

  @Passport_test @build @staging @integration @smoke
  Scenario: Beta Banner Reject Analytics
    When I view the Beta banner
    When the beta banner reads This is a new service – your feedback (opens in new tab) will help us to improve it.
    And I select Reject analytics cookies button
    Then I see the Reject Analytics sentence You’ve rejected additional cookies. You can change your cookie settings at any time.
    And  I select the link change your cookie settings
    Then I check the page to change cookie preferences opens
    Then The test is complete and I close the driver

# No longer a valid test as front end form validation prevents the invalid passport number being sent
#  @Passport_test
#  Scenario Outline: Passport details page unhappy path with InvalidPassportDetails
#    Given User enters data as a <PassportSubject>
#    Then User clicks on continue
#    Then I navigate to the passport verifiable issuer to check for a Invalid response
#    And JSON response should contain error description Authorization permission denied and status code as 302
#    And The test is complete and I close the driver
#    Examples:
#      |PassportSubject      |
#      |PassportSubjectUnhappySelina |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectPassportNumber
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And JSON response should contain documentNumber 887766551 same as given passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject      |
      |IncorrectPassportNumber |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectDateOfBirth
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectDateOfBirth |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectFirstName
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectFirstName|

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectLastName
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectLastName|

# # Invalid test - expiry date not checked in DCS stub
#  @Passport_test @build @staging @integration
#  Scenario Outline: Passport details page unhappy path with IncorrectValidToDate
#    Given User enters data as a <PassportSubject>
#    When User clicks on continue
#    Then Proper error message for Could not find your details is displayed
#    When User clicks on continue
#    Then I navigate to the Passport verifiable issuer to check for a Valid response
#    And JSON payload should contain ci D02, validity score 0 and strength score 3
#    And The test is complete and I close the driver
#    Examples:
#      |PassportSubject |
#      |IncorrectValidToDate|

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport Retry Test Happy Path
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User Re-enters data as a <PassportSubject>
    And User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportSubjectHappyKenneth |

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport User failed second attempt
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User Re-enters data as a <PassportSubject>
    And User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectPassportNumber |

  @Passport_test @build @staging @integration @smoke
  Scenario: Passport User cancels after failed first attempt
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User click on ‘prove your identity another way' Link
    And User selects prove another way radio button
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver

  @Passport_test @smoke
  Scenario: Passport User cancels before first attempt via prove your identity another way route
    Given User click on ‘prove your identity another way' Link
    Then User selects prove another way radio button
    Then I navigate to the passport verifiable issuer to check for a Invalid response
    And JSON response should contain error description Authorization permission denied and status code as 302
    And The test is complete and I close the driver

###########   Field Validations ##########
  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport Generate VC with invalid Passport number and prove in another way unhappy path
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    When User click on ‘prove your identity another way' Link
    And User selects prove another way radio button
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON response should contain documentNumber 887766551 same as given passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject           |
      | IncorrectPassportNumber     |

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport expiry date valid
    Given User enters data as a <PassportSubject>
    Then User enters expiry date as current date minus <months> months and minus <daysToSubtract> days
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And JSON response should contain documentNumber 321654987 same as given passport
    And exp should be absent in the JSON payload
    And The test is complete and I close the driver
    Examples:
      | PassportSubject             | months | daysToSubtract |
      | PassportSubjectHappyKenneth | 18     | 0 |

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport expiry date invalid
    Given User enters data as a <PassportSubject>
    Then User enters expiry date as current date minus <months> months and minus <daysToSubtract> days
    When User clicks on continue
    Then I can see the valid to date error in the error summary as Your passport must not have expired more than 18 months ago
    And I can see the Valid to date field error as Error:Your passport must not have expired more than 18 months ago
    And The test is complete and I close the driver

    Examples:
      | PassportSubject             | months | daysToSubtract |
      | PassportSubjectHappyKenneth | 18     | 1 |
      | PassportSubjectHappyKenneth | 18     | 2 |