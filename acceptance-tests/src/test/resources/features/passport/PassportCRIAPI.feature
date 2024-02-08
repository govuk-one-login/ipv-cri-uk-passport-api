@passport_CRI_API
Feature: Passport CRI API

  @hmpoDVAD @passportCRI_API @pre-merge @dev @testing
  Scenario: Passport Journey Happy Path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidKennethJsonPayload
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4
    And Passport VC Evidence contains expected values for scenario 1
    And Passport VC should contain JTI field value

  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario: Passport Retry Journey Happy Path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload
    Then Passport check response should contain Retry value as true
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidKennethJsonPayload
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4
    And Passport VC Evidence contains expected values for scenario 1

  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario: Passport user fails first attempt and VC is created for prove another way route
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload
    Then Passport check response should contain Retry value as true
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain ci D02, validityScore 0 and strengthScore 4
    And Passport VC Evidence contains expected values for scenario 2

  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario Outline: Create call to auth token from Passport CRI with dvad as document checking route and test CI scenarios
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest <PassportJsonPayload>
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain ci <CI>, validityScore 0 and strengthScore 4
    And Passport VC Evidence contains expected values for scenario <Scenario>
    Examples:
      |PassportJsonPayload              | CI  |  Scenario |
      |PassportInvalidCI1JsonPayload    | D01 |  3        |
      |PassportInvalidCI2JsonPayload    | D01 |  4        |
