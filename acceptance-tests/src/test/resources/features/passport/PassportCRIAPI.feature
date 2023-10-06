@passport_CRI_API
Feature: Passport CRI API

  @passportCRI_API @pre-merge @dev
  Scenario Outline: Create call to auth token from Passport CRI when document checking route is not provided or is invalid
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest <PassportJsonPayload> and document checking route is <Invalid>
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4
    And Passport VC should contain success checkDetails
    Examples:
      |PassportJsonPayload                   |     Invalid         |
      |PassportValidKennethJsonPayload       |       ABCD          |
      |PassportValidKennethJsonPayload       |  not-provided       |

#########  hmpoDVAD tests ##########
  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario: Create call to auth token from Passport CRI with dvad as document checking route
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidKennethJsonPayload and document checking route is dvad
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4
    And Passport VC should contain success checkDetails

  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario: Passport Retry Journey Happy Path with dvad as document checking route
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload and document checking route is dvad
    Then Passport check response should contain Retry value as true
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidKennethJsonPayload and document checking route is dvad
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4
    And Passport VC should contain success checkDetails

  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario: Passport user fails first attempt with dvad as document checking route but VC is still created
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload and document checking route is dvad
    Then Passport check response should contain Retry value as true
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain ci D02, validityScore 0 and strengthScore 4
    And Passport VC should contain failed checkDetails

#  Bug LIME-776 raised to fix the validity score
  @hmpoDVAD @passportCRI_API @pre-merge @dev
  Scenario Outline: Create call to auth token from Passport CRI with dvad as document checking route and test CI scenarios
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-v1-cri-dev and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest <PassportJsonPayload> and document checking route is dvad
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-v1-cri-dev
    Then User requests Passport CRI VC
    And Passport VC should contain ci <CI>, validityScore 0 and strengthScore 4
    And Passport VC should contain <checkDetails> checkDetails
    Examples:
      |PassportJsonPayload              | CI  | checkDetails |
      |PassportInvalidCI1JsonPayload    | D01 |  failed            |
      |PassportInvalidCI2JsonPayload    | D01 |  failed            |
      |PassportInvalidJsonPayload       | D02 |  failed            |
