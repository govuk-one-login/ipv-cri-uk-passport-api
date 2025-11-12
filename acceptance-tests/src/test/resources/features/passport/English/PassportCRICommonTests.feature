@hmpoDVAD
Feature: Passport CRI - UI Tests

  @build @staging @stub @uat
  Scenario: GET request to well-known/jwks endpoint returns single public key
    Given User sends a GET request to the well-known jwks endpoint

  @build @staging @stub @uat
  Scenario Outline: Public API endpoints that are not well known cannot be accessed (issuer/token)
    Given User sends a basic POST request to public <endpoint_name> endpoint without apiKey they get a forbidden error

    Examples:
      | endpoint_name     |
      | /token            |
      | /credential/issue |
