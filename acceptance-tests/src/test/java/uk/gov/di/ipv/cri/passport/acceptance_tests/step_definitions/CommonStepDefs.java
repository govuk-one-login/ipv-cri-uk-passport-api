package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.CommonPageObject;

import java.io.IOException;

public class CommonStepDefs extends CommonPageObject {

    // Background steps: Stub navigation
    @Given("I navigate to the IPV Core Stub")
    public void navigateToStub() {
        navigateToIPVCoreStub();
    }

    @And("^I click the passport CRI for the testEnvironment$")
    public void navigateToPassportOnTestEnv() {
        navigateToPassportCRIOnTestEnv();
    }

    @Then("^I search for passport user number (.*) in the Experian table$")
    public void i_search_for_passport_user_number(String number) {
        searchForUATUser(number);
    }

    // VC Validation Steps
    @Then("^I navigate to the passport verifiable issuer to check for a (.*) response$")
    public void i_navigate_to_passport_verifiable_issuer_for_valid_response(String validOrInvalid) {
        navigateToPassportResponse(validOrInvalid);
    }

    @And("^JSON response should contain error description (.*) and status code as (.*)$")
    public void errorInJsonResponse(String testErrorDescription, String testStatusCode)
            throws JsonProcessingException {
        jsonErrorResponse(testErrorDescription, testStatusCode);
    }

    @And("^JSON payload should contain validity score (.*) and strength score (.*)$")
    public void scoresInVerifiableCredential(String validityScore, String strengthScore)
            throws IOException {
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @And("^JSON payload should contain ci (.*), validity score (.*) and strength score (.*)$")
    public void contraIndicatorInVerifiableCredential(
            String ci, String validityScore, String strengthScore) throws IOException {
        ciInVC(ci);
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @And("^JSON response should contain documentNumber (.*) same as given passport$")
    public void errorInJsonResponse(String documentNumber) throws IOException {
        assertDocumentNumberInVc(documentNumber);
    }

    @And("^Passport VC should contain JTI field$")
    public void jsonPayloadShouldContainJtiField() throws IOException {
        assertJtiIsPresentAndNotNull();
    }

    @And("^(.*) should be absent in the JSON payload$")
    public void ExpiryNotPresentInJsonResponse(String exp) throws JsonProcessingException {
        expiryAbsentFromVC(exp);
    }
}
