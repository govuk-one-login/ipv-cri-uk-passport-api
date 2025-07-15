package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PassportPageObject;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;

import java.io.IOException;

public class PassportStepDefs extends PassportPageObject {

    @When("^User enters data as a (.*)$")
    public void user_enters_and(String passportSubjectScenario) {
        userEntersData(passportSubjectScenario);
    }

    @And("User re-enters last name as (.*)$")
    public void userEntersLastName(String InvalidLastName) {
        userReEntersLastName(InvalidLastName);
    }

    @And("User re-enters first name as (.*)$")
    public void userEntersFirstName(String InvalidFirstName) {
        userReEntersFirstName(InvalidFirstName);
    }

    @And("User re-enters passport number as (.*)$")
    public void userEntersPassportNumber(String InvalidPassportNumber) {
        userReEntersPassportNumber(InvalidPassportNumber);
    }

    @And("User re-enters birth day as (.*)$")
    public void userEntersBirthDay(String InvalidBirthDay) {
        userReEntersBirthDay(InvalidBirthDay);
    }

    @And("User re-enters birth month as (.*)$")
    public void userEntersBirthMonth(String InvalidBirthMonth) {
        userReEntersBirthMonth(InvalidBirthMonth);
    }

    @And("User re-enters birth year as (.*)$")
    public void userEntersBirthYear(String InvalidBirthYear) {
        userReEntersBirthYear(InvalidBirthYear);
    }

    @And("User re-enters valid to day as (.*)$")
    public void userEntersValidToDay(String InvalidValidToDay) {
        userReEntersValidToDay(InvalidValidToDay);
    }

    @And("User re-enters valid to month as (.*)$")
    public void userEntersValidToMonth(String InvalidValidToMonth) {
        userReEntersValidToMonth(InvalidValidToMonth);
    }

    @And("User re-enters valid to year as (.*)$")
    public void userEntersValidToYear(String InvalidValidToYear) {
        userReEntersValidToYear(InvalidValidToYear);
    }

    @Given("I navigate to the IPV Core Stub")
    public void navigateToStub() {
        navigateToIPVCoreStub();
    }

    @Then("^I search for passport user number (.*) in the Experian table$")
    public void i_search_for_passport_user_number(String number) {
        searchForUATUser(number);
    }

    @And("I assert the url path contains (.*)$")
    public void i_assert_the_url_path_contains(String path) {
        passportPageURLValidation(path);
    }

    @Given("^I check the page title is (.*)$")
    public void i_check_the_page_titled(String pageTitle) {
        assertExpectedPage(pageTitle, false);
    }

    @Then("^I navigate to the passport verifiable issuer to check for a (.*) response$")
    public void i_navigate_to_passport_verifiable_issuer_for_valid_response(String validOrInvalid) {
        navigateToPassportResponse(validOrInvalid);
    }

    @And("^JSON response should contain error description (.*) and status code as (.*)$")
    public void errorInJsonResponse(String testErrorDescription, String testStatusCode)
            throws JsonProcessingException {
        jsonErrorResponse(testErrorDescription, testStatusCode);
    }

    @Given("^I delete the (.*) cookie to get the unexpected error$")
    public void iDeleteTheCookieToGetTheUnexpectedError(String cookieName) {
        BrowserUtils.deleteCookie(cookieName);
    }

    @And("^I click the passport CRI for the testEnvironment$")
    public void navigateToPassportOnTestEnv() {
        navigateToPassportCRIOnTestEnv();
    }

    @When("^User Re-enters data as a (.*)$")
    public void userReInputsDataAsAPassportSubject(String passportSubject) {
        userReEntersDataAsPassportSubject(passportSubject);
    }

    @Then("Proper error message for Could not find your details is displayed")
    public void properErrorMessageForCouldNotFindDetailsIsDisplayed() {
        userNotFoundInThirdPartyErrorIsDisplayed();
    }

    @Then("^I can see the valid to date error in the error summary as (.*)$")
    public void properErrorMessageForInvalidValidToDateIsDisplayed(String expectedText) {
        assertInvalidValidToDateInErrorSummary(expectedText);
    }

    @Then("^I can see the Valid to date field error as (.*)$")
    public void fieldErrorMessageForInvalidValidToDateIsDisplayed(String expectedText) {
        assertInvalidValidToDateOnField(expectedText);
    }

    @Given("User enters invalid passport details")
    public void userInputsInvalidPassportDetails() {
        userEntersInvalidPassportDetails();
    }

    @Given("User click on ‘prove your identity another way' Link")
    public void userClickOnProveYourIdentityAnotherWayLink() {
        proveAnotherWay.click();
    }

    @Given("User clicks on language toggle and switches to Welsh")
    public void userClickOnLanguageToggle() {
        languageToggle.click();
    }

    @Given("User clicks language toggle and switches to English")
    public void userClickOnLanguageToggleWales() {
        languageToggleWales.click();
    }

    @When("User clicks on continue")
    public void user_clicks_on_continue() {
        Continue.click();
    }

    @And("^JSON payload should contain ci (.*), validity score (.*) and strength score (.*)$")
    public void contraIndicatorInVerifiableCredential(
            String ci, String validityScore, String strengthScore) throws IOException {
        ciInVC(ci);
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @And("^JSON payload should contain validity score (.*) and strength score (.*)$")
    public void scoresInVerifiableCredential(String validityScore, String strengthScore)
            throws IOException {
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @And("^JSON response should contain documentNumber (.*) same as given passport$")
    public void errorInJsonResponse(String documentNumber) throws IOException {
        assertDocumentNumberInVc(documentNumber);
    }

    @And("^(.*) should be absent in the JSON payload$")
    public void ExpiryNotPresentInJsonResponse(String exp) throws JsonProcessingException {
        expiryAbsentFromVC(exp);
    }

    @And("^Passport VC should contain JTI field$")
    public void jsonPayloadShouldContainJtiField() throws IOException {
        assertJtiIsPresentAndNotNull();
    }

    @Then("User enters expiry date as current date minus (.*) months and minus (.*) days$")
    public void expiryDateAsCurrentMinus(int monthsToSubtract, int daysToSubtract) {
        userReEntersExpiryDateAsCurrentDateMinus(monthsToSubtract, daysToSubtract);
    }
}
