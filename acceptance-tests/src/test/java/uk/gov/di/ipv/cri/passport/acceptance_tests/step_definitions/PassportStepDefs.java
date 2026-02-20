package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PassportPageObject;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;

public class PassportStepDefs extends PassportPageObject {

    @When("^User enters data as a (.*)$")
    public void user_enters_and(String passportSubjectScenario) {
        userEntersData(passportSubjectScenario);
    }

    @And("User re-enters last name as (.*)$")
    public void userEntersLastName(String invalidLastName) {
        userReEntersLastName(invalidLastName);
    }

    @And("User re-enters first name as (.*)$")
    public void userEntersFirstName(String invalidFirstName) {
        userReEntersFirstName(invalidFirstName);
    }

    @And("User re-enters passport number as (.*)$")
    public void userEntersPassportNumber(String invalidPassportNumber) {
        userReEntersPassportNumber(invalidPassportNumber);
    }

    @And("User re-enters birth day as (.*)$")
    public void userEntersBirthDay(String invalidBirthDay) {
        userReEntersBirthDay(invalidBirthDay);
    }

    @And("User re-enters birth month as (.*)$")
    public void userEntersBirthMonth(String invalidBirthMonth) {
        userReEntersBirthMonth(invalidBirthMonth);
    }

    @And("User re-enters birth year as (.*)$")
    public void userEntersBirthYear(String invalidBirthYear) {
        userReEntersBirthYear(invalidBirthYear);
    }

    @And("User re-enters valid to day as (.*)$")
    public void userEntersValidToDay(String invalidValidToDay) {
        userReEntersValidToDay(invalidValidToDay);
    }

    @And("User re-enters valid to month as (.*)$")
    public void userEntersValidToMonth(String invalidValidToMonth) {
        userReEntersValidToMonth(invalidValidToMonth);
    }

    @And("User re-enters valid to year as (.*)$")
    public void userEntersValidToYear(String invalidValidToYear) {
        userReEntersValidToYear(invalidValidToYear);
    }

    @And("I assert the url path contains (.*)$")
    public void i_assert_the_url_path_contains(String path) {
        passportPageURLValidation(path);
    }

    @Given("^I check the page title is (.*)$")
    public void i_check_the_page_titled(String pageTitle) {
        assertExpectedPage(pageTitle, false);
    }

    @Given("^I delete the (.*) cookie to get the unexpected error$")
    public void iDeleteTheCookieToGetTheUnexpectedError(String cookieName) {
        BrowserUtils.deleteCookie(cookieName);
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
        continueButton.click();
    }

    @Then("User enters expiry date as current date minus (.*) months and minus (.*) days$")
    public void expiryDateAsCurrentMinus(int monthsToSubtract, int daysToSubtract) {
        userReEntersExpiryDateAsCurrentDateMinus(monthsToSubtract, daysToSubtract);
    }
}
