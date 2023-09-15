package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;

public class E2E_PassportStepDefs {

    private final OrchestratorStubPage orchestratorStubPage = new OrchestratorStubPage();

    @When("user clicks on browser back button")
    public void userClicksOnBrowserBackButton() {
        orchestratorStubPage.clickBrowserButton();
    }

    @Then("^User should be on (.*) page with heading as (.*)$")
    public void userIsNavigatedToPageWithHeading(String page, String expectedText) {
        orchestratorStubPage.userIsOnPageWithHeading(page, expectedText);
        orchestratorStubPage.continueSubmitButton.click();
    }

    @Then("^User should be navigated to (.*) page with text (.*)$")
    public void userIsNavigatedToPage(String page, String expectedText) {
        orchestratorStubPage.userIsOnPageWithHeading(page, expectedText);
    }

    @And("^I enter (.*) in the Postcode field and find address$")
    public void enterPostcode(String postcode) {
        orchestratorStubPage.addPostcode(postcode);
    }

    @And("the user completes the Fraud Cri Check")
    public void theUserCompletesTheFraudCriCheck() {
        orchestratorStubPage.CheckingYourDetailsPage();
        orchestratorStubPage.continueButton.click();
    }

    @Then("^User should see message as (.*) and title should contain the text user information$")
    public void theUserShouldSeeThatTheyHaveProvedTheirIdentityOrchestratorStub(
            String expectedText) {
        orchestratorStubPage.validateUserInformationTitle(expectedText);
    }

    @When("the user chooses their address (.*) from dropdown and click `Choose address`$")
    public void the_user_chooses_their_address_from_dropdown_and_click_Choose_address(
            String address) {
        orchestratorStubPage.selectAddressFromDropdown(address);
    }

    @When("the user enters the date (.*) they moved into their current address$")
    public void the_user_enters_the_date_they_moved_into_their_current_address(String expiryDate) {
        orchestratorStubPage.enterAddressExpiry(expiryDate);
    }

    @When("the user clicks `I confirm my details are correct`")
    public void the_user_clicks_I_confirm_my_details_are_correct() {
        orchestratorStubPage.confirmClick();
    }

    @When("^I check Continue button is enabled and click on the Continue button$")
    public void clickOnContinueButton() {
        orchestratorStubPage.clickContinue();
    }

    @When("the user clicks `Answer security questions`")
    public void the_user_clicks_Answe_security_questions() {
        orchestratorStubPage.confirmClick();
    }

    @When("kenneth answers the (.*) question correctly$")
    public void the_user_answers_the_first_question_correctly(String questionNumber)
            throws Exception {
        orchestratorStubPage.answerKBVQuestion();
    }

    @Then("verify the users address credentials. current address (.*)$")
    public void credentials_are_verified_against_input_address(String currentAddress)
            throws Exception {
        orchestratorStubPage.validateAddressVc(currentAddress);
    }

    @Then("verify the users fraud credentials")
    public void credentials_are_verified_against_input_fraud() throws Exception {
        orchestratorStubPage.validateFraudVc();
    }
}
