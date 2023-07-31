package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;

public class E2E_PassportStepDefs {

    private final OrchestratorStubPage orchestratorStubPage =
            new OrchestratorStubPage();

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

}
