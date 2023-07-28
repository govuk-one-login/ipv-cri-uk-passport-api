package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;

public class IPV_E2E_PassportStepDefs {

    private final OrchestratorStubPage orchestratorStubPage =
            new OrchestratorStubPage();

    @When("user clicks on browser back button")
    public void userClicksOnBrowserBackButton() {
        orchestratorStubPage.clickBrowserButton();
    }

    @Then("^User should be on page with with heading as (.*)$")
    public void userIsRedirectedBackToThePassportCRIStub(String expectedText) {
        orchestratorStubPage.userIsOnPassportcris(expectedText);
        orchestratorStubPage.continueSubmitButton.click();
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

}
