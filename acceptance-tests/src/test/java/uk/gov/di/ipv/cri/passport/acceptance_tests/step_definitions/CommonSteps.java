package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CommonSteps {

    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));

    private final OrchestratorStubPage orchestratorStubPage = new OrchestratorStubPage();

    @Given("I am on Orchestrator Stub")
    public void i_am_on_orchestrator_stub() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I click on Debug route")
    public void i_click_on_debug_route() {
        orchestratorStubPage.DebugRoute.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @And("^I click on Full journey route and Continue$")
    public void clickOnFullJourneyRoute() {
        orchestratorStubPage.clickOnFullJourneyRouteButton();
        orchestratorStubPage.continueSubmitButton.click();
    }

    @When("User clicks on submit button")
    public void user_clicks_on_submit() {
        orchestratorStubPage.continueSubmitButton.click();
    }
}
