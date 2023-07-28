package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_CheckAndConfirmYourAddressPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_ChooseYourAddressPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_FindYourAddressPage;

import java.io.IOException;

public class IPV_AddressCriSteps {

    private final IPV_FindYourAddressPage findYourAddressPage = new IPV_FindYourAddressPage();
    private final IPV_ChooseYourAddressPage chooseYourAddressPage = new IPV_ChooseYourAddressPage();
    private final IPV_CheckAndConfirmYourAddressPage checkAndConfirmYourAddressPage =
            new IPV_CheckAndConfirmYourAddressPage();

    @Then("User should be on Address CRI Page")
    public void userShouldBeOnAddressCRIPage() {
        findYourAddressPage.waitForPageToLoad();
        findYourAddressPage.validateAddPage();
    }

    @And("the user {string} {string} adds their Address Details")
    public void theUserSuccessfullyAddsTheirAddressDetails(
            String userName, String addressCriSuccess) throws IOException {
        findYourAddressPage.searchForUserAddress(userName);
        chooseYourAddressPage.selectUserAddress(userName, addressCriSuccess);
        checkAndConfirmYourAddressPage.checkAndConfirmUserAddress(userName);
    }

    @And("user enters data in address stub and Click on submit data and generate auth code")
    public void userEntersDataInAddressStubAndClickOnSubmitDataAndGenerateAuthCode() {
        chooseYourAddressPage.selectStubUserAddress();
    }

    @Then("User should see error recovery page")
    public void userShouldSeeErrorRecoveryPage() {
        chooseYourAddressPage.backButtonErrPage();
    }
}
