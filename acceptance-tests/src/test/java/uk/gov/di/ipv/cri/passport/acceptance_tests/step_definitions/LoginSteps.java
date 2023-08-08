package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.DeviceSelectionPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PassportDocCheckPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.ProveYourIdentityGovUkPage;

import java.util.logging.Logger;

public class LoginSteps {

    private final ProveYourIdentityGovUkPage proveYourIdentityGovUkPage =
            new ProveYourIdentityGovUkPage();
    private final DeviceSelectionPage deviceSelectionPage = new DeviceSelectionPage();
    private final PassportDocCheckPage passportDocCheckPage = new PassportDocCheckPage();
    private static final Logger LOGGER = Logger.getLogger(LoginSteps.class.getName());

    @And("clicks continue on the signed into your GOV.UK One Login page")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPage() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        try {
            if (deviceSelectionPage.isDeviceSelectionScreenPresent()) {
                deviceSelectionPage.selectNoMobileDeviceAndContinue();
                deviceSelectionPage.selectNoIphoneOrAndroidAndContinue();
            }
        } catch (NullPointerException e) {
            LOGGER.warning(
                    "No environment variable specified, please specify a variable for runs in Integration");
        }
        passportDocCheckPage.waitForPageToLoad();
        passportDocCheckPage.passportDocCheck();
    }
}
