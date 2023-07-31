package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_DeviceSelectionPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_PassportDocCheckPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.IPV_ProveYourIdentityGovUkPage;

import java.util.logging.Logger;

public class IPV_LoginSteps {

    private final IPV_ProveYourIdentityGovUkPage proveYourIdentityGovUkPage =
            new IPV_ProveYourIdentityGovUkPage();
    private final IPV_DeviceSelectionPage deviceSelectionPage = new IPV_DeviceSelectionPage();
    private final IPV_PassportDocCheckPage passportDocCheckPage = new IPV_PassportDocCheckPage();
    private static final Logger LOGGER = Logger.getLogger(IPV_LoginSteps.class.getName());

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
