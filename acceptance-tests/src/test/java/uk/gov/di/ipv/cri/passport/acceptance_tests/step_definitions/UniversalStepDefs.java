package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.UniversalSteps;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.changeLanguageTo;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.setFeatureSet;

public class UniversalStepDefs extends UniversalSteps {

    @And("The test is complete and I close the driver")
    public void closeDriver() {
        driverClose();
    }

    @And("^I add a cookie to change the language to (.*)$")
    public void iAddACookieToChangeTheLanguageToWelsh(String language) {
        changeLanguageTo(language);
    }

    @And("^I set the document checking route$")
    public void setDocumentCheckingRoute() {
        if (System.getProperty("cucumber.tags").equals("@hmpoDVAD")) {
            setFeatureSet("hmpoDVAD");
        }
    }
}
