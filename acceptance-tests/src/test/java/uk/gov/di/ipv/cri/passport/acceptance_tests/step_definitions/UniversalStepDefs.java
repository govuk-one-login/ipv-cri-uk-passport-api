package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.AfterAll;
import io.cucumber.java.en.And;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.UniversalSteps;

import java.util.Objects;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.changeLanguageTo;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.setFeatureSet;

public class UniversalStepDefs extends UniversalSteps {

    @And("The test is complete and I close the driver")
    public void closeDriver() {
        // Intended
        System.out.println("closeDriver() ignored");
    }

    // unused step but keeping in case needed to test language cookie manually instead of with
    // language toggle
    @And("^I add a cookie to change the language to (.*)$")
    public void iAddACookieToChangeTheLanguageToWelsh(String language) {
        changeLanguageTo(language);
    }

    // this is useful for testing FE feature toggles
    @And("^I set the document checking route$")
    public void setDocumentCheckingRoute() {

        boolean hmpoFeatureSet = "@hmpoDVAD".equals(getProperty("cucumber.tags"));

        if (hmpoFeatureSet) {
            setFeatureSet("hmpoDVAD");
        }
    }

    private static String getProperty(String propertyName) {
        String property = System.getProperty(propertyName);
        return Objects.requireNonNullElse(property, "");
    }

    @AfterAll
    public static void cleanUp() {
        System.out.println("CleanUp after tests");
        driverClose();
    }
}
