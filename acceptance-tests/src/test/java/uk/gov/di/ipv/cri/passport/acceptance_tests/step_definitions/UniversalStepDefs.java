package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.After;
import io.cucumber.java.AfterAll;
import io.cucumber.java.en.And;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.UniversalSteps;

import java.util.Objects;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.changeLanguageTo;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.setFeatureSet;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver.closeAllDrivers;

public class UniversalStepDefs extends UniversalSteps {

    private static final Logger LOGGER = LoggerFactory.getLogger(UniversalStepDefs.class);
    private static final int DELAY_BETWEEN_SCENARIOS_MS = 500;

    @After("@stub or @uat or @traffic or @smoke")
    @SuppressWarnings("java:S2925")
    public void waitBetweenScenarios() {
        try {
            // We want to wait between tests enough to not overload smaller F.E
            // But not so long we push the test duration up
            LOGGER.info(
                    "Waiting {}ms between scenarios to avoid overloading F.E.",
                    DELAY_BETWEEN_SCENARIOS_MS);
            Thread.sleep(DELAY_BETWEEN_SCENARIOS_MS);
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
        }
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
        closeAllDrivers();
    }
}
