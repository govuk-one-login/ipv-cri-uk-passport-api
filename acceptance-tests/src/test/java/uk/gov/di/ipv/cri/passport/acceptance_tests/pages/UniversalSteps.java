package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import static org.junit.Assert.assertTrue;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.waitForPageToLoad;

public class UniversalSteps {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int MAX_WAIT_SEC = 10;

    public UniversalSteps() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void assertPageTitle(String expTitle, boolean fuzzy) {
        waitForPageToLoad(MAX_WAIT_SEC);

        String title = Driver.get().getTitle();

        boolean match = fuzzy ? title.contains(expTitle) : title.equals(expTitle);

        LOGGER.info("Page title: " + title);
        assertTrue(match);
    }

    public void driverClose() {
        Driver.closeDriver();
    }

    public void assertURLContains(String expected) {
        waitForPageToLoad(MAX_WAIT_SEC);

        String url = Driver.get().getCurrentUrl();

        LOGGER.info("Page url: " + url);
        assertTrue(url.contains(expected));
    }
}
