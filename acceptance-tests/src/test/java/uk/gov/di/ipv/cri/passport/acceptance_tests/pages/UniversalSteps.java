package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import static org.junit.Assert.assertTrue;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils.waitForPageToLoad;

public class UniversalSteps {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int MAX_WAIT_SEC = 60;

    public UniversalSteps() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void assertPageTitle(String expTitle, boolean fuzzy) {
        waitForPageToLoad(MAX_WAIT_SEC);

        String title = Driver.get().getTitle();
        if (title == null) {
            title = "Driver had no page title";
        }

        final boolean match = fuzzy ? title.contains(expTitle) : title.equals(expTitle);

        LOGGER.info(
                "{} match - Page title: {}, Expected {}",
                fuzzy ? "Fuzzy" : "Match",
                title,
                expTitle);

        if (!match) {
            // Log the entire page content if title match fails
            // Body logged as there are several error pages
            LOGGER.error(
                    "Error page content - : {}",
                    Driver.get().findElement(By.tagName("body")).getText());
        }

        Assert.assertTrue(match);
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
