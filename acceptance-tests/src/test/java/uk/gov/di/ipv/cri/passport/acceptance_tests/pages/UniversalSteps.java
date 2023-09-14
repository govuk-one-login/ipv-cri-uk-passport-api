package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import java.time.Duration;
import static org.junit.Assert.assertTrue;

public class UniversalSteps {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int WAIT_DELAY_SEC = 10;

    public UniversalSteps() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void assertPageTitle(String expTitle, boolean fuzzy) {
        ImplicitlyWait();

        String title = Driver.get().getTitle();

        boolean match = fuzzy ? title.contains(expTitle) : title.equals(expTitle);

        LOGGER.info("Page title: " + title);
        assertTrue(match);
    }

    public void driverClose() {
        Driver.closeDriver();
    }

    public void assertURLContains(String expected) {
        ImplicitlyWait();

        String url = Driver.get().getCurrentUrl();

        LOGGER.info("Page url: " + url);
        assertTrue(url.contains(expected));
    }

    public static void ImplicitlyWait() {
        Driver.get().manage().timeouts().implicitlyWait(Duration.ofSeconds(WAIT_DELAY_SEC));
    }
}
