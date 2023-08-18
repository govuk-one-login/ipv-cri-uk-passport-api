package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import java.time.Duration;

import static org.junit.Assert.assertTrue;

public class UniversalSteps {

    public UniversalSteps() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void driverClose() {
        Driver.closeDriver();
    }

    public void assertURLContains(String expected) {
        WebDriver driver = Driver.get();
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(2));

        String url = driver.getCurrentUrl();
        assertTrue(url.contains(expected));
    }
}
