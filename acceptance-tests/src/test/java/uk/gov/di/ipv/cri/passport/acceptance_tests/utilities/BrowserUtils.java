package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.openqa.selenium.*;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.pages.UniversalSteps.MAX_WAIT_SEC;

public class BrowserUtils {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Switches to new window by the exact title. Returns to original window if target title not
     * found
     *
     * @param targetTitle
     */
    public static void switchToWindow(String targetTitle) {
        String origin = Driver.get().getWindowHandle();
        for (String handle : Driver.get().getWindowHandles()) {
            Driver.get().switchTo().window(handle);
            if (Driver.get().getTitle().equals(targetTitle)) {
                return;
            }
        }
        Driver.get().switchTo().window(origin);
    }

    /**
     * Moves the mouse to given element
     *
     * @param element on which to hover
     */
    public static void hover(WebElement element) {
        Actions actions = new Actions(Driver.get());
        actions.moveToElement(element).perform();
    }

    /**
     * return a list of string from a list of elements
     *
     * @param list of webelements
     * @return list of string
     */
    public static List<String> getElementsText(List<WebElement> list) {
        List<String> elemTexts = new ArrayList<>();
        for (WebElement el : list) {
            elemTexts.add(el.getText());
        }
        return elemTexts;
    }

    /**
     * Extracts text from list of elements matching the provided locator into new List<String>
     *
     * @param locator
     * @return list of strings
     */
    public static List<String> getElementsText(By locator) {

        List<WebElement> elems = Driver.get().findElements(locator);
        List<String> elemTexts = new ArrayList<>();

        for (WebElement el : elems) {
            elemTexts.add(el.getText());
        }
        return elemTexts;
    }

    /**
     * Performs a pause
     *
     * @param seconds
     */
    public static void waitFor(int seconds) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Waits for the provided element to be visible on the page
     *
     * @param element
     * @param timeToWaitInSec
     * @return
     */
    public static WebElement waitForVisibility(WebElement element, int timeToWaitInSec) {
        WebDriverWait wait = new WebDriverWait(Driver.get(), Duration.ofSeconds(timeToWaitInSec));
        return wait.until(ExpectedConditions.visibilityOf(element));
    }

    /**
     * Waits for element matching the locator to be visible on the page
     *
     * @param locator
     * @param timeout
     * @return
     */
    public static WebElement waitForVisibility(By locator, int timeout) {
        WebDriverWait wait = new WebDriverWait(Driver.get(), Duration.ofSeconds(timeout));
        return wait.until(ExpectedConditions.visibilityOfElementLocated(locator));
    }

    /**
     * Waits for provided element to be clickable
     *
     * @param element
     * @param timeout
     * @return
     */
    public static WebElement waitForClickablility(WebElement element, int timeout) {
        WebDriverWait wait = new WebDriverWait(Driver.get(), Duration.ofSeconds(timeout));
        return wait.until(ExpectedConditions.elementToBeClickable(element));
    }

    /**
     * Waits for element matching the locator to be clickable
     *
     * @param locator
     * @param timeout
     * @return
     */
    public static WebElement waitForClickablility(By locator, int timeout) {
        WebDriverWait wait = new WebDriverWait(Driver.get(), Duration.ofSeconds(timeout));
        return wait.until(ExpectedConditions.elementToBeClickable(locator));
    }

    /**
     * waits for backgrounds processes on the browser to complete
     *
     * @param timeOutInSeconds
     */
    public static void waitForPageToLoad(long timeOutInSeconds) {
        ExpectedCondition<Boolean> expectation =
                new ExpectedCondition<Boolean>() {
                    public Boolean apply(WebDriver driver) {
                        return ((JavascriptExecutor) driver)
                                .executeScript("return document.readyState")
                                .equals("complete");
                    }
                };
        try {
            WebDriverWait wait =
                    new WebDriverWait(Driver.get(), Duration.ofSeconds(timeOutInSeconds));
            wait.until(expectation);
        } catch (Throwable error) {
            error.printStackTrace();
        }
    }

    /**
     * Waits for a page with the provided title to fully load. Optionally can be an exact or fuzzy
     * title match.
     *
     * @param timeOutInSeconds
     */
    public static boolean waitForSpecificPageWithTitleToFullyLoad(
            String expectedTitle, boolean exactTitleMatchRequired, long timeOutInSeconds) {

        ExpectedCondition<Boolean> pageLoadedExpectation =
                new ExpectedCondition<Boolean>() {
                    public Boolean apply(WebDriver driver) {
                        return ((JavascriptExecutor) driver)
                                .executeScript("return document.readyState")
                                .equals("complete");
                    }
                };

        try {
            WebDriverWait wait =
                    new WebDriverWait(Driver.get(), Duration.ofSeconds(timeOutInSeconds));
            wait.until(pageLoadedExpectation);
        } catch (Throwable error) {
            error.printStackTrace();
            return false;
        }

        ExpectedCondition<Boolean> titleExpectation =
                new ExpectedCondition<Boolean>() {
                    public Boolean apply(WebDriver driver) {
                        String title = driver.getTitle();

                        if (title == null || expectedTitle == null) {
                            return false;
                        }

                        System.out.println(
                                "title: "
                                        + title
                                        + " "
                                        + expectedTitle
                                        + " "
                                        + title.contains(expectedTitle));

                        return exactTitleMatchRequired
                                ? title.equals(expectedTitle)
                                : title.contains(expectedTitle);
                    }
                };

        try {
            WebDriverWait wait =
                    new WebDriverWait(Driver.get(), Duration.ofSeconds(timeOutInSeconds));
            wait.until(titleExpectation);
        } catch (Throwable error) {
            error.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Waits for a page with the provided title to fully load. Optionally can be an exact or fuzzy
     * title match.
     *
     * @param timeOutInSeconds
     */
    public static boolean waitForUrlToContain(String expectedText, long timeOutInSeconds) {

        ExpectedCondition<Boolean> pageLoadedExpectation =
                new ExpectedCondition<Boolean>() {
                    public Boolean apply(WebDriver driver) {
                        return ((JavascriptExecutor) driver)
                                .executeScript("return document.readyState")
                                .equals("complete");
                    }
                };

        try {
            WebDriverWait wait =
                    new WebDriverWait(Driver.get(), Duration.ofSeconds(timeOutInSeconds));
            wait.until(pageLoadedExpectation);
        } catch (Throwable error) {
            error.printStackTrace();
            return false;
        }

        ExpectedCondition<Boolean> urlCheckExpectation =
                new ExpectedCondition<Boolean>() {
                    public Boolean apply(WebDriver driver) {
                        String url = driver.getCurrentUrl();

                        if (url == null) {
                            return false;
                        }

                        System.out.println(
                                "URL: "
                                        + url
                                        + " "
                                        + expectedText
                                        + " "
                                        + url.contains(expectedText));

                        return url.contains(expectedText);
                    }
                };

        try {
            WebDriverWait wait =
                    new WebDriverWait(Driver.get(), Duration.ofSeconds(timeOutInSeconds));
            wait.until(urlCheckExpectation);
        } catch (Throwable error) {
            error.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Verifies whether the element matching the provided locator is displayed on page
     *
     * @param by
     * @throws AssertionError if the element matching the provided locator is not found or not
     *     displayed
     */
    public static void verifyElementDisplayed(By by) {
        try {
            Assert.assertTrue(
                    "Element not visible: " + by, Driver.get().findElement(by).isDisplayed());
        } catch (NoSuchElementException e) {
            LOGGER.error(e);
            Assert.fail("Element not found: " + by);
        }
    }

    /**
     * Verifies whether the element matching the provided locator is NOT displayed on page
     *
     * @param by
     * @throws AssertionError the element matching the provided locator is displayed
     */
    public static void verifyElementNotDisplayed(By by) {
        try {
            Assert.assertFalse(
                    "Element should not be visible: " + by,
                    Driver.get().findElement(by).isDisplayed());
        } catch (NoSuchElementException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Verifies whether the element is displayed on page
     *
     * @param element
     * @throws AssertionError if the element is not found or not displayed
     */
    public static void verifyElementDisplayed(WebElement element) {
        try {
            Assert.assertTrue("Element not visible: " + element, element.isDisplayed());
        } catch (NoSuchElementException e) {
            LOGGER.error(e);
            Assert.fail("Element not found: " + element);
        }
    }

    /**
     * Waits for element to be not stale
     *
     * @param element
     */
    public static void waitForStaleElement(WebElement element) {
        int y = 0;
        while (y <= 15) {
            if (y == 1)
                try {
                    element.isDisplayed();
                    break;
                } catch (StaleElementReferenceException st) {
                    y++;
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        LOGGER.error(e);
                    }
                } catch (WebDriverException we) {
                    y++;
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        LOGGER.error(e);
                    }
                }
        }
    }

    /**
     * Clicks on an element using JavaScript
     *
     * @param element
     */
    public static void clickWithJS(WebElement element) {
        ((JavascriptExecutor) Driver.get())
                .executeScript("arguments[0].scrollIntoView(true);", element);
        ((JavascriptExecutor) Driver.get()).executeScript("arguments[0].click();", element);
    }

    /**
     * Scrolls down to an element using JavaScript
     *
     * @param element
     */
    public static void scrollToElement(WebElement element) {
        ((JavascriptExecutor) Driver.get())
                .executeScript("arguments[0].scrollIntoView(true);", element);
    }

    /**
     * Performs double click action on an element
     *
     * @param element
     */
    public static void doubleClick(WebElement element) {
        new Actions(Driver.get()).doubleClick(element).build().perform();
    }

    /**
     * Changes the HTML attribute of a Web Element to the given value using JavaScript
     *
     * @param element
     * @param attributeName
     * @param attributeValue
     */
    public static void setAttribute(
            WebElement element, String attributeName, String attributeValue) {
        ((JavascriptExecutor) Driver.get())
                .executeScript(
                        "arguments[0].setAttribute(arguments[1], arguments[2]);",
                        element,
                        attributeName,
                        attributeValue);
    }

    /**
     * Highlighs an element by changing its background and border color
     *
     * @param element
     */
    public static void highlight(WebElement element) {
        ((JavascriptExecutor) Driver.get())
                .executeScript(
                        "arguments[0].setAttribute('style', 'background: yellow; border: 2px solid red;');",
                        element);
        waitFor(1);
        ((JavascriptExecutor) Driver.get())
                .executeScript(
                        "arguments[0].removeAttribute('style', 'background: yellow; border: 2px solid red;');",
                        element);
    }

    /**
     * Checks or unchecks given checkbox
     *
     * @param element
     * @param check
     */
    public static void selectCheckBox(WebElement element, boolean check) {
        if (check) {
            if (!element.isSelected()) {
                element.click();
            }
        } else {
            if (element.isSelected()) {
                element.click();
            }
        }
    }

    /**
     * attempts to click on provided element until given time runs out
     *
     * @param element
     * @param timeout
     */
    public static void clickWithTimeOut(WebElement element, int timeout) {
        for (int i = 0; i < timeout; i++) {
            try {
                element.click();
                return;
            } catch (WebDriverException e) {
                waitFor(1);
            }
        }
    }

    /**
     * executes the given JavaScript command on given web element
     *
     * @param element
     */
    public static void executeJScommand(WebElement element, String command) {
        JavascriptExecutor jse = (JavascriptExecutor) Driver.get();
        jse.executeScript(command, element);
    }

    /**
     * executes the given JavaScript command on given web element
     *
     * @param command
     */
    public static void executeJScommand(String command) {
        JavascriptExecutor jse = (JavascriptExecutor) Driver.get();
        jse.executeScript(command);
    }

    /**
     * This method will recover in case of exception after unsuccessful the click, and will try to
     * click on element again.
     *
     * @param by
     * @param attempts
     */
    public static void clickWithWait(By by, int attempts) {
        int counter = 0;
        // click on element as many as you specified in attempts parameter
        while (counter < attempts) {
            try {
                // selenium must look for element again
                clickWithJS(Driver.get().findElement(by));
                // if click is successful - then break
                break;
            } catch (WebDriverException e) {
                // if click failed
                // print exception
                // print attempt
                LOGGER.error(e);
                ++counter;
                // wait for 1 second, and try to click again
                waitFor(1);
            }
        }
    }

    /**
     * checks that an element is present on the DOM of a page. This does not * necessarily mean that
     * the element is visible.
     *
     * @param by
     * @param time
     */
    public static void waitForPresenceOfElement(By by, long time) {
        new WebDriverWait(Driver.get(), Duration.ofSeconds(time))
                .until(ExpectedConditions.presenceOfElementLocated(by));
    }

    public static void deleteCookie(String cookieName) {
        Set<Cookie> cookies = Driver.get().manage().getCookies();

        for (Cookie cookie : cookies) {
            LOGGER.info(cookie.getName() + ":" + cookie.getValue());
        }
        Driver.get().manage().deleteCookieNamed(cookieName);
        Driver.get().navigate().refresh();
    }

    public static String changeLanguageTo(final String language) {

        String languageCode = "en";
        switch (language) {
            case "Welsh":
                {
                    languageCode = "cy";
                }
        }

        String currentURL = Driver.get().getCurrentUrl();
        String newURL = currentURL + "/?lng=" + languageCode;
        Driver.get().get(newURL);

        waitForPageToLoad(MAX_WAIT_SEC);

        return languageCode;
    }

    public static void setFeatureSet(final String featureSet) {
        LOGGER.info("Setting feature set : {}", featureSet);

        String currentURL = Driver.get().getCurrentUrl();

        String featureKeyValuePair = "featureSet=" + featureSet;
        int li = currentURL.lastIndexOf('?');
        String newURL;

        if (li == -1) {
            // First parameter
            newURL = currentURL + "?" + featureKeyValuePair;
        } else {
            // Additional parameter
            newURL = currentURL + "&" + featureKeyValuePair;
        }

        LOGGER.debug("newURL with feature set : {}", newURL);
        Driver.get().get(newURL);
    }

    public static void logFeatureSetTag(final String featureSet) {
        LOGGER.info("Feature set tag was : {}", featureSet);
    }

    public static HttpResponse<String> sendHttpRequest(HttpRequest request)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response;
    }

    public static void checkOkHttpResponseOnLink(String link) {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(link)).GET().build();
        HttpResponse<String> httpResponse = null;
        try {
            httpResponse = sendHttpRequest(request);
            int statusCode = httpResponse.statusCode();
            assertEquals(statusCode, 200);
        } catch (IOException | InterruptedException e) {
            fail("Failed to get 200 back on request to url");
        }
    }
}
