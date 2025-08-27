package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.TestDataCreator;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.TestInput;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PassportPageObject extends UniversalSteps {

    private final ConfigurationService configurationService;
    private static final Logger LOGGER = LogManager.getLogger();

    @FindBy(className = "error-summary")
    public WebElement errorSummary;

    @FindBy(xpath = "//*[@class='govuk-notification-banner__content']")
    public WebElement userNotFoundInThirdPartyBanner;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/div/a")
    public WebElement proveAnotherWay;

    @FindBy(xpath = "/html/body/div[2]/nav/ul/li[2]/a")
    public WebElement languageToggle;

    @FindBy(xpath = "/html/body/div[2]/nav/ul/li[1]/a")
    public WebElement languageToggleWales;

    @FindBy(id = "govuk-notification-banner-title")
    public WebElement errorText;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/div[1]/div[2]/p[1]")
    public WebElement thereWasAProblemFirstSentence;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/p")
    public WebElement pageDescriptionHeading;

    @FindBy(className = "govuk-error-summary__title")
    public WebElement errorSummaryTitle;

    @FindBy(id = "passportNumber")
    public WebElement passportNumber;

    @FindBy(id = "surname")
    public WebElement LastName;

    @FindBy(id = "firstName")
    public WebElement FirstName;

    @FindBy(id = "middleNames")
    public WebElement MiddleNames;

    @FindBy(id = "dateOfBirth-day")
    public WebElement birthDay;

    @FindBy(id = "dateOfBirth-month")
    public WebElement birthMonth;

    @FindBy(id = "dateOfBirth-year")
    public WebElement birthYear;

    @FindBy(id = "expiryDate-day")
    public WebElement validToDay;

    @FindBy(id = "expiryDate-month")
    public WebElement validToMonth;

    @FindBy(id = "expiryDate-year")
    public WebElement validToYear;

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;

    @FindBy(id = "header")
    public WebElement pageHeader;

    // Error summary items

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'dateOfBirth-day')]")
    public WebElement InvalidDOBErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#passportNumber')]")
    public WebElement InvalidPassportErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#surname')]")
    public WebElement InvalidLastNameErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#firstName')]")
    public WebElement InvalidFirstNameErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#middleNames')]")
    public WebElement InvalidMiddleNamesErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#expiryDate-day')]")
    public WebElement InvalidValidToDateErrorInSummary;

    // -------------------------

    // Field errors

    @FindBy(id = "dateOfBirth-error")
    public WebElement InvalidDateOfBirthFieldError;

    @FindBy(id = "surname-error")
    public WebElement InvalidLastNameFieldError;

    @FindBy(id = "firstName-error")
    public WebElement InvalidFirstNameFieldError;

    @FindBy(id = "middleNames-error")
    public WebElement InvalidMiddleNamesFieldError;

    @FindBy(id = "expiryDate-error")
    public WebElement InvalidValidToDateFieldError;

    @FindBy(id = "passportNumber-error")
    public WebElement PassportNumberFieldError;

    // ------------------------

    // --- Hints ---
    @FindBy(id = "dateOfBirth-hint")
    public WebElement dateOfBirthHint;

    @FindBy(id = "passportNumber-hint")
    public WebElement passportNumberHint;

    @FindBy(id = "firstName-hint")
    public WebElement firstNameHint;

    @FindBy(id = "middleNames-hint")
    public WebElement middleNameHint;

    @FindBy(id = "expiryDate-hint")
    public WebElement validToHint;

    // --- Legend text ---
    @FindBy(xpath = "//*[@id=\"dateOfBirth-fieldset\"]/legend")
    public WebElement dateOfBirthLegend;

    @FindBy(xpath = "//*[@id=\"expiryDate-fieldset\"]/legend")
    public WebElement validToLegend;

    // --- Label text ---
    @FindBy(id = "passportNumber-label")
    public WebElement passportNumberFieldLabel;

    @FindBy(xpath = "//*[@class='govuk-back-link']")
    public WebElement back;

    public PassportPageObject() {
        this.configurationService = new ConfigurationService(System.getenv("ENVIRONMENT"));
        PageFactory.initElements(Driver.get(), this);
        TestDataCreator.createDefaultResponses();
    }

    public void passportPageURLValidation(String path) {
        assertURLContains(path);
    }

    public void userReEntersLastName(String invalidLastName) {
        LastName.clear();
        LastName.sendKeys(invalidLastName);
    }

    public void userReEntersFirstName(String invalidFirstName) {
        FirstName.clear();
        FirstName.sendKeys(invalidFirstName);
    }

    // this method is not currently used, saved for reuse in future
    public void userReEntersMiddleNames(String invalidMiddleNames) {
        MiddleNames.clear();
        MiddleNames.sendKeys(invalidMiddleNames);
    }

    public void userReEntersPassportNumber(String invalidPassportNumber) {
        passportNumber.clear();
        passportNumber.sendKeys(invalidPassportNumber);
    }

    public void userReEntersBirthDay(String invalidBirthDay) {
        birthDay.clear();
        birthDay.sendKeys(invalidBirthDay);
    }

    public void userReEntersBirthMonth(String invalidBirthMonth) {
        birthMonth.clear();
        birthMonth.sendKeys(invalidBirthMonth);
    }

    public void userReEntersBirthYear(String invalidBirthYear) {
        birthYear.clear();
        birthYear.sendKeys(invalidBirthYear);
    }

    public void userReEntersValidToDay(String invalidValidToDate) {
        validToDay.clear();
        validToDay.sendKeys(invalidValidToDate);
    }

    public void userReEntersValidToMonth(String invalidValidToMonth) {
        validToMonth.clear();
        validToMonth.sendKeys(invalidValidToMonth);
    }

    public void userReEntersValidToYear(String invalidValidToYear) {
        validToYear.clear();
        validToYear.sendKeys(invalidValidToYear);
    }

    public void userEntersData(String passportSubjectScenario) {
        TestInput passportSubject =
                TestDataCreator.getPassportTestUserFromMap(passportSubjectScenario);
        passportNumber.sendKeys(passportSubject.getPassportNumber());
        birthDay.sendKeys(passportSubject.getBirthDay());
        birthMonth.sendKeys(passportSubject.getBirthMonth());
        birthYear.sendKeys(passportSubject.getBirthYear());

        LastName.sendKeys(passportSubject.getLastName());
        FirstName.sendKeys(passportSubject.getFirstName());
        validToDay.sendKeys(passportSubject.getValidToDay());
        validToMonth.sendKeys(passportSubject.getValidToMonth());
        validToYear.sendKeys(passportSubject.getValidToYear());
    }

    public void userEntersInvalidPassportDetails() {
        PassportPageObject passportPage = new PassportPageObject();
        passportPage.passportNumber.sendKeys("123456789");
        passportPage.LastName.sendKeys("Testlastname");
        passportPage.FirstName.sendKeys("Testfirstname");
        passportPage.birthDay.sendKeys("11");
        passportPage.birthMonth.sendKeys("10");
        passportPage.birthYear.sendKeys("1962");
        passportPage.validToDay.sendKeys("01");
        passportPage.validToMonth.sendKeys("01");
        passportPage.validToYear.sendKeys("2030");
    }

    // this method is not currently used, saved for reuse in future
    public void enterInvalidLastAndFirstName() {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.LastName.sendKeys("Parker!");
        passportPageObject.FirstName.sendKeys("Peter@@!");
        passportPageObject.MiddleNames.sendKeys("@@@@@@@");
    }

    // this method is not currently used, saved for reuse in future
    public void enterBirthYear(String day, String month, String year) {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.birthDay.clear();
        passportPageObject.birthDay.click();
        passportPageObject.birthDay.sendKeys(day);
        passportPageObject.birthMonth.clear();
        passportPageObject.birthMonth.click();
        passportPageObject.birthMonth.sendKeys(month);
        passportPageObject.birthYear.clear();
        passportPageObject.birthYear.click();
        passportPageObject.birthYear.sendKeys(year);
    }

    // this method is not currently used, saved for reuse in future
    public void enterValidToDate(String day, String month, String year) {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.validToDay.clear();
        passportPageObject.validToDay.click();
        passportPageObject.validToDay.sendKeys(day);
        passportPageObject.validToMonth.clear();
        passportPageObject.validToMonth.click();
        passportPageObject.validToMonth.sendKeys(month);
        passportPageObject.validToYear.clear();
        passportPageObject.validToYear.click();
        passportPageObject.validToYear.sendKeys(year);
    }

    // this method is not currently used, saved for reuse in future
    public void enterPassportNumber(String passportNumber) {
        PassportPageObject passportPage = new PassportPageObject();
        passportPage.passportNumber.clear();
        passportPage.passportNumber.click();
        passportPage.passportNumber.sendKeys(passportNumber);
    }

    public void userReEntersDataAsPassportSubject(String passportSubjectScenario) {
        TestInput passportSubject =
                TestDataCreator.getPassportTestUserFromMap(passportSubjectScenario);

        passportNumber.clear();
        LastName.clear();
        FirstName.clear();
        MiddleNames.clear();
        birthDay.clear();
        birthMonth.clear();
        birthYear.clear();
        validToDay.clear();
        validToMonth.clear();
        validToYear.clear();
        passportNumber.sendKeys(passportSubject.getPassportNumber());
        LastName.sendKeys(passportSubject.getLastName());
        FirstName.sendKeys(passportSubject.getFirstName());
        if (null != passportSubject.getMiddleNames()) {
            MiddleNames.sendKeys(passportSubject.getMiddleNames());
        }
        birthDay.sendKeys(passportSubject.getBirthDay());
        birthMonth.sendKeys(passportSubject.getBirthMonth());
        birthYear.sendKeys(passportSubject.getBirthYear());
        validToDay.sendKeys(passportSubject.getValidToDay());
        validToMonth.sendKeys(passportSubject.getValidToMonth());
        validToYear.sendKeys(passportSubject.getValidToYear());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidDoBInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidDOBErrorInSummary.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidDoBOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidDateOfBirthFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidValidToDateInErrorSummary(String expectedText) {
        BrowserUtils.waitForVisibility(InvalidValidToDateErrorInSummary, 10);
        Assert.assertEquals(expectedText, InvalidValidToDateErrorInSummary.getText());
    }

    public void assertInvalidValidToDateOnField(String expectedText) {
        BrowserUtils.waitForVisibility(InvalidValidToDateFieldError, 10);
        Assert.assertEquals(
                expectedText, InvalidValidToDateFieldError.getText().trim().replace("\n", ""));
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidPassportNumberInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidPassportErrorInSummary.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidPassportNumberOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, PassportNumberFieldError.getText().trim().replace("\n", ""));
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidLastNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidLastNameErrorInSummary.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidLastNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidLastNameFieldError.getText().trim().replace("\n", ""));
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidFirstNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidFirstNameErrorInSummary.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidFirstNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidFirstNameFieldError.getText().trim().replace("\n", ""));
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidMiddleNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidMiddleNamesErrorInSummary.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertInvalidMiddleNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidMiddleNamesFieldError.getText().trim().replace("\n", ""));
    }

    // this method is not currently used, saved for reuse in future
    public void validateErrorPageHeading(String expectedText) {
        Assert.assertEquals(expectedText, pageHeader.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertPageHeading(String expectedText) {
        Assert.assertEquals(expectedText, pageHeader.getText().split("\n")[0]);
    }

    // this method is not currently used, saved for reuse in future
    public void assertProveAnotherWayLinkText(String expectedText) {
        Assert.assertEquals(expectedText, getParent(proveAnotherWay).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertErrorPrefix(String expectedText) {
        Assert.assertEquals(expectedText, errorText.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertFirstLineOfUserNotFoundText(String expectedText) {
        Assert.assertEquals(expectedText, userNotFoundInThirdPartyBanner.getText().split("\n")[0]);
    }

    // this method is not currently used, saved for reuse in future
    public void youWillBeAbleToFindSentence(String expectedText) {
        Assert.assertEquals(expectedText, thereWasAProblemFirstSentence.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertPageSourceContains(String expectedText) {
        assert (Driver.get().getPageSource().contains(expectedText));
    }

    // this method is not currently used, saved for reuse in future
    public void assertLastNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(LastName)).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertGivenNameLegendText(String expectedText) {
        Assert.assertEquals(
                expectedText,
                FirstName.findElement(By.xpath("./../../.."))
                        .findElement(By.tagName("legend"))
                        .getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertMiddleNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(MiddleNames)).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertGivenNameDescription(String expectedText) {
        Assert.assertEquals(
                expectedText, getLabel(firstNameHint.findElement(By.xpath("./../.."))).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertGivenNameHint(String expectedText) {
        Assert.assertEquals(expectedText, firstNameHint.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertMiddleNameHint(String expectedText) {
        Assert.assertEquals(expectedText, middleNameHint.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertDateOfBirthLegendText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthLegend.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertDateOfBirthHintText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthHint.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertBirthDayLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthDay)).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertBirthMonthLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthMonth)).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertBirthYearLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthYear)).getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertValidToHintText(String expectedText) {
        Assert.assertEquals(expectedText, validToHint.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertPassportNumberLabelText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberFieldLabel.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertPassportNumberHintText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberHint.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertPageDescription(String expectedText) {
        Assert.assertEquals(expectedText, pageDescriptionHeading.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertValidToLegend(String expectedText) {
        Assert.assertEquals(expectedText, validToLegend.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertErrorSummaryText(String expectedText) {
        Assert.assertEquals(expectedText, errorSummaryTitle.getText());
    }

    // this method is not currently used, saved for reuse in future
    public void assertCTATextAs(String expectedText) {
        assertEquals(Continue.getText(), expectedText);
    }

    private WebElement getParent(WebElement webElement) {
        return webElement.findElement(By.xpath("./.."));
    }

    private WebElement getLabel(WebElement webElement) {
        return webElement.findElement(By.tagName("label"));
    }

    private LocalDate subtractMonthsFromCurrentDate(int monthsToSubtract) {
        LocalDate currentDate = LocalDate.now();
        LocalDate pastDate = currentDate.minusMonths(monthsToSubtract);

        LOGGER.info(
                "SubtractMonthsFromCurrentDate - monthsToSubtract {}, currentDate {}, pastDate {}",
                monthsToSubtract,
                currentDate,
                pastDate);

        return pastDate;
    }

    public void userNotFoundInThirdPartyErrorIsDisplayed() {
        BrowserUtils.waitForVisibility(userNotFoundInThirdPartyBanner, 10);
        Assert.assertTrue(userNotFoundInThirdPartyBanner.isDisplayed());
        LOGGER.info(userNotFoundInThirdPartyBanner.getText());
    }

    public void userReEntersExpiryDateAsCurrentDateMinus(int monthsToSubtract, int daysToSubtract) {

        LocalDate resultMinusMonths = subtractMonthsFromCurrentDate(monthsToSubtract);
        LocalDate resultMinusDays = resultMinusMonths.minusDays(daysToSubtract);

        LOGGER.info(
                "UserReEntersExpiryDateAsCurrentDateMinus - monthsToSubtract {}, daysToSubtract {}, resultMinusMonths {}, resultMinusDays {}",
                monthsToSubtract,
                daysToSubtract,
                resultMinusMonths,
                resultMinusDays);

        String dayMinusEighteen = String.valueOf(resultMinusDays.getDayOfMonth());
        String monthMinusEighteen = String.valueOf(resultMinusDays.getMonthValue());
        String yearMinusEighteen = String.valueOf(resultMinusDays.getYear());

        validToDay.clear();
        validToMonth.clear();
        validToYear.clear();

        validToDay.sendKeys(dayMinusEighteen);
        validToMonth.sendKeys(monthMinusEighteen);
        validToYear.sendKeys(yearMinusEighteen);
    }
}
