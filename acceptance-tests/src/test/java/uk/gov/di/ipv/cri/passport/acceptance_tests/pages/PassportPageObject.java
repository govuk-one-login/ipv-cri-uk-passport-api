package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.apache.commons.lang3.StringUtils;
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

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.pages.Headers.IPV_CORE_STUB;

public class PassportPageObject extends UniversalSteps {

    private final ConfigurationService configurationService;
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String STUB_VC_PAGE_TITLE = "IPV Core Stub Credential Result - GOV.UK";

    private static final String STUB_ERROR_PAGE_TITLE = "IPV Core Stub - GOV.UK";

    // Should be separate stub page

    @FindBy(xpath = "//*[@id=\"main-content\"]/p/a/button")
    public WebElement visitCredentialIssuers;

    @FindBy(xpath = "//*[@value=\"Passport CRI dev\"]")
    public WebElement passportCRIDevLocalStub;

    @FindBy(xpath = "//*[@value=\"Passport CRI Shared dev\"]")
    public WebElement passportCRISharedDevLocalStub;

    @FindBy(xpath = "//*[@value=\"Passport CRI Dev\"]")
    public WebElement passportCRIDev;

    @FindBy(xpath = "//*[@value=\"Passport CRI Shared Dev\"]")
    public WebElement passportCRISharedDev;

    @FindBy(xpath = "//*[@value=\"Passport CRI Build\"]")
    public WebElement passportCRIBuild;

    @FindBy(xpath = "//*[@value=\"Passport CRI Staging\"]")
    public WebElement passportCRIStaging;

    @FindBy(xpath = "//*[@value=\"Passport CRI Integration\"]")
    public WebElement passportCRIIntegration;

    @FindBy(id = "rowNumber")
    public WebElement selectRow;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details/div/pre")
    public WebElement JSONPayload;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details")
    public WebElement errorResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details/summary/span")
    public WebElement viewResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/form[2]/div/button")
    public WebElement searchButton;

    @FindBy(xpath = "//*[@id=\"main-content\"]/form[2]/div/button")
    public WebElement goToPassportCRIButton;

    // ---------------------

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

    @FindBy(id = "proveAnotherWayRadio")
    public WebElement proveAnotherWayRadio;

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

    // Should be in stub page
    public void navigateToIPVCoreStub() {
        Driver.get().manage().deleteAllCookies();

        String coreStubUrl = configurationService.getCoreStubUrl(true);
        Driver.get().get(coreStubUrl);
        assertExpectedPage(IPV_CORE_STUB, false);
    }

    public void navigateToPassportCRIOnTestEnv() {
        visitCredentialIssuers.click();
        String passportCRITestEnvironment = configurationService.getPassportCRITestEnvironment();
        LOGGER.info("passportCRITestEnvironment = " + passportCRITestEnvironment);

        boolean sharedDev = passportCRITestEnvironment.toLowerCase().contains("shared");

        boolean isUsingLocalStub = configurationService.isUsingLocalStub();
        LOGGER.info("isUsingLocalStub = " + isUsingLocalStub);

        if (isUsingLocalStub) {
            // Local Stub - Passport CRI dev V1 or Passport CRI Shared dev V1
            if (!sharedDev) {
                passportCRIDevLocalStub.click();
            } else {
                passportCRISharedDevLocalStub.click();
            }
        } else if (passportCRITestEnvironment.toLowerCase().contains("dev")) {
            // Hosted Stub - Passport CRI Dev V1 or Passport CRI Shared Dev V1
            if (!sharedDev) {
                passportCRIDev.click();
            } else {
                passportCRISharedDev.click();
            }
        } else if (passportCRITestEnvironment.toLowerCase().contains("build")) {
            passportCRIBuild.click();
        } else if (passportCRITestEnvironment.toLowerCase().contains("staging")) {
            passportCRIStaging.click();
        } else if (passportCRITestEnvironment.toLowerCase().contains("integration")) {
            passportCRIIntegration.click();
        } else {
            LOGGER.info("No test environment is set");
        }
    }

    public void searchForUATUser(String number) {
        assertURLContains(
                "credential-issuer?cri="
                        + "passport-v1-cri-"
                        + System.getenv("ENVIRONMENT").toLowerCase());
        selectRow.sendKeys(number);
        searchButton.click();
    }

    public void navigateToPassportResponse(String validOrInvalid) {
        assertURLContains("callback");

        if ("Invalid".equalsIgnoreCase(validOrInvalid)) {
            assertExpectedPage(STUB_ERROR_PAGE_TITLE, true);
            assertURLContains("callback");
            BrowserUtils.waitForVisibility(errorResponse, 10);
            errorResponse.click();
        } else {
            assertExpectedPage(STUB_VC_PAGE_TITLE, true);
            assertURLContains("callback");
            BrowserUtils.waitForVisibility(viewResponse, 10);
            viewResponse.click();
        }
    }

    public void navigateToPassportCRI() {
        goToPassportCRIButton.click();
    }

    // ------------------

    // Should be seperate page

    public void passportPageURLValidation(String path) {
        assertURLContains(path);
    }

    public void jsonErrorResponse(String expectedErrorDescription, String expectedErrorStatusCode)
            throws JsonProcessingException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);

        JsonNode insideError = getJsonNode(result, "errorObject");
        LOGGER.info("insideError = " + insideError);

        JsonNode errorDescription = insideError.get("description");
        JsonNode statusCode = insideError.get("httpstatusCode");
        String ActualErrorDescription = insideError.get("description").asText();
        String ActualStatusCode = insideError.get("httpstatusCode").asText();

        LOGGER.info("errorDescription = " + errorDescription);
        LOGGER.info("statusCode = " + statusCode);
        LOGGER.info("testErrorDescription = " + expectedErrorDescription);
        LOGGER.info("testStatusCode = " + expectedErrorStatusCode);

        Assert.assertEquals(expectedErrorDescription, ActualErrorDescription);
        Assert.assertEquals(expectedErrorStatusCode, ActualStatusCode);
    }

    public void checkScoreInStubIs(String validityScore, String strengthScore) throws IOException {
        scoreIs(validityScore, strengthScore, JSONPayload.getText());
    }

    public void scoreIs(String validityScore, String strengthScore, String jsonPayloadText)
            throws IOException {
        String result = jsonPayloadText;
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        List<JsonNode> evidence = getListOfNodes(vcNode, "evidence");

        String ValidityScore = evidence.get(0).get("validityScore").asText();
        assertEquals(ValidityScore, validityScore);

        String StrengthScore = evidence.get(0).get("strengthScore").asText();
        assertEquals(StrengthScore, strengthScore);
    }

    public void assertCheckDetailsWithinVc(String checkDetailsType, String passportCriVc)
            throws IOException {

        JsonNode vcNode = getJsonNode(passportCriVc, "vc");
        List<JsonNode> evidence = getListOfNodes(vcNode, "evidence");

        String checkDetails = null;
        if (checkDetailsType.equals("success")) {
            checkDetails = evidence.get(0).get("checkDetails").toString();
        } else {
            checkDetails = evidence.get(0).get("failedCheckDetails").toString();
        }
        assertEquals("[{\"checkMethod\":\"data\"}]", checkDetails);
    }

    public void userNotFoundInThirdPartyErrorIsDisplayed() {
        BrowserUtils.waitForVisibility(userNotFoundInThirdPartyBanner, 10);
        Assert.assertTrue(userNotFoundInThirdPartyBanner.isDisplayed());
        LOGGER.info(userNotFoundInThirdPartyBanner.getText());
    }

    public void userReEntersLastName(String invalidLastName) {
        LastName.clear();
        LastName.sendKeys(invalidLastName);
    }

    public void userReEntersFirstName(String invalidFirstName) {
        FirstName.clear();
        FirstName.sendKeys(invalidFirstName);
    }

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

    // Why is this invalid
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

        //        BrowserUtils.waitForPageToLoad(10);
    }

    public void enterInvalidLastAndFirstName() {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.LastName.sendKeys("Parker!");
        passportPageObject.FirstName.sendKeys("Peter@@!");
        passportPageObject.MiddleNames.sendKeys("@@@@@@@");
    }

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

    public void assertInvalidDoBInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidDOBErrorInSummary.getText());
    }

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

    public void assertInvalidPassportNumberInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidPassportErrorInSummary.getText());
    }

    public void assertInvalidPassportNumberOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, PassportNumberFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidLastNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidLastNameErrorInSummary.getText());
    }

    public void assertInvalidLastNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidLastNameFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidFirstNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidFirstNameErrorInSummary.getText());
    }

    public void assertInvalidFirstNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidFirstNameFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidMiddleNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidMiddleNamesErrorInSummary.getText());
    }

    public void assertInvalidMiddleNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidMiddleNamesFieldError.getText().trim().replace("\n", ""));
    }

    public void ciInVC(String ci) throws IOException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        JsonNode evidenceNode = vcNode.get("evidence");

        List<String> cis = getCIsFromEvidence(evidenceNode);

        if (StringUtils.isNotEmpty(ci)) {
            if (cis.size() > 0) {
                LOGGER.info("HELP " + Arrays.toString(cis.toArray()) + "    " + ci);
                assertTrue(cis.contains(ci));
            } else {
                fail("No CIs found");
            }
        }
    }

    public void assertDocumentNumberInVc(String documentNumber) throws IOException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        String passportNumber = getDocumentNumberFromVc(vcNode);
        assertEquals(documentNumber, passportNumber);
    }

    public void validateErrorPageHeading(String expectedText) {
        Assert.assertEquals(expectedText, pageHeader.getText());
    }

    public void assertPageHeading(String expectedText) {
        Assert.assertEquals(expectedText, pageHeader.getText().split("\n")[0]);
    }

    public void assertProveAnotherWayLinkText(String expectedText) {
        Assert.assertEquals(expectedText, getParent(proveAnotherWay).getText());
    }

    public void assertErrorPrefix(String expectedText) {
        Assert.assertEquals(expectedText, errorText.getText());
    }

    public void assertFirstLineOfUserNotFoundText(String expectedText) {
        Assert.assertEquals(expectedText, userNotFoundInThirdPartyBanner.getText().split("\n")[0]);
    }

    public void youWillBeAbleToFindSentence(String expectedText) {
        Assert.assertEquals(expectedText, thereWasAProblemFirstSentence.getText());
    }

    public void assertPageSourceContains(String expectedText) {
        assert (Driver.get().getPageSource().contains(expectedText));
    }

    public void assertLastNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(LastName)).getText());
    }

    public void assertGivenNameLegendText(String expectedText) {
        Assert.assertEquals(
                expectedText,
                FirstName.findElement(By.xpath("./../../.."))
                        .findElement(By.tagName("legend"))
                        .getText());
    }

    public void assertMiddleNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(MiddleNames)).getText());
    }

    public void assertGivenNameDescription(String expectedText) {
        Assert.assertEquals(
                expectedText, getLabel(firstNameHint.findElement(By.xpath("./../.."))).getText());
    }

    public void assertGivenNameHint(String expectedText) {
        Assert.assertEquals(expectedText, firstNameHint.getText());
    }

    public void assertMiddleNameHint(String expectedText) {
        Assert.assertEquals(expectedText, middleNameHint.getText());
    }

    public void assertDateOfBirthLegendText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthLegend.getText());
    }

    public void assertDateOfBirthHintText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthHint.getText());
    }

    public void assertBirthDayLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthDay)).getText());
    }

    public void assertBirthMonthLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthMonth)).getText());
    }

    public void assertBirthYearLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthYear)).getText());
    }

    public void assertValidToHintText(String expectedText) {
        Assert.assertEquals(expectedText, validToHint.getText());
    }

    public void assertPassportNumberLabelText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberFieldLabel.getText());
    }

    public void assertPassportNumberHintText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberHint.getText());
    }

    public void assertPageDescription(String expectedText) {
        Assert.assertEquals(expectedText, pageDescriptionHeading.getText());
    }

    public void assertValidToLegend(String expectedText) {
        Assert.assertEquals(expectedText, validToLegend.getText());
    }

    public void assertErrorSummaryText(String expectedText) {
        Assert.assertEquals(expectedText, errorSummaryTitle.getText());
    }

    public void assertCTATextAs(String expectedText) {
        assertEquals(Continue.getText(), expectedText);
    }

    private List<String> getCIsFromEvidence(JsonNode evidenceNode) throws IOException {
        ObjectReader objectReader =
                new ObjectMapper().readerFor(new TypeReference<List<JsonNode>>() {});
        List<JsonNode> evidence = objectReader.readValue(evidenceNode);

        List<String> cis =
                getListOfNodes(evidence.get(0), "ci").stream()
                        .map(JsonNode::asText)
                        .collect(Collectors.toList());
        return cis;
    }

    private JsonNode getJsonNode(String result, String vc) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(result);
        return jsonNode.get(vc);
    }

    private String getDocumentNumberFromVc(JsonNode vcNode) throws IOException {
        JsonNode credentialSubject = vcNode.findValue("credentialSubject");
        List<JsonNode> evidence = getListOfNodes(credentialSubject, "passport");

        String passportNumber = evidence.get(0).get("documentNumber").asText();
        return passportNumber;
    }

    private List<JsonNode> getListOfNodes(JsonNode vcNode, String evidence) throws IOException {
        JsonNode evidenceNode = vcNode.get(evidence);

        ObjectReader objectReader =
                new ObjectMapper().readerFor(new TypeReference<List<JsonNode>>() {});
        return objectReader.readValue(evidenceNode);
    }

    private WebElement getParent(WebElement webElement) {
        return webElement.findElement(By.xpath("./.."));
    }

    private WebElement getLabel(WebElement webElement) {
        return webElement.findElement(By.tagName("label"));
    }

    private JsonNode getVCFromJson(String vc) throws JsonProcessingException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(result);
        return jsonNode.get(vc);
    }

    public void expiryAbsentFromVC(String exp) throws JsonProcessingException {
        assertNbfIsRecentAndExpiryIsNull();
    }

    public void assertJtiIsPresentAndNotNull() throws JsonProcessingException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(result);
        JsonNode jtiNode = jsonNode.get("jti");
        LOGGER.info("jti = " + jtiNode.asText());

        assertNotNull(jtiNode.asText());
    }

    private void assertNbfIsRecentAndExpiryIsNull() throws JsonProcessingException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(result);
        JsonNode nbfNode = jsonNode.get("nbf");
        JsonNode expNode = jsonNode.get("exp");
        String nbf = jsonNode.get("nbf").asText();
        LOGGER.info("nbf = " + nbfNode);
        LOGGER.info("exp = " + expNode);
        LocalDateTime nbfDateTime =
                LocalDateTime.ofEpochSecond(Long.parseLong(nbf), 0, ZoneOffset.UTC);

        assertNull(expNode);
        assertTrue(isWithinRange(nbfDateTime));
    }

    boolean isWithinRange(LocalDateTime testDate) {
        LocalDateTime nbfMin = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(30);
        LocalDateTime nbfMax = LocalDateTime.now(ZoneOffset.UTC).plusSeconds(30);
        LOGGER.info("nbfMin " + nbfMin);
        LOGGER.info("nbfMax " + nbfMax);
        LOGGER.info("nbf " + testDate);

        return testDate.isBefore(nbfMax) && testDate.isAfter(nbfMin);
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
