package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.Address;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class OrchestratorStubPage extends UniversalSteps {

    public OrchestratorStubPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//input[@value='Debug route']")
    public WebElement DebugRoute;

    @FindBy(xpath = "//*[@value=\"Full journey route\"]")
    public WebElement fullJourneyRouteButton;

    @FindBy(id = "submitButton")
    public WebElement continueSubmitButton;

    @FindBy(id = "addressSearch")
    public WebElement postcodeField;

    @FindBy(id = "continue")
    public WebElement continueButton;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div[1]/h1")
    public WebElement header;

    @FindBy(id = "addressResults")
    public WebElement ChooseYourAddressFromTheList;

    @FindBy(id = "addressYearFrom")
    public WebElement EnterTheYearYouStartedLivingAtThisAddress;

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement IConfirmMyDetailsAreCorrect;

    @FindBy(id = "Q00033-TSBBANKPLC-label")
    public WebElement loanTSBBANKPLC;

    @FindBy(id = "Q00033-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement loanNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00018-OVER500UPTO600-label")
    public WebElement OVER500UPTO600;

    @FindBy(id = "Q00018-UPTO600-label")
    public WebElement UPTO600;

    @FindBy(id = "Q00009-SANTANDERANMFMORTGAGE-label")
    public WebElement SANTANDERANMFMORTGAGE;

    @FindBy(id = "Q00009-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement mortgageCompanyNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00002-2002-label")
    public WebElement Year2002;

    @FindBy(id = "Q00002-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement currentAddressNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00043-UPTO48MONTHS-label")
    public WebElement UPTO48MONTHS;

    @FindBy(xpath = "//*[@id=\"Q00043-OVER36MONTHSUPTO48MONTHS-label\"]")
    public WebElement OVER36MONTHSUPTO48MONTHS;

    @FindBy(id = "Q00042-OVER550UPTO600-label")
    public WebElement OVER550UPTO600;

    @FindBy(id = "Q00042-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement loanMonthlyNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00015-UPTO60000-label")
    public WebElement UPTO60000;

    @FindBy(id = "Q00015-OVER35000UPTO60000-label")
    public WebElement OVER35000UPTO60000;

    @FindBy(id = "Q00015-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement mortgageLeftToPayNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00039-UPTO6750-label")
    public WebElement UPTO6750;

    @FindBy(id = "Q00039-OVER6500UPTO6750-label")
    public WebElement OVER6500UPTO6750;

    @FindBy(xpath = "//label[@id='Q00019-KA-label']")
    public WebElement KA;

    @FindBy(id = "Q00048-TSBBANKPLC-label")
    public WebElement TSBBANKPLC;

    @FindBy(id = "Q00048-NONEOFTHEABOVEDOESNOTAPPLY-label")
    public WebElement currentAccountNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "Q00020-021963-label")
    public WebElement February1963;

    @FindBy(xpath = "//label[@id='Q00020-NONEOFTHEABOVEDOESNOTAPPLY-label']")
    public WebElement dobNONEOFTHEABOVEDOESNOTAPPLY;

    @FindBy(id = "targetEnvironment")
    public WebElement ChooseYourEnvironmentFromTheList;

    @FindBy(id = "journey")
    public WebElement proveYourIdRadioBtn;

    public void clickOnFullJourneyRouteButton() {
        fullJourneyRouteButton.click();
    }

    public void clickBrowserButton() {
        Driver.get().navigate().back();
    }

    public void userIsOnPageWithHeading(String page, String expectedText) {
        Assert.assertEquals(expectedText, new PassportPageObject().pageHeader.getText());
    }

    public void addPostcode(String housename) {
        postcodeField.sendKeys(housename);
        continueButton.click();
    }

    public void CheckingYourDetailsPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void validateUserInformationTitle(String expectedText) {
        Assert.assertTrue(expectedText, header.getText().contains("User information"));
    }

    public void selectAddressFromDropdown(String address) {
        Select select = new Select(ChooseYourAddressFromTheList);
        select.selectByValue(address);
        continueButton.click();
        BrowserUtils.waitForPageToLoad(100);
    }

    public void enterAddressExpiry(String expiryDate) {
        EnterTheYearYouStartedLivingAtThisAddress.sendKeys(expiryDate);
        continueButton.click();
        BrowserUtils.waitForPageToLoad(100);
    }

    public void confirmClick() {
        IConfirmMyDetailsAreCorrect.click();
    }

    public void clickContinue() {
        continueButton.isEnabled();
        continueButton.click();
    }

    public void answerKBVQuestion() {
        BrowserUtils.waitFor(2);
        String kennethFirstQuestion = Driver.get().getTitle();
        kennethFirstQuestion.trim();
        System.out.println("kennethFirstQuestion = " + kennethFirstQuestion);
        switch (kennethFirstQuestion) {
            case "Which provider did you take out a loan with? – Prove your identity – GOV.UK":
                try {
                    if (loanTSBBANKPLC.isDisplayed()) {
                        loanTSBBANKPLC.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (loanNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        loanNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            case "What is the outstanding balance of your current mortgage? – Prove your identity – GOV.UK":
                try {
                    if (OVER35000UPTO60000.isDisplayed()) {
                        OVER35000UPTO60000.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (mortgageLeftToPayNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        mortgageLeftToPayNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            case "How much is your monthly mortgage payment? – Prove your identity – GOV.UK":
                try {
                    if (OVER500UPTO600.isDisplayed()) {
                        OVER500UPTO600.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (UPTO600.isDisplayed()) {
                        UPTO600.click();
                        continueButton.click();
                    }
                }
                break;
            case "Which lender did you borrow your mortgage from? – Prove your identity – GOV.UK":
                try {
                    if (SANTANDERANMFMORTGAGE.isDisplayed()) {
                        SANTANDERANMFMORTGAGE.click();
                        continueButton.click();
                        BrowserUtils.waitForPageToLoad(100);
                    }
                } catch (Exception e) {
                    if (mortgageCompanyNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        mortgageCompanyNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                        BrowserUtils.waitForPageToLoad(100);
                    }
                }
                break;
            case "In which year did you move to your current address? – Prove your identity – GOV.UK":
                try {
                    if (Year2002.isDisplayed()) {
                        Year2002.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (currentAddressNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        currentAddressNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            case "How long do you have to pay back your loan? – Prove your identity – GOV.UK":
                BrowserUtils.waitFor(2);
                try {
                    if (OVER36MONTHSUPTO48MONTHS.isDisplayed()) {
                        OVER36MONTHSUPTO48MONTHS.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (UPTO48MONTHS.isDisplayed()) {
                        UPTO48MONTHS.click();
                        continueButton.click();
                    }
                }
                break;
            case "How much of your loan do you pay back every month? – Prove your identity – GOV.UK":
                try {
                    if (OVER550UPTO600.isDisplayed()) {
                        OVER550UPTO600.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (loanMonthlyNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        loanMonthlyNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            case "How much do you have left to pay on your mortgage? – Prove your identity – GOV.UK":
                try {
                    if (UPTO60000.isDisplayed()) {
                        UPTO60000.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (OVER35000UPTO60000.isDisplayed()) {
                        OVER35000UPTO60000.click();
                        continueButton.click();
                    }
                }
                break;
            case "How much of your loan do you have left to pay back? – Prove your identity – GOV.UK":
                try {
                    if (UPTO6750.isDisplayed()) {
                        UPTO6750.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (OVER6500UPTO6750.isDisplayed()) {
                        OVER6500UPTO6750.click();
                        continueButton.click();
                    }
                }
                break;
            case "What are the first 2 letters of the first name of the other person on your mortgage? – Prove your identity – GOV.UK":
                KA.click();
                continueButton.click();
                break;
            case "Who have you opened a current account with? – Prove your identity – GOV.UK":
                try {
                    if (TSBBANKPLC.isDisplayed()) {
                        TSBBANKPLC.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (currentAccountNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        currentAccountNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            case "When was the other person on your mortgage born? – Prove your identity – GOV.UK":
                try {
                    if (February1963.isDisplayed()) {
                        February1963.click();
                        continueButton.click();
                    }
                } catch (Exception e) {
                    if (dobNONEOFTHEABOVEDOESNOTAPPLY.isDisplayed()) {
                        dobNONEOFTHEABOVEDOESNOTAPPLY.click();
                        continueButton.click();
                    }
                }
                break;
            default:
                System.out.println("First question not answered");
        }
    }

    public void validateAddressVc(String currentAddress) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Map<String, String>> vcMap = getVcMap(objectMapper);
        Map<String, String> addressVc =
                vcMap.get("Cri Type: https://review-a.staging.account.gov.uk");

        List<Address> addressList = getAddresses(objectMapper, addressVc);

        LocalDate validFrom = null;
        LocalDate validUntil = null;

        for (Address address : addressList) {
            if (address.getAddressType().name().equals("CURRENT")) {
                validFrom = address.getValidFrom();
            } else {
                validUntil = address.getValidUntil();
            }
        }

        if (null != validFrom && addressList.size() > 1) {
            assertEquals(validFrom, validUntil);
        }

        for (Address address : addressList) {
            if (currentAddress.contains(address.getPostalCode())) {
                assertEquals("CURRENT", address.getAddressType().name());
            } else {
                assertEquals("PREVIOUS", address.getAddressType().name());
            }
        }
    }

    public void validateFraudVc() throws JsonProcessingException {

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Map<String, String>> vcMap = getVcMap(objectMapper);
        Map<String, String> fraudVc =
                vcMap.get("Cri Type: https://review-f.staging.account.gov.uk");

        List<Address> addressList = getAddresses(objectMapper, fraudVc);
        if (addressList.size() > 1) {
            assertEquals(2, addressList.size());
        } else {
            assertEquals(1, addressList.size());
        }
    }

    private List<Address> getAddresses(ObjectMapper objectMapper, Map<String, String> fraudVc)
            throws JsonProcessingException {
        TypeReference<HashMap<String, Object>> typeRef =
                new TypeReference<HashMap<String, Object>>() {};

        TypeReference<List<Address>> addressListRef = new TypeReference<>() {};
        String vcString = objectMapper.writeValueAsString(fraudVc.get("vc"));

        Map<String, Object> vc = objectMapper.readValue(vcString, typeRef);
        Map<String, Object> credentialSubject = (Map) vc.get("credentialSubject");

        List<Address> addressList = (List<Address>) credentialSubject.get("address");
        addressList =
                objectMapper
                        .registerModule(new JavaTimeModule())
                        .convertValue(addressList, addressListRef);
        return addressList;
    }

    private Map<String, Map<String, String>> getVcMap(ObjectMapper objectMapper)
            throws JsonProcessingException {
        Map<String, Map<String, String>> vcMap = new HashMap<>();
        List<WebElement> elements =
                Driver.get().findElements(By.className("govuk-summary-list__row"));
        for (WebElement element : elements) {
            String key =
                    element.findElement(By.tagName("dt")).findElement(By.tagName("span")).getText();
            String stringValue =
                    element.findElement(By.tagName("dd"))
                            .findElement(By.tagName("details"))
                            .findElement(By.tagName("div"))
                            .findElement(By.tagName("pre"))
                            .findElement(By.tagName("code"))
                            .getAttribute("innerHTML");
            Map<String, String> vc = objectMapper.readValue(stringValue, Map.class);
            vcMap.put(key, vc);
        }
        return vcMap;
    }

    public void selectTargetEnvironmentFromDropdown(String environment) {
        Select select = new Select(ChooseYourEnvironmentFromTheList);
        select.selectByValue(environment);
    }

    public void clickContinueToProveYourIdRadioBtn() {
        proveYourIdRadioBtn.click();
        continueSubmitButton.click();
    }
}
