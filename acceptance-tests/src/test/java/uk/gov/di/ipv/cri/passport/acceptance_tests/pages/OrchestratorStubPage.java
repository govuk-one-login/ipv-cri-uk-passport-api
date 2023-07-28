package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import io.cucumber.java.en.Then;
import net.minidev.json.JSONObject;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.IPV_PageObjectSupport;

import java.io.IOException;

public class OrchestratorStubPage {

    private static final String USER_DATA_DIRECTORY = "src/test/resources/Data/";

    public OrchestratorStubPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//input[@value='Debug route']")
    public WebElement DebugRoute;

    @FindBy(xpath = "//*[@id='cri-link-ukPassport']")
    public WebElement UkPassport;

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


    public void clickOnFullJourneyRouteButton() {
        fullJourneyRouteButton.click();
    }

    public void clickBrowserButton() {
        Driver.get().navigate().back();
    }

    public void userIsOnPassportcris(String page, String expectedText) {
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
        Assert.assertTrue(
                expectedText,
                header.getText().contains("User information"));

    }
}
