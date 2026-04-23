package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.TestDataCreator;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.pages.Headers.IPV_CORE_STUB;

public class CommonPageObject extends UniversalSteps {

    private static final Logger LOGGER = LoggerFactory.getLogger(CommonPageObject.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final ConfigurationService configurationService;

    private static final String STUB_VC_PAGE_TITLE = "IPV Core Stub Credential Result - GOV.UK";

    private static final String STUB_ERROR_PAGE_TITLE = "IPV Core Stub - GOV.UK";

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
    public WebElement jsonPayload;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details")
    public WebElement errorResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details/summary/span")
    public WebElement viewResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/form[2]/div/button")
    public WebElement searchButton;

    public CommonPageObject() {
        this.configurationService = new ConfigurationService(System.getenv("ENVIRONMENT"));
        PageFactory.initElements(Driver.get(), this);
        TestDataCreator.createDefaultResponses();
    }

    public void navigateToIPVCoreStub() {
        Driver.get().manage().deleteAllCookies();

        String coreStubUrl = configurationService.getCoreStubUrl(true);
        Driver.get().get(coreStubUrl);
        assertExpectedPage(IPV_CORE_STUB, false);
    }

    public void navigateToPassportCRIOnTestEnv() {
        BrowserUtils.clickAndWaitForNavigation(visitCredentialIssuers);
        String passportCRITestEnvironment = configurationService.getPassportCRITestEnvironment();
        LOGGER.info("passportCRITestEnvironment = {}", passportCRITestEnvironment);

        switch (passportCRITestEnvironment.toLowerCase()) {
            case "dev", "local" -> BrowserUtils.clickAndWaitForNavigation(passportCRIDev);
            case "build" -> BrowserUtils.clickAndWaitForNavigation(passportCRIBuild);
            case "staging" -> BrowserUtils.clickAndWaitForNavigation(passportCRIStaging);
            case "integration" -> BrowserUtils.clickAndWaitForNavigation(passportCRIIntegration);
            default -> LOGGER.info("No test environment is set");
        }
    }

    // Selects a UAT user row and clicks search, triggering a redirect chain
    // through to the passport credential issuer.
    public void searchForUATUser(String number) {
        assertURLContains(
                "credential-issuer?cri="
                        + "passport-v1-cri-"
                        + System.getenv("ENVIRONMENT").toLowerCase());
        selectRow.sendKeys(number);
        BrowserUtils.clickAndWaitForNavigation(searchButton);
        assertURLContains("details");
    }

    public void navigateToPassportResponse(String validOrInvalid) {
        assertURLContains(configurationService.getCoreStubEndpoint() + "/callback");

        if ("Invalid".equalsIgnoreCase(validOrInvalid)) {
            assertExpectedPage(STUB_ERROR_PAGE_TITLE, true);
            BrowserUtils.waitForVisibility(errorResponse, MAX_WAIT_SEC);
            errorResponse.click();
        } else {
            assertExpectedPage(STUB_VC_PAGE_TITLE, true);
            BrowserUtils.waitForVisibility(viewResponse, MAX_WAIT_SEC);
            viewResponse.click();
        }
    }

    public void jsonErrorResponse(String expectedErrorDescription, String expectedErrorStatusCode)
            throws JsonProcessingException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);

        JsonNode insideError = getJsonNode(result, "errorObject");
        LOGGER.info("insideError = {}", insideError);

        JsonNode errorDescription = insideError.get("description");
        JsonNode statusCode = insideError.get("httpstatusCode");
        String actualErrorDescription = insideError.get("description").asText();
        String actualStatusCode = insideError.get("httpstatusCode").asText();

        LOGGER.info("errorDescription = {}", errorDescription);
        LOGGER.info("statusCode = {}", statusCode);
        LOGGER.info("testErrorDescription = {}", expectedErrorDescription);
        LOGGER.info("testStatusCode = {}", expectedErrorStatusCode);

        Assert.assertEquals(expectedErrorDescription, actualErrorDescription);
        Assert.assertEquals(expectedErrorStatusCode, actualStatusCode);
    }

    public void checkScoreInStubIs(String validityScore, String strengthScore) throws IOException {
        scoreIs(validityScore, strengthScore, jsonPayload.getText());
    }

    public void scoreIs(String validityScore, String strengthScore, String jsonPayloadText)
            throws IOException {
        String result = jsonPayloadText;
        LOGGER.info("result = {}", result);
        JsonNode vcNode = getJsonNode(result, "vc");
        List<JsonNode> evidence = getListOfNodes(vcNode, "evidence");

        String evidenceValidityScore = evidence.getFirst().get("validityScore").asText();
        assertEquals(evidenceValidityScore, validityScore);

        String evidenceStrengthScore = evidence.getFirst().get("strengthScore").asText();
        assertEquals(evidenceStrengthScore, strengthScore);
    }

    // this method is not currently used, saved for reuse in future
    public void assertCheckDetailsWithinVc(String checkDetailsType, String passportCriVc)
            throws IOException {

        JsonNode vcNode = getJsonNode(passportCriVc, "vc");
        List<JsonNode> evidence = getListOfNodes(vcNode, "evidence");

        String checkDetails = null;
        if (checkDetailsType.equals("success")) {
            checkDetails = evidence.getFirst().get("checkDetails").toString();
        } else {
            checkDetails = evidence.getFirst().get("failedCheckDetails").toString();
        }
        assertEquals("[{\"checkMethod\":\"data\"}]", checkDetails);
    }

    public void ciInVC(String ci) throws IOException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);
        JsonNode vcNode = getJsonNode(result, "vc");
        JsonNode evidenceNode = vcNode.get("evidence");

        List<String> cis = getCIsFromEvidence(evidenceNode);

        if (StringUtils.isNotEmpty(ci)) {
            if (!cis.isEmpty()) {
                LOGGER.info("HELP {}    {}", Arrays.toString(cis.toArray()), ci);
                assertTrue(cis.contains(ci));
            } else {
                fail("No CIs found");
            }
        }
    }

    public void assertDocumentNumberInVc(String documentNumber) throws IOException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);
        JsonNode vcNode = getJsonNode(result, "vc");
        String passportNumber = getDocumentNumberFromVc(vcNode);
        assertEquals(documentNumber, passportNumber);
    }

    private List<String> getCIsFromEvidence(JsonNode evidenceNode) throws IOException {
        ObjectReader objectReader = OBJECT_MAPPER.readerFor(new TypeReference<List<JsonNode>>() {});
        List<JsonNode> evidence = objectReader.readValue(evidenceNode);

        return getListOfNodes(evidence.getFirst(), "ci").stream().map(JsonNode::asText).toList();
    }

    private JsonNode getJsonNode(String result, String vc) throws JsonProcessingException {
        JsonNode jsonNode = OBJECT_MAPPER.readTree(result);
        return jsonNode.get(vc);
    }

    private String getDocumentNumberFromVc(JsonNode vcNode) throws IOException {
        JsonNode credentialSubject = vcNode.findValue("credentialSubject");
        List<JsonNode> evidence = getListOfNodes(credentialSubject, "passport");

        return evidence.getFirst().get("documentNumber").asText();
    }

    private List<JsonNode> getListOfNodes(JsonNode vcNode, String evidence) throws IOException {
        JsonNode evidenceNode = vcNode.get(evidence);

        ObjectReader objectReader = OBJECT_MAPPER.readerFor(new TypeReference<List<JsonNode>>() {});
        return objectReader.readValue(evidenceNode);
    }

    private JsonNode getVCFromJson(String vc) throws JsonProcessingException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);
        JsonNode jsonNode = OBJECT_MAPPER.readTree(result);
        return jsonNode.get(vc);
    }

    public void expiryAbsentFromVC(String exp) throws JsonProcessingException {
        assertNbfIsRecentAndExpiryIsNull();
    }

    public void assertJtiIsPresentAndNotNull() throws JsonProcessingException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);
        JsonNode jsonNode = OBJECT_MAPPER.readTree(result);
        JsonNode jtiNode = jsonNode.get("jti");
        LOGGER.info("jti = {}", jtiNode.asText());

        assertNotNull(jtiNode.asText());
    }

    private void assertNbfIsRecentAndExpiryIsNull() throws JsonProcessingException {
        String result = jsonPayload.getText();
        LOGGER.info("result = {}", result);
        JsonNode jsonNode = OBJECT_MAPPER.readTree(result);
        JsonNode nbfNode = jsonNode.get("nbf");
        JsonNode expNode = jsonNode.get("exp");
        String nbf = jsonNode.get("nbf").asText();
        LOGGER.info("nbf = {}", nbfNode);
        LOGGER.info("exp = {}", expNode);
        LocalDateTime nbfDateTime =
                LocalDateTime.ofEpochSecond(Long.parseLong(nbf), 0, ZoneOffset.UTC);

        assertNull(expNode);
        assertTrue(isWithinRange(nbfDateTime));
    }

    boolean isWithinRange(LocalDateTime testDate) {
        LocalDateTime nbfMin = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(30);
        LocalDateTime nbfMax = LocalDateTime.now(ZoneOffset.UTC).plusSeconds(30);
        LOGGER.info("nbfMin {}", nbfMin);
        LOGGER.info("nbfMax {}", nbfMax);
        LOGGER.info("nbf {}", testDate);

        return testDate.isBefore(nbfMax) && testDate.isAfter(nbfMin);
    }
}
