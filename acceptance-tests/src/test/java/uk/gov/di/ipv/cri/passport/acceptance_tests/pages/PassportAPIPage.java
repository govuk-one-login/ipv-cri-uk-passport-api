package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.AuthorisationResponse;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.CheckPassportSuccessResponse;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.PassportFormData;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class PassportAPIPage extends PassportPageObject {

    private static String CLIENT_ID;
    private static String SESSION_REQUEST_BODY;
    private static String SESSION_ID;
    private static String STATE;
    private static String AUTHCODE;
    private static String ACCESS_TOKEN;
    private static String vcHeader;
    private static String vcBody;
    private static final String KID_PREFIX = "did:web:review-p.dev.account.gov.uk#";
    private static String RETRY;
    private static String extractedKeyValues;
    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));
    private static final Logger LOGGER = LogManager.getLogger();

    public String getAuthorisationJwtFromStub(String criId, int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        if (coreStubUrl == null) {
            throw new IllegalArgumentException("Environment variable IPV_CORE_STUB_URL is not set");
        }
        return getClaimsForUser(coreStubUrl, criId, userDataRowNumber);
    }

    public void userIdentityAsJwtString(String criId, int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String jsonString = getAuthorisationJwtFromStub(criId, userDataRowNumber);
        LOGGER.info("jsonString = " + jsonString);
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        SESSION_REQUEST_BODY = createRequest(coreStubUrl, criId, jsonString);
        LOGGER.info("SESSION_REQUEST_BODY = " + SESSION_REQUEST_BODY);

        // Capture client id for using later in the auth request
        Map<String, String> deserialisedSessionResponse =
                objectMapper.readValue(SESSION_REQUEST_BODY, new TypeReference<>() {});
        CLIENT_ID = deserialisedSessionResponse.get("client_id");
        LOGGER.info("CLIENT_ID = {}", CLIENT_ID);
    }

    public void getRequestToJwksEndpoint() throws IOException, InterruptedException {
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        LOGGER.info("getPublicAPIEndpoint() ==> {}", publicApiGatewayUrl);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/.well-known/jwks.json"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .GET()
                        .build();
        String wellKnownJWKSResponse = sendHttpRequest(request).body();
        LOGGER.info("wellKnownJWKSResponse = {}", wellKnownJWKSResponse);

        try {
            JsonNode rootNode = objectMapper.readTree(wellKnownJWKSResponse);
            JsonNode keysNode = rootNode.path("keys").get(0);

            // Assertions for each key-value pair
            Assertions.assertTrue(keysNode.has("kty"), "kty field is missing");
            Assertions.assertEquals("RSA", keysNode.path("kty").asText(), "kty value is incorrect");
            Assertions.assertTrue(keysNode.has("n"), "n field is missing");
            Assertions.assertTrue(keysNode.has("e"), "e field is missing");
            Assertions.assertEquals("AQAB", keysNode.path("e").asText(), "e value is incorrect");
            Assertions.assertTrue(keysNode.has("use"), "use field is missing");
            Assertions.assertEquals("enc", keysNode.path("use").asText(), "use value is incorrect");
            Assertions.assertTrue(keysNode.has("kid"), "kid field is missing");
            Assertions.assertTrue(keysNode.has("alg"), "alg field is missing");
            Assertions.assertEquals(
                    "RSA_OAEP_256", keysNode.path("alg").asText(), "alg value is incorrect");

        } catch (IOException e) {
            LOGGER.error("Error parsing JSON response: {}", e.getMessage());
            // Handle the exception appropriately, e.g., throw a custom exception or fail the test
            Assertions.fail("Error parsing JSON response: " + e.getMessage()); // Fail the test
        } catch (NullPointerException e) {
            LOGGER.error("Error accessing JSON node: {}", e.getMessage());
            Assertions.fail("Error accessing JSON node: " + e.getMessage()); // Fail the test
        }
    }

    public void userIdentityAsJwtStringForupdatedUser(
            String givenName, String familyName, String criId, int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String jsonString = getAuthorisationJwtFromStub(criId, userDataRowNumber);
        LOGGER.info("jsonString = " + jsonString);
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        JsonNode jsonNode = objectMapper.readTree((jsonString));
        JsonNode nameArray = jsonNode.get("shared_claims").get("name");
        JsonNode firstItemInNameArray = nameArray.get(0);
        JsonNode namePartsNode = firstItemInNameArray.get("nameParts");
        JsonNode firstItemInNamePartsArray = namePartsNode.get(0);
        ((ObjectNode) firstItemInNamePartsArray).put("value", givenName);
        JsonNode secondItemInNamePartsArray = namePartsNode.get(1);
        ((ObjectNode) secondItemInNamePartsArray).put("value", familyName);
        String updatedJsonString = jsonNode.toString();
        LOGGER.info("updatedJsonString = " + updatedJsonString);
        SESSION_REQUEST_BODY = createRequest(coreStubUrl, criId, updatedJsonString);
        LOGGER.info("SESSION_REQUEST_BODY = " + SESSION_REQUEST_BODY);
    }

    public void postRequestToSessionEndpoint() throws IOException, InterruptedException {
        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        LOGGER.info("getPrivateAPIEndpoint() ==> " + privateApiGatewayUrl);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(privateApiGatewayUrl + "/session"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("X-Forwarded-For", "123456789")
                        .POST(HttpRequest.BodyPublishers.ofString(SESSION_REQUEST_BODY))
                        .build();
        String sessionResponse = sendHttpRequest(request).body();
        LOGGER.info("sessionResponse = " + sessionResponse);
        Map<String, String> deserialisedResponse =
                objectMapper.readValue(sessionResponse, new TypeReference<>() {});
        SESSION_ID = deserialisedResponse.get("session_id");
        STATE = deserialisedResponse.get("state");
    }

    public void getSessionIdForPassport() {
        LOGGER.info("SESSION_ID = " + SESSION_ID);
        assertTrue(StringUtils.isNotBlank(SESSION_ID));
    }

    public void postRequestToPassportEndpoint(String passportJsonRequestBody)
            throws IOException, InterruptedException, NoSuchFieldException, IllegalAccessException {
        postRequestToPassportEndpoint(passportJsonRequestBody, "");
    }

    public void postRequestToPassportEndpoint(
            String passportJsonRequestBody, String jsonEditsString)
            throws IOException, InterruptedException, NoSuchFieldException, IllegalAccessException {
        Map<String, String> jsonEdits = new HashMap<>();
        if (!StringUtils.isEmpty(jsonEditsString)) {
            jsonEdits = objectMapper.readValue(jsonEditsString, Map.class);
        }

        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        PassportFormData passportJson =
                objectMapper.readValue(
                        new File("src/test/resources/Data/" + passportJsonRequestBody + ".json"),
                        PassportFormData.class);

        for (Map.Entry<String, String> entry : jsonEdits.entrySet()) {
            Field field = passportJson.getClass().getDeclaredField(entry.getKey());
            field.setAccessible(true);

            field.set(passportJson, entry.getValue());
        }
        String passportInputJsonString = objectMapper.writeValueAsString(passportJson);

        HttpRequest.Builder builder = HttpRequest.newBuilder();
        builder.uri(URI.create(privateApiGatewayUrl + "/check-passport"))
                .setHeader("Accept", "application/json")
                .setHeader("Content-Type", "application/json")
                .setHeader("session_id", SESSION_ID)
                .POST(HttpRequest.BodyPublishers.ofString(passportInputJsonString));
        HttpRequest request = builder.build();
        LOGGER.info("passport RequestBody = " + passportInputJsonString);
        String passportCheckResponse = sendHttpRequest(request).body();

        LOGGER.info("passportCheckResponse = " + passportCheckResponse);

        try {
            CheckPassportSuccessResponse checkPassportSuccessResponse =
                    objectMapper.readValue(
                            passportCheckResponse, CheckPassportSuccessResponse.class);

            STATE = checkPassportSuccessResponse.getState();
            SESSION_ID = checkPassportSuccessResponse.getPassportSessionId();

            LOGGER.info("Found a CheckPassportSuccessResponse");

        } catch (JsonMappingException e) {
            LOGGER.info("Not a CheckPassportSuccessResponse");

            RETRY = passportCheckResponse;
            LOGGER.info("RETRY = {}", RETRY);
        }
    }

    public void postRequestToPassportEndpointWithInvalidSessionId(
            String invalidHeaderValue, String passportJsonRequestBody)
            throws IOException, InterruptedException, NoSuchFieldException, IllegalAccessException {
        postRequestToPassportEndpointWithInvalidSessionId(
                invalidHeaderValue, passportJsonRequestBody, "");
    }

    public void postRequestToPassportEndpointWithInvalidSessionId(
            String invalidHeaderValue, String passportJsonRequestBody, String jsonEditsString)
            throws IOException, InterruptedException, NoSuchFieldException, IllegalAccessException {
        Map<String, String> jsonEdits = new HashMap<>();
        if (!StringUtils.isEmpty(jsonEditsString)) {
            jsonEdits = objectMapper.readValue(jsonEditsString, Map.class);
        }

        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        PassportFormData passportJson =
                objectMapper.readValue(
                        new File("src/test/resources/Data/" + passportJsonRequestBody + ".json"),
                        PassportFormData.class);

        for (Map.Entry<String, String> entry : jsonEdits.entrySet()) {
            Field field = passportJson.getClass().getDeclaredField(entry.getKey());
            field.setAccessible(true);

            field.set(passportJson, entry.getValue());
        }
        String passportInputJsonString = objectMapper.writeValueAsString(passportJson);

        HttpRequest.Builder builder = HttpRequest.newBuilder();
        builder.uri(URI.create(privateApiGatewayUrl + "/check-passport"))
                .setHeader("Accept", "application/json")
                .setHeader("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(passportInputJsonString));

        switch (invalidHeaderValue) {
            case "mismatchSessionId" -> builder.setHeader(
                    "session_id", UUID.randomUUID().toString());
            case "malformedSessionId" -> builder.setHeader("session_id", "&%^$£$%");
            case "missingSessionId" -> builder.setHeader("session_id", "");
            default -> {
                /*Do Nothing - No Header Provided*/
            }
        }

        HttpRequest request = builder.build();
        LOGGER.info("passport RequestBody = {}, {}", passportInputJsonString, request.headers());
        String passportCheckResponse = sendHttpRequest(request).body();

        LOGGER.info("passportCheckResponse = {}", passportCheckResponse);

        String expectedResponseForInvalidSessionId =
                "{\"oauth_error\":{\"error_description\":\"Session not found\",\"error\":\"access_denied\"}}";
        assertEquals(expectedResponseForInvalidSessionId, passportCheckResponse);

        try {
            CheckPassportSuccessResponse checkPassportSuccessResponse =
                    objectMapper.readValue(
                            passportCheckResponse, CheckPassportSuccessResponse.class);

            STATE = checkPassportSuccessResponse.getState();
            SESSION_ID = checkPassportSuccessResponse.getPassportSessionId();

            LOGGER.info("Found a CheckPassportSuccessResponse");

        } catch (JsonMappingException e) {
            LOGGER.info("Not a CheckPassportSuccessResponse");

            RETRY = passportCheckResponse;
            LOGGER.info("RETRY = " + RETRY);
        }
    }

    public void retryValueInPassportCheckResponse(Boolean retry) {
        if (!(retry && RETRY.equals("{\"result\":\"retry\"}"))) {
            fail("Should have retried");
        }
    }

    public void getAuthorisationCode() throws IOException, InterruptedException {
        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        String coreStubUrl = configurationService.getCoreStubUrl(false);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        privateApiGatewayUrl
                                                + "/authorization?redirect_uri="
                                                + coreStubUrl
                                                + "/callback&state="
                                                + STATE
                                                + "&scope=openid&response_type=code&client_id="
                                                + CLIENT_ID))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("session-id", SESSION_ID)
                        .GET()
                        .build();
        String authCallResponse = sendHttpRequest(request).body();
        LOGGER.info("authCallResponse = " + authCallResponse);
        AuthorisationResponse deserialisedResponse =
                objectMapper.readValue(authCallResponse, AuthorisationResponse.class);
        if (null != deserialisedResponse.getAuthorizationCode()) {
            AUTHCODE = deserialisedResponse.getAuthorizationCode().getValue();
            LOGGER.info("authorizationCode = " + AUTHCODE);
        }
    }

    public void postRequestToAccessTokenEndpoint(String criId)
            throws IOException, InterruptedException {
        String accessTokenRequestBody = getAccessTokenRequest(criId);
        LOGGER.info("Access Token Request Body = " + accessTokenRequestBody);
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        LOGGER.info("getPublicAPIEndpoint() ==> " + publicApiGatewayUrl);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/token"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(accessTokenRequestBody))
                        .build();
        String accessTokenPostCallResponse = sendHttpRequest(request).body();
        LOGGER.info("accessTokenPostCallResponse = " + accessTokenPostCallResponse);
        Map<String, String> deserialisedResponse =
                objectMapper.readValue(accessTokenPostCallResponse, new TypeReference<>() {});
        ACCESS_TOKEN = deserialisedResponse.get("access_token");
    }

    public void postRequestToPublicApiEndpointWithoutApiKey(String endpoint)
            throws IOException, InterruptedException {
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        LOGGER.info("getPublicAPIEndpoint() ==> " + publicApiGatewayUrl);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + endpoint))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build();
        String publicAPIGatewayEndpointPostResponse = sendHttpRequest(request).body();
        LOGGER.info(
                "publicAPIGatewayEndpointPostResponse = " + publicAPIGatewayEndpointPostResponse);
        try {
            ObjectMapper objectMapper =
                    new ObjectMapper(); // Assuming you have ObjectMapper defined elsewhere
            JsonNode rootNode = objectMapper.readTree(publicAPIGatewayEndpointPostResponse);

            // Assertion for the expected error message
            Assertions.assertEquals(
                    "Forbidden",
                    rootNode.path("message").asText(),
                    "Unexpected error message received");

        } catch (IOException e) {
            LOGGER.error("Error parsing JSON response: {}", e.getMessage());
            Assertions.fail(
                    "Error parsing JSON response: "
                            + e.getMessage()); // Fail the test if parsing fails
        } catch (NullPointerException e) {
            LOGGER.error("Error accessing JSON node: {}", e.getMessage());
            Assertions.fail(
                    "Error accessing JSON node: "
                            + e.getMessage()); // Fail the test if node is missing
        }
    }

    public void postRequestToPassportVCEndpoint()
            throws IOException, InterruptedException, ParseException {
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/credential/issue"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("Authorization", "Bearer " + ACCESS_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build();
        String requestPassportVCResponse = sendHttpRequest(request).body();
        LOGGER.info("requestPassportVCResponse = " + requestPassportVCResponse);
        SignedJWT signedJWT = SignedJWT.parse(requestPassportVCResponse);

        vcHeader = signedJWT.getHeader().toString();
        LOGGER.info("VC Header = {}", vcHeader);

        vcBody = signedJWT.getJWTClaimsSet().toString();
        LOGGER.info("VC Body = {}", vcBody);

        JSONObject jsonHeader;
        try {
            jsonHeader = new JSONObject(vcHeader);
        } catch (Exception e) {
            LOGGER.error("Failed to parse VC Header as JSON", e);
            throw new AssertionError("Failed to parse VC Header as JSON", e);
        }
        String[] expectedFields = {"kid", "typ", "alg"};
        for (String field : expectedFields) {
            Assert.assertTrue(
                    "Field '" + field + "' is missing in the VC Header", jsonHeader.has(field));
        }
        Assert.assertEquals(
                "The 'typ' field does not have the expected value",
                "JWT",
                jsonHeader.getString("typ"));
        Assert.assertEquals(
                "The 'alg' field does not have the expected value",
                "ES256",
                jsonHeader.getString("alg"));
        String kid = jsonHeader.getString("kid");
        Assert.assertTrue(
                "The 'kid' field does not start with the expected prefix",
                kid.startsWith(KID_PREFIX));
        String kidSuffix = kid.substring(KID_PREFIX.length());
        Assert.assertFalse("The 'kid' field suffix should not be empty", kidSuffix.isEmpty());
    }

    public void postRequestToPassportVCEndpointWithInvalidAuthCode()
            throws IOException, InterruptedException {
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        String randomAccessToken = UUID.randomUUID().toString();
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/credential/issue"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("Authorization", "Bearer " + randomAccessToken)
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build();
        String requestPassportVCResponse = sendHttpRequest(request).body();
        LOGGER.info("requestPassportVCResponse = {}", requestPassportVCResponse);

        String expectedResponseForInvalidAuthCode =
                "{\"oauth_error\":{\"error_description\":\"Access denied by resource owner or authorization server\",\"error\":\"access_denied\"}}";
        assertEquals(expectedResponseForInvalidAuthCode, requestPassportVCResponse);
    }

    public void validityScoreAndStrengthScoreInVC(String validityScore, String strengthScore)
            throws IOException, InterruptedException, ParseException {
        scoreIs(validityScore, strengthScore, vcBody);
    }

    public void assertJtiIsPresent() throws IOException, ParseException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(vcBody);
        JsonNode jtiNode = jsonNode.get("jti");
        LOGGER.info("jti = " + jtiNode.asText());

        assertNotNull(jtiNode.asText());
    }

    public void assertVCEvidence(int scenario) throws IOException, NoSuchAlgorithmException {

        int expectedArrayIndex = scenario - 1;

        String emptyArrayHash = "T1PNoYwrqgwDVLtfmj7L5e0Sq02OEbqHPC8RFhICuUU=";
        String nullElementHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

        String[] ciArrayHashes = {
            emptyArrayHash,
            "NE4izyyWEjSKpbBTxHVuF0gqrxibXsfkQvq3wiwI8Rc=",
            "zvdG3b6B15wfoPIFcbk2yPsSp870Ww6BN0KblxFP8o4=",
            "zvdG3b6B15wfoPIFcbk2yPsSp870Ww6BN0KblxFP8o4="
        };
        String[] checkDetailsArrayHashes = {
            "OJ1A8Y8ptgNc9fuYBA3/50F6wrHw3FqA65fIV6vN++I=",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            "ErM5+OmTfHBYo0CNuh2FHI+nXlLk1xFl6TVDskSoBjw=",
            "/gtEhinua5O3bdqX+67vzKBTC02esLnGffHeUeTm9JY="
        };
        String[] failedCheckDetailsArrayHashes = {
            nullElementHash,
            "/gtEhinua5O3bdqX+67vzKBTC02esLnGffHeUeTm9JY=",
            "zJjJilDg2lowm2PZjj43zqpI3TC82pnvej/mxIoJlQc=",
            "99nsWNFMJ4QdCEYGInK/4hTcemYr/6Hf3RYuZFRsRZI="
        };
        String[] ciReasonsArrayHashes = {
            emptyArrayHash,
            "zwv2uJ/HkFXEvlgie/5MX+KKTztBBsqtq5cP9zrf39Y=",
            "ECbhSFWj61a98BYpqXRj3k4HjJrMsGkD08TSJMCLjwA=",
            "Cdf9YoboXyJxqCKvcAgqxvq+r4TCMt2Qh7WtgLWqr8k="
        };

        JsonNode vcRootNode = objectMapper.readTree((vcBody));

        // Only the first evidence item
        JsonNode evidenceArrayFirst = vcRootNode.get("vc").get("evidence").get(0);
        LOGGER.debug("asserting VC Evidence = " + evidenceArrayFirst.toPrettyString());

        // Contra Indicators
        JsonNode ciArray = evidenceArrayFirst.get("ci");
        LOGGER.debug("ciArray = " + ciArray);
        String ciArrayFoundHash = createBase64Sha254HashOfNode(ciArray);
        LOGGER.debug("ciArrayFoundHash = " + ciArrayFoundHash);
        assertTrue(compareHashes(ciArrayHashes[expectedArrayIndex], ciArrayFoundHash));

        // Check Details
        JsonNode checkDetailsArray = evidenceArrayFirst.get("checkDetails");
        LOGGER.debug("checkDetailsArray = " + checkDetailsArray);
        String checkDetailsArrayFoundHash = createBase64Sha254HashOfNode(checkDetailsArray);
        LOGGER.debug("checkDetailsArrayFoundHash = " + checkDetailsArrayFoundHash);
        assertTrue(
                compareHashes(
                        checkDetailsArrayHashes[expectedArrayIndex], checkDetailsArrayFoundHash));

        // Failed Check Details
        JsonNode failedCheckDetailsArray = evidenceArrayFirst.get("failedCheckDetails");
        LOGGER.debug("failedCheckDetailsArray = " + failedCheckDetailsArray);
        String failedCheckDetailsArrayFoundHash =
                createBase64Sha254HashOfNode(failedCheckDetailsArray);
        LOGGER.debug("failedCheckDetailsArrayFoundHash = " + failedCheckDetailsArrayFoundHash);
        assertTrue(
                compareHashes(
                        failedCheckDetailsArrayHashes[expectedArrayIndex],
                        failedCheckDetailsArrayFoundHash));

        // CI Reasons
        JsonNode ciReasonsArray = evidenceArrayFirst.get("ciReasons");
        LOGGER.debug("ciReasons = " + ciReasonsArray);
        String ciReasonsFoundHash = createBase64Sha254HashOfNode(ciReasonsArray);
        LOGGER.debug("ciReasonsFoundHash = " + ciReasonsFoundHash);
        assertTrue(compareHashes(ciReasonsArrayHashes[expectedArrayIndex], ciReasonsFoundHash));
    }

    private boolean compareHashes(String expectedSha265Bash64Hash, String foundSha265Bash64Hash) {

        boolean match = expectedSha265Bash64Hash.equals(foundSha265Bash64Hash);

        Level level = Level.INFO;

        if (!match) {
            level = Level.ERROR;
        }

        LOGGER.log(
                level,
                "Hash match is "
                        + match
                        + ", Comparing Expected Hash : "
                        + expectedSha265Bash64Hash
                        + "  to Found Hash : "
                        + foundSha265Bash64Hash);

        return match;
    }

    private String createBase64Sha254HashOfNode(JsonNode nodeToHash)
            throws NoSuchAlgorithmException {

        String stringToHash = nodeToHash == null ? "" : nodeToHash.toString();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(stringToHash.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(hash);
    }

    public void ciInPassportCriVc(String ci)
            throws IOException, InterruptedException, ParseException {
        JsonNode jsonNode = objectMapper.readTree((vcBody));
        JsonNode evidenceArray = jsonNode.get("vc").get("evidence");
        JsonNode ciInEvidenceArray = evidenceArray.get(0);
        LOGGER.info("ciInEvidenceArray = " + ciInEvidenceArray);
        JsonNode ciNode = ciInEvidenceArray.get("ci").get(0);
        String actualCI = ciNode.asText();
        Assert.assertEquals(ci, actualCI);
    }

    public void checkPassportResponseContainsException() {
        RETRY.equals(
                "{\"oauth_error\":{\"error_description\":\"Unexpected server error\",\"error\":\"server_error\"}}");
    }

    private String getClaimsForUser(String baseUrl, String criId, int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {

        var url =
                new URI(
                        baseUrl
                                + "/backend/generateInitialClaimsSet?cri="
                                + criId
                                + "&rowNumber="
                                + userDataRowNumber);

        LOGGER.info("URL =>> " + url);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(url)
                        .GET()
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .build();
        return sendHttpRequest(request).body();
    }

    private String createRequest(String baseUrl, String criId, String jsonString)
            throws URISyntaxException, IOException, InterruptedException {

        URI uri = new URI(baseUrl + "/backend/createSessionRequest?cri=" + criId);
        LOGGER.info("URL =>> " + uri);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .POST(HttpRequest.BodyPublishers.ofString(jsonString))
                        .build();

        return sendHttpRequest(request).body();
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest request)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response;
    }

    private static final String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

    private String getAccessTokenRequest(String criId) throws IOException, InterruptedException {
        String coreStubUrl = configurationService.getCoreStubUrl(false);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        coreStubUrl
                                                + "/backend/createTokenRequestPrivateKeyJWT?authorization_code="
                                                + AUTHCODE
                                                + "&cri="
                                                + criId))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .GET()
                        .build();
        return sendHttpRequest(request).body();
    }
}
