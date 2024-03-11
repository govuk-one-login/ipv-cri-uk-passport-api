package uk.gov.di.ipv.cri.passport.issuecredential.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.CanonicalAddress;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityDateOfBirth;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityItem;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityName;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityNamePart;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityMapper;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.common.library.util.ListUtil;
import uk.gov.di.ipv.cri.passport.issuecredential.handler.IssueCredentialHandler;
import uk.gov.di.ipv.cri.passport.issuecredential.pact.utils.Injector;
import uk.gov.di.ipv.cri.passport.issuecredential.pact.utils.MockHttpServer;
import uk.gov.di.ipv.cri.passport.issuecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.io.IOException;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.MAX_JWT_TTL_UNIT;

@Tag("Pact")
@Provider("PassportVcProvider")
@PactBroker(
        url = "https://${PACT_BROKER_HOST}",
        authentication =
                @PactBrokerAuth(
                        username = "${PACT_BROKER_USERNAME}",
                        password = "${PACT_BROKER_PASSWORD}"))
@ExtendWith(MockitoExtension.class)
class IssueCredentialHandlerTest {

    private static final int PORT = 5050;

    @Mock private ServiceFactory mockServiceFactory;
    @Mock private EventProbe mockEventProbe;
    @Mock private ConfigurationService mockCommonLibConfigurationService;
    private SessionService sessionService;
    @Mock private AuditService mockAuditService;
    @Mock private DataStore<DocumentCheckResultItem> mockDocumentCheckResultStore;
    @Mock private ParameterStoreService mockParameterStoreService;

    @Mock private DataStore<SessionItem> sessionItemDataStore;
    @Mock private DataStore<PersonIdentityItem> personIdentityDataStore;

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {

        mockServiceFactoryBehaviour();

        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec privateKeySpec =
                new PKCS8EncodedKeySpec(
                        Base64.getDecoder()
                                .decode(
                                        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBYNBSda5ttN9Wu4Do4"
                                                + "gLV1xaks+DB5n6ity2MvBlzDUw=="));
        JWSSigner signer = new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        Injector tokenHandlerInjector =
                new Injector(
                        new IssueCredentialHandler(
                                mockServiceFactory,
                                new VerifiableCredentialService(mockServiceFactory, signer)),
                        "/issue/credential",
                        "/");
        MockHttpServer.startServer(new ArrayList<>(List.of(tokenHandlerInjector)), PORT, signer);

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @AfterEach
    public void tearDown() {
        MockHttpServer.stopServer();
    }

    @State("dummyApiKey is a valid api key")
    void dummyAPIKeyIsValid() {}

    @State("dummyAccessToken is a valid access token")
    void accessTokenIsValid() {
        mockHappyPathVcParameters();

        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);

        // INITIAL SESSION HANDOFF
        UUID sessionId = performInitialSessionRequest(sessionService, todayPlusADay);
        setSessionIntoMockDB(sessionId);
        // INITIAL SESSION HANDOFF

        // SIMULATED CRI LOGIC
        PersonIdentityNamePart firstNamePart = new PersonIdentityNamePart();
        firstNamePart.setType("GivenName");
        firstNamePart.setValue("Mary");
        PersonIdentityNamePart surnamePart = new PersonIdentityNamePart();
        surnamePart.setType("FamilyName");
        surnamePart.setValue("Watson");
        PersonIdentityName name = new PersonIdentityName();
        name.setNameParts(List.of(firstNamePart, surnamePart));

        PersonIdentityDateOfBirth birthDate = new PersonIdentityDateOfBirth();
        birthDate.setValue(LocalDate.of(1932, 2, 25));

        CanonicalAddress address = new CanonicalAddress();
        address.setBuildingNumber("46");
        address.setBuildingName("The Building");
        address.setStreetName("Main Street");
        address.setAddressLocality("London");
        address.setPostalCode("E1 6AN");
        address.setValidFrom(LocalDate.now().minusDays(1));

        PersonIdentityItem personIdentityItem = new PersonIdentityItem();
        personIdentityItem.setExpiryDate(
                LocalDate.of(2030, 1, 1).toEpochSecond(LocalTime.now(), ZoneOffset.UTC));
        personIdentityItem.setSessionId(sessionId);
        personIdentityItem.setAddresses(List.of(address));
        personIdentityItem.setNames(List.of(name));
        personIdentityItem.setBirthDates(List.of(birthDate));

        when(personIdentityDataStore.getItem(sessionId.toString())).thenReturn(personIdentityItem);

        // SESSION HANDBACK
        performAuthorizationCodeSet(sessionService, sessionId);
        // SESSION HANDBACK

        // ACCESS TOKEN GENERATION AND SETTING
        SessionItem session = performAccessTokenSet(sessionService, sessionId);
        // ACCESS TOKEN GENERATION AND SETTING

        when(sessionItemDataStore.getItemByIndex(
                        SessionItem.ACCESS_TOKEN_INDEX, "Bearer dummyAccessToken"))
                .thenReturn(List.of(session));
    }

    @State("dummyInvalidAccessToken is an invalid access token")
    void invalidAccessTokenIsInvalidAccessToken() {}

    @State("test-subject is a valid subject")
    void jwtSubjectIsValid() {}

    @State("dummyPassportComponentId is a valid issuer")
    void componentIdIsValidIssue() {}

    @State("VC familyName is Watson")
    void vcHasTheDesiredFamilyName() {}

    @State("VC is a scenario 2 failure")
    void vcHasTheDesiredFamilyName1() throws ParseException {
        UUID sessionUUID =
                sessionService
                        .getSessionByAccessToken(
                                AccessToken.parse(
                                        "Bearer dummyAccessToken", AccessTokenType.BEARER))
                        .getSessionId();
        String sessionId = sessionUUID.toString();

        DocumentCheckResultItem documentCheckResultItem = createBaseDocumentResultItem(sessionUUID);
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        documentCheckResultItem.setDocumentNumber("123456789");
        documentCheckResultItem.setFailedCheckDetails(
                List.of("scenario1_check", "scenario2_check"));
        documentCheckResultItem.setCheckDetails(List.of("record_check"));
        documentCheckResultItem.setValidityScore(0);
        documentCheckResultItem.setContraIndicators(List.of("CI01"));
        documentCheckResultItem.setCiReasons(List.of("CI01,Scenario2"));
        when(mockDocumentCheckResultStore.getItem(sessionId.toString()))
                .thenReturn(documentCheckResultItem);
    }

    @State("VC givenName is Mary")
    void vcHasTheDesiredGivenName() {}

    @State("VC birthDate is 1932-02-25")
    void vcHasTheDesiredBirthDate() {}

    @State("VC passport documentNumber is 824159121")
    void vcHasTheDesiredDocumentNumber() throws ParseException {
        UUID sessionUUID =
                sessionService
                        .getSessionByAccessToken(
                                AccessToken.parse(
                                        "Bearer dummyAccessToken", AccessTokenType.BEARER))
                        .getSessionId();
        String sessionId = sessionUUID.toString();

        DocumentCheckResultItem documentCheckResultItem = createBaseDocumentResultItem(sessionUUID);
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        documentCheckResultItem.setDocumentNumber("824159121");
        documentCheckResultItem.setCheckDetails(List.of("scenario_1", "record_check"));
        documentCheckResultItem.setValidityScore(2);
        documentCheckResultItem.setContraIndicators(new ArrayList<>());
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        when(mockDocumentCheckResultStore.getItem(sessionId.toString()))
                .thenReturn(documentCheckResultItem);
    }

    @State("VC passport documentNumber is 123456789")
    void vcHasTheDesiredDocumentNumber2() throws ParseException {
        UUID sessionUUID =
                sessionService
                        .getSessionByAccessToken(
                                AccessToken.parse(
                                        "Bearer dummyAccessToken", AccessTokenType.BEARER))
                        .getSessionId();
        String sessionId = sessionUUID.toString();

        DocumentCheckResultItem documentCheckResultItem = createBaseDocumentResultItem(sessionUUID);
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        documentCheckResultItem.setDocumentNumber("123456789");
        documentCheckResultItem.setFailedCheckDetails(List.of("record_check"));
        documentCheckResultItem.setValidityScore(0);
        documentCheckResultItem.setContraIndicators(List.of("D02"));
        documentCheckResultItem.setCiReasons(List.of("D02,NoMatchingRecord"));
        when(mockDocumentCheckResultStore.getItem(sessionId.toString()))
                .thenReturn(documentCheckResultItem);
    }

    @State("VC passport expiryDate is 2030-12-12")
    void vcHasTheDesiredExpiryDate() {}

    @State("VC passport expiryDate is 2030-01-01")
    void vcHasTheDesiredExpiryDate2() {}

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        context.verifyInteraction();
    }

    private SessionItem performAuthorizationCodeSet(SessionService sessionService, UUID sessionId) {
        SessionItem session = sessionService.getSession(sessionId.toString());
        sessionService.createAuthorizationCode(session);
        session.setAuthorizationCode("dummyAuthCode");
        sessionService.updateSession(session);
        return session;
    }

    private SessionItem performAccessTokenSet(SessionService sessionService, UUID sessionId) {
        SessionItem session = sessionService.getSession(sessionId.toString());
        session.setAccessToken("dummyAccessToken");
        session.setAccessTokenExpiryDate(
                LocalDate.now().plusDays(1).toEpochSecond(LocalTime.now(), ZoneOffset.UTC));
        sessionService.updateSession(session);
        return session;
    }

    private void setSessionIntoMockDB(UUID sessionId) {
        ArgumentCaptor<SessionItem> sessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        verify(sessionItemDataStore).create(sessionItemArgumentCaptor.capture());

        SessionItem savedSessionitem = sessionItemArgumentCaptor.getValue();

        when(sessionItemDataStore.getItem(sessionId.toString())).thenReturn(savedSessionitem);
    }

    private UUID performInitialSessionRequest(SessionService sessionService, long todayPlusADay) {
        SessionRequest sessionRequest = new SessionRequest();
        sessionRequest.setNotBeforeTime(new Date(todayPlusADay));
        sessionRequest.setClientId("ipv-core");
        sessionRequest.setAudience("dummyPassportComponentId");
        sessionRequest.setRedirectUri(URI.create("http://localhost:5050"));
        sessionRequest.setExpirationTime(new Date(todayPlusADay));
        sessionRequest.setIssuer("ipv-core");
        sessionRequest.setClientId("ipv-core");
        sessionRequest.setSubject("test-subject");

        doNothing().when(sessionItemDataStore).create(any(SessionItem.class));

        return sessionService.saveSession(sessionRequest);
    }

    private static DocumentCheckResultItem createBaseDocumentResultItem(UUID sessionUUID) {
        DocumentCheckResultItem documentCheckResultItem = new DocumentCheckResultItem();
        documentCheckResultItem.setStrengthScore(4);
        documentCheckResultItem.setTransactionId("278450f1-75f5-4d0d-9e8e-8bc37a07248d");
        documentCheckResultItem.setTtl(10000L);
        documentCheckResultItem.setExpiryDate(LocalDate.of(2030, 1, 1).toString());
        documentCheckResultItem.setSessionId(sessionUUID);
        return documentCheckResultItem;
    }

    private void mockServiceFactoryBehaviour() {

        when(mockServiceFactory.getObjectMapper()).thenReturn(new ObjectMapper());
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);
        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);
        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);
        when(mockServiceFactory.getCommonLibConfigurationService())
                .thenReturn(mockCommonLibConfigurationService);
        sessionService =
                new SessionService(
                        sessionItemDataStore,
                        mockCommonLibConfigurationService,
                        Clock.systemUTC(),
                        new ListUtil());
        when(mockServiceFactory.getSessionService()).thenReturn(sessionService);
        when(mockServiceFactory.getAuditService()).thenReturn(mockAuditService);
        when(mockServiceFactory.getPersonIdentityService())
                .thenReturn(
                        new PersonIdentityService(
                                new PersonIdentityMapper(),
                                mockCommonLibConfigurationService,
                                personIdentityDataStore));
        when(mockServiceFactory.getDocumentCheckResultStore())
                .thenReturn(mockDocumentCheckResultStore);
    }

    private void mockHappyPathVcParameters() {
        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);

        when(mockCommonLibConfigurationService.getVerifiableCredentialIssuer())
                .thenReturn("dummyPassportComponentId");
        when(mockCommonLibConfigurationService.getSessionExpirationEpoch())
                .thenReturn(todayPlusADay);
        when(mockCommonLibConfigurationService.getAuthorizationCodeExpirationEpoch())
                .thenReturn(todayPlusADay);
        when(mockCommonLibConfigurationService.getMaxJwtTtl()).thenReturn(1000L);
        when(mockParameterStoreService.getStackParameterValue(MAX_JWT_TTL_UNIT))
                .thenReturn("HOURS");
        when(mockCommonLibConfigurationService.getVerifiableCredentialIssuer())
                .thenReturn("dummyPassportComponentId");
        when(mockCommonLibConfigurationService.getParameterValueByAbsoluteName(
                        "/release-flags/vc-expiry-removed"))
                .thenReturn("true");
        when(mockCommonLibConfigurationService.getParameterValue(
                        "release-flags/vc-contains-unique-id"))
                .thenReturn("true");
    }
}
