package uk.gov.di.ipv.cri.passport.issuecredential.pact;



import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import software.amazon.awssdk.regions.Region;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.CanonicalAddress;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityDateOfBirth;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityItem;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityName;
import uk.gov.di.ipv.cri.common.library.persistence.item.personidentity.PersonIdentityNamePart;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
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
import uk.gov.di.ipv.cri.passport.library.service.ClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
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

// For static tests against potential new contracts
@PactFolder("pacts")
// For local tests the pact details will need set as environment variables
//@Tag("Pact")
@Provider("PassportCriProvider")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IssueCredentialHandlerTest {

    private static final int PORT = 5050;
    private static boolean SERVER_STARTED = false;

    @Mock private PassportConfigurationService configurationService;
    @Mock private DataStore<SessionItem> dataStore;
    @Mock private DataStore<PersonIdentityItem> personIdentityDataStore;
    @Mock private DataStore<DocumentCheckResultItem> documentCheckResultStore;
    @Mock private EventProbe eventProbe;
    @Mock private AuditService auditService;
    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {

        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);

        when(configurationService.getVerifiableCredentialIssuer()).thenReturn("dummyPassportComponentId");
        when(configurationService.getSessionExpirationEpoch()).thenReturn(todayPlusADay);
        when(configurationService.getAuthorizationCodeExpirationEpoch()).thenReturn(todayPlusADay);
        when(configurationService.getMaxJwtTtl()).thenReturn(1000L);
        when(configurationService.getStackParameterValue(MAX_JWT_TTL_UNIT)).thenReturn("HOURS");
        when(configurationService.getVerifiableCredentialIssuer()).thenReturn("dummyPassportComponentId");

        ServiceFactory serviceFactory =
                new ServiceFactory(
                        new ObjectMapper(),
                        eventProbe,
                        new ClientFactoryService(Region.EU_WEST_2),
                        configurationService,
                        new SessionService(dataStore, configurationService, Clock.systemUTC(), new ListUtil()),
                        auditService,
                        new PersonIdentityService(new PersonIdentityMapper(), configurationService, personIdentityDataStore),
                        documentCheckResultStore);

        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec privateKeySpec =
                new PKCS8EncodedKeySpec(
                        Base64.getDecoder()
                                .decode(
                                        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBYNBSda5ttN9Wu4Do4" +
                                                "gLV1xaks+DB5n6ity2MvBlzDUw=="));
        JWSSigner signer =
                new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        Injector tokenHandlerInjector =
                new Injector(
                        new IssueCredentialHandler(
                                serviceFactory,
                                new VerifiableCredentialService(serviceFactory, signer)),
                        "/issue/credential",
                        "/");
        if (!SERVER_STARTED) {
            MockHttpServer.startServer(new ArrayList<>(List.of(tokenHandlerInjector)), PORT);
            SERVER_STARTED = true;
        }

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @State("dummyApiKey is a valid api key")
    void dummyAPIKeyIsValid() {}

    @State("dummyAccessToken is a valid access token")
    void componentIdIsSetToPassportCri() {}

    @State("test-subject is a valid subject")
    void passportIsUsingExpectedSigningKey() {}

    @State("dummyPassportComponentId is a valid issuer")
    void componentIdIsValidIssue() {}

    @State("VC familyName is Watson")
    void vcHasTheDesiredFamilyName() {}

    @State("VC givenName is Mary")
    void vcHasTheDesiredGivenName() {}

    @State("VC birthDate is 1932-02-25")
    void vcHasTheDesiredBirthDate() {}

    @State("VC passport documentNumber is 824159121")
    void vcHasTheDesiredDocumentNumber() {}

    @State("VC passport expiryDate is 2030-01-01")
    void vcHasTheDesiredExpiryDate() {}

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        // Simulates session creation and CRI lambda completion by generating an auth code
        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);

        SessionService sessionService =
                new SessionService(
                        dataStore, configurationService, Clock.systemUTC(), new ListUtil());

        // INITIAL SESSION HANDOFF
        UUID sessionId = performInitialSessionRequest(sessionService, todayPlusADay);
        setPersonIntoMockDB(sessionId);
        // INITIAL SESSION HANDOFF

        // SIMULATED CRI LOGIC
        PersonIdentityName name = createName("Mary", "Watson");
        PersonIdentityDateOfBirth birthDate = createDoB(1932, 2, 25);
        CanonicalAddress address = createAddress();

        PersonIdentityItem personIdentityItem = createPerson(name, birthDate, address);

        setPersonIntoMockDB(sessionId, personIdentityItem);

        DocumentCheckResultItem documentCheckResultItem = createDocument( "824159121");

        List<String> identityChecks = List.of("IdentityCheck");
        setScoresAndChecks(documentCheckResultItem, identityChecks);
        setDocumentIntoMockDB(sessionId, documentCheckResultItem);
        // SIMULATED CRI LOGIC


        // SESSION HANDBACK
        performAuthorizationCodeSet(sessionService, sessionId);
        // SESSION HANDBACK

        // ACCESS TOKEN GENERATION AND SETTING
        SessionItem session = performAccessTokenSet(sessionService, sessionId);
        // ACCESS TOKEN GENERATION AND SETTING

        when(dataStore.getItemByIndex(SessionItem.ACCESS_TOKEN_INDEX, "Bearer dummyAccessToken"))
                .thenReturn(List.of(session));
        context.verifyInteraction();
    }

    private void setScoresAndChecks(DocumentCheckResultItem documentCheckResultItem, List<String> identityChecks) {
        documentCheckResultItem.setValidityScore(2);
        documentCheckResultItem.setStrengthScore(4);
        documentCheckResultItem.setCheckDetails(identityChecks);
        documentCheckResultItem.setCiReasons(new ArrayList<>());
    }

    private void setDocumentIntoMockDB(UUID sessionId, DocumentCheckResultItem documentCheckResultItem) {
        documentCheckResultItem.setSessionId(sessionId);
        when(documentCheckResultStore.getItem(sessionId.toString()))
                .thenReturn(documentCheckResultItem);
    }

    private DocumentCheckResultItem createDocument(String docNumber) {
        DocumentCheckResultItem documentCheckResultItem = new DocumentCheckResultItem();
        documentCheckResultItem.setCiReasons(new ArrayList<>());
        documentCheckResultItem.setDocumentNumber(docNumber);
        documentCheckResultItem.setTransactionId("DSJJSEE29392");
        documentCheckResultItem.setTtl(10000L);
        documentCheckResultItem.setExpiryDate(LocalDate.of(2030, 1, 1).toString());
        return documentCheckResultItem;
    }

    private void setPersonIntoMockDB(UUID sessionId, PersonIdentityItem personIdentityItem) {
        personIdentityItem.setSessionId(sessionId);
        when(personIdentityDataStore.getItem(sessionId.toString()))
                .thenReturn(personIdentityItem);
    }

    private PersonIdentityItem createPerson(PersonIdentityName name, PersonIdentityDateOfBirth birthDate, CanonicalAddress address) {
        PersonIdentityItem personIdentityItem = new PersonIdentityItem();
        personIdentityItem.setExpiryDate(
                LocalDate.of(2030, 1, 1).toEpochSecond(LocalTime.now(), ZoneOffset.UTC));
        personIdentityItem.setAddresses(List.of(address));
        personIdentityItem.setNames(List.of(name));
        personIdentityItem.setBirthDates(List.of(birthDate));
        return personIdentityItem;
    }

    private static CanonicalAddress createAddress() {
        CanonicalAddress address = new CanonicalAddress();
        address.setBuildingNumber("buildingNum");
        address.setBuildingName("buildingName");
        address.setStreetName("street");
        address.setAddressLocality("locality");
        address.setPostalCode("postcode");
        address.setValidFrom(LocalDate.now().minusDays(1));
        return address;
    }

    private PersonIdentityDateOfBirth createDoB(int year, int month, int day) {
        PersonIdentityDateOfBirth birthDate = new PersonIdentityDateOfBirth();
        birthDate.setValue(LocalDate.of(year, month, day));
        return birthDate;
    }

    private PersonIdentityName createName(String firstName, String surname) {
        PersonIdentityNamePart firstNamePart = new PersonIdentityNamePart();
        firstNamePart.setType("GivenName");
        firstNamePart.setValue(firstName);
        PersonIdentityNamePart surnamePart = new PersonIdentityNamePart();
        surnamePart.setType("FamilyName");
        surnamePart.setValue(surname);
        PersonIdentityName name = new PersonIdentityName();
        name.setNameParts(List.of(firstNamePart, surnamePart));
        return name;
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
        session.setAccessTokenExpiryDate(LocalDate.now().plusDays(1).toEpochSecond(LocalTime.now(), ZoneOffset.UTC));
        sessionService.updateSession(session);
        return session;
    }

    private void setPersonIntoMockDB(UUID sessionId) {
        ArgumentCaptor<SessionItem> sessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        verify(dataStore).create(sessionItemArgumentCaptor.capture());

        SessionItem savedSessionitem = sessionItemArgumentCaptor.getValue();

        when(dataStore.getItem(sessionId.toString()))
                .thenReturn(savedSessionitem);
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

        doNothing().when(dataStore).create(any(SessionItem.class));

        return sessionService.saveSession(sessionRequest);
    }

}
