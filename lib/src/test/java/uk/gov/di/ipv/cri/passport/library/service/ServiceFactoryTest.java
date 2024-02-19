package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mockConstruction;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ServiceFactoryTest {

    @SystemStub private EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock private AuditService mockAuditService;
    @Mock private DataStore<DocumentCheckResultItem> mockDocumentCheckResultStore;

    private ServiceFactory serviceFactory;

    @BeforeEach
    void setUp() {
        environmentVariables.set("AWS_REGION", "eu-west-2");
        environmentVariables.set("AWS_STACK_NAME", "TEST_STACK");

        serviceFactory = new ServiceFactory();
    }

    @Test
    void shouldReturnObjectMapper() {
        ObjectMapper objectMapper = serviceFactory.getObjectMapper();
        assertNotNull(objectMapper);

        ObjectMapper objectMapper2 = serviceFactory.getObjectMapper();

        assertEquals(objectMapper, objectMapper2);
    }

    @Test
    void shouldReturnEventProbe() {
        EventProbe eventProbe = serviceFactory.getEventProbe();
        assertNotNull(eventProbe);

        EventProbe eventProbe2 = serviceFactory.getEventProbe();
        assertEquals(eventProbe, eventProbe2);
    }

    @Test
    void shouldReturnClientFactoryService() {
        ClientFactoryService clientFactoryService = serviceFactory.getClientFactoryService();
        assertNotNull(clientFactoryService);

        ClientFactoryService clientFactoryService2 = serviceFactory.getClientFactoryService();
        assertEquals(clientFactoryService, clientFactoryService2);
    }

    @Test
    void shouldReturnPassportConfigurationService() {
        ParameterStoreService parameterStoreService1 = serviceFactory.getParameterStoreService();
        assertNotNull(parameterStoreService1);

        ParameterStoreService parameterStoreService2 = serviceFactory.getParameterStoreService();
        assertEquals(parameterStoreService1, parameterStoreService2);
    }

    @Test
    void shouldReturnCommonLibConfigurationService() {
        ConfigurationService commonLibConfigurationService1 =
                serviceFactory.getCommonLibConfigurationService();
        assertNotNull(commonLibConfigurationService1);

        ConfigurationService commonLibConfigurationService2 =
                serviceFactory.getCommonLibConfigurationService();
        assertEquals(commonLibConfigurationService1, commonLibConfigurationService2);
    }

    @Test
    void shouldReturnSessionService() {
        try (MockedConstruction<SessionService> sessionServiceMockedConstruction =
                mockConstruction(SessionService.class)) {

            SessionService sessionService = serviceFactory.getSessionService();
            assertNotNull(sessionService);

            SessionService sessionService2 = serviceFactory.getSessionService();
            assertEquals(sessionService, sessionService2);

            assertEquals(sessionService, sessionServiceMockedConstruction.constructed().get(0));
        }
    }

    @Test
    void shouldReturnAuditService() throws NoSuchFieldException, IllegalAccessException {

        // Audit Service makes nested object calls during construction
        // This test just confirms that the service is a singleton
        Field auditServiceField = serviceFactory.getClass().getDeclaredField("auditService");

        auditServiceField.setAccessible(true);
        auditServiceField.set(serviceFactory, mockAuditService);

        AuditService auditService = serviceFactory.getAuditService();
        assertNotNull(auditService);

        AuditService auditService2 = serviceFactory.getAuditService();
        assertEquals(auditService, auditService2);
    }

    @Test
    void shouldReturnPersonIdentityService() throws NoSuchFieldException, IllegalAccessException {
        try (MockedConstruction<PersonIdentityService> personIdentityServiceMockedConstruction =
                mockConstruction(PersonIdentityService.class)) {

            PersonIdentityService personIdentityService = serviceFactory.getPersonIdentityService();
            assertNotNull(personIdentityService);

            PersonIdentityService personIdentityService2 =
                    serviceFactory.getPersonIdentityService();
            assertEquals(personIdentityService, personIdentityService2);

            assertEquals(
                    personIdentityService,
                    personIdentityServiceMockedConstruction.constructed().get(0));
        }
    }

    @Test
    void shouldReturnDocumentCheckResultStore()
            throws NoSuchFieldException, IllegalAccessException {

        // DataStore makes nested object calls using objects created during construction
        // This test just confirms that the service is a singleton
        Field documentCheckResultStoreField =
                serviceFactory.getClass().getDeclaredField("documentCheckResultStore");

        documentCheckResultStoreField.setAccessible(true);
        documentCheckResultStoreField.set(serviceFactory, mockDocumentCheckResultStore);

        DataStore<DocumentCheckResultItem> documentCheckResultStore =
                serviceFactory.getDocumentCheckResultStore();
        assertNotNull(documentCheckResultStore);

        DataStore<DocumentCheckResultItem> documentCheckResultStore2 =
                serviceFactory.getDocumentCheckResultStore();
        assertEquals(documentCheckResultStore, documentCheckResultStore2);
    }
}
