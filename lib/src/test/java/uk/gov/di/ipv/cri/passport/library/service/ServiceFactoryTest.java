package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.service.AuditEventFactory;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
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

    @Mock private ParameterStoreService mockParameterStoreService;
    @Mock private ConfigurationService mockCommonLibConfigurationService;

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
    void shouldReturnClientProviderFactory() {
        ClientProviderFactory clientProviderFactory1 = serviceFactory.getClientProviderFactory();
        assertNotNull(clientProviderFactory1);

        ClientProviderFactory clientProviderFactory2 = serviceFactory.getClientProviderFactory();
        assertEquals(clientProviderFactory1, clientProviderFactory2);
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
    @SuppressWarnings("java:S1481") // ignored
    void shouldReturnAuditService() throws NoSuchFieldException, IllegalAccessException {

        // Pre-set commonLibConfigurationService to avoid real SSM calls
        Field commonLibConfigField =
                serviceFactory.getClass().getDeclaredField("commonLibConfigurationService");
        commonLibConfigField.setAccessible(true);
        commonLibConfigField.set(serviceFactory, mockCommonLibConfigurationService);

        try (MockedConstruction<AuditEventFactory> ignored =
                        mockConstruction(AuditEventFactory.class);
                MockedConstruction<AuditService> auditServiceMockedConstruction =
                        mockConstruction(AuditService.class)) {

            AuditService auditService = serviceFactory.getAuditService();
            assertNotNull(auditService);

            AuditService auditService2 = serviceFactory.getAuditService();
            assertEquals(auditService, auditService2);

            assertEquals(auditService, auditServiceMockedConstruction.constructed().getFirst());
        }
    }

    @Test
    void shouldReturnPersonIdentityService() {
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

        // Pre-set parameterStoreService to avoid real SSM calls
        Field parameterStoreServiceField =
                serviceFactory.getClass().getDeclaredField("parameterStoreService");
        parameterStoreServiceField.setAccessible(true);
        parameterStoreServiceField.set(serviceFactory, mockParameterStoreService);

        try (@SuppressWarnings("rawtypes")
                MockedConstruction<DataStore> dataStoreMockedConstruction =
                        mockConstruction(DataStore.class)) {

            DataStore<DocumentCheckResultItem> documentCheckResultStore =
                    serviceFactory.getDocumentCheckResultStore();
            assertNotNull(documentCheckResultStore);

            DataStore<DocumentCheckResultItem> documentCheckResultStore2 =
                    serviceFactory.getDocumentCheckResultStore();
            assertEquals(documentCheckResultStore, documentCheckResultStore2);

            assertEquals(
                    documentCheckResultStore, dataStoreMockedConstruction.constructed().get(0));
        }
    }
}
