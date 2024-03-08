package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.service.AuditEventFactory;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.PersonIdentityService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.time.Clock;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DOCUMENT_CHECK_RESULT_TABLE_NAME;

public class ServiceFactory {

    private ObjectMapper objectMapper;
    private EventProbe eventProbe;
    private ClientFactoryService clientFactoryService;
    private ParameterStoreService parameterStoreService;
    private ConfigurationService commonLibConfigurationService;
    private SessionService sessionService;
    private AuditService auditService;
    private PersonIdentityService personIdentityService;
    private DataStore<DocumentCheckResultItem> documentCheckResultStore;

    /**
     * Creates common service objects used by *both* passport lambdas Important - - All objects in
     * this class are intended to be singletons. ALWAYS use getters() for object parameters to
     * ensure all parameters objects are also setup
     */
    public ServiceFactory() {
        // Lazy Init Singletons (NOT thread safe)
    }

    @SuppressWarnings("java:S107")
    @ExcludeFromGeneratedCoverageReport
    public ServiceFactory(
            ObjectMapper objectMapper,
            EventProbe eventProbe,
            ClientFactoryService clientFactoryService,
            ParameterStoreService parameterStoreService,
            SessionService sessionService,
            AuditService auditService,
            PersonIdentityService personIdentityService,
            DataStore<DocumentCheckResultItem> documentCheckResultStore) {
        this.objectMapper = objectMapper;
        this.eventProbe = eventProbe;
        this.clientFactoryService = clientFactoryService;
        this.parameterStoreService = parameterStoreService;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.personIdentityService = personIdentityService;
        this.documentCheckResultStore = documentCheckResultStore;
    }

    public ObjectMapper getObjectMapper() {

        if (objectMapper == null) {
            objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        }

        return objectMapper;
    }

    public EventProbe getEventProbe() {

        if (eventProbe == null) {
            eventProbe = new EventProbe();
        }

        return eventProbe;
    }

    public ClientFactoryService getClientFactoryService() {

        if (clientFactoryService == null) {
            clientFactoryService = new ClientFactoryService();
        }

        return clientFactoryService;
    }

    public ParameterStoreService getParameterStoreService() {

        if (parameterStoreService == null) {
            parameterStoreService = new ParameterStoreService(getClientFactoryService());
        }

        return parameterStoreService;
    }

    public SessionService getSessionService() {

        if (sessionService == null) {
            sessionService = new SessionService(getCommonLibConfigurationService());
        }

        return sessionService;
    }

    public AuditService getAuditService() {

        if (auditService == null) {
            auditService =
                    new AuditService(
                            getClientFactoryService().getSqsClient(),
                            getCommonLibConfigurationService(),
                            getObjectMapper(),
                            new AuditEventFactory(
                                    getCommonLibConfigurationService(), Clock.systemUTC()));
        }

        return auditService;
    }

    public PersonIdentityService getPersonIdentityService() {

        if (personIdentityService == null) {
            personIdentityService = new PersonIdentityService(getCommonLibConfigurationService());
        }

        return personIdentityService;
    }

    public ConfigurationService getCommonLibConfigurationService() {

        if (commonLibConfigurationService == null) {
            // Note SSM parameter gets via this service use a 5min cache time
            commonLibConfigurationService =
                    new uk.gov.di.ipv.cri.common.library.service.ConfigurationService();
        }

        return commonLibConfigurationService;
    }

    public DataStore<DocumentCheckResultItem> getDocumentCheckResultStore() {

        if (documentCheckResultStore == null) {
            final String tableName =
                    getParameterStoreService()
                            .getStackParameterValue(DOCUMENT_CHECK_RESULT_TABLE_NAME);

            documentCheckResultStore =
                    new DataStore<>(
                            tableName, DocumentCheckResultItem.class, DataStore.getClient());
        }

        return documentCheckResultStore;
    }
}
