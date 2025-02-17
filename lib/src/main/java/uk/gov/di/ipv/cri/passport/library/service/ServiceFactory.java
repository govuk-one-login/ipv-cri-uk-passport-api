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
import uk.gov.di.ipv.cri.common.library.util.ClientProviderFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.time.Clock;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.DOCUMENT_CHECK_RESULT_TABLE_NAME;

public class ServiceFactory {

    private ObjectMapper objectMapper;
    private EventProbe eventProbe;
    private ClientProviderFactory clientProviderFactory;
    private ApacheHTTPClientFactoryService apacheHTTPClientFactoryService;
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
            ClientProviderFactory clientProviderFactory,
            ParameterStoreService parameterStoreService,
            SessionService sessionService,
            AuditService auditService,
            PersonIdentityService personIdentityService,
            DataStore<DocumentCheckResultItem> documentCheckResultStore) {
        this.objectMapper = objectMapper;
        this.eventProbe = eventProbe;
        this.clientProviderFactory = clientProviderFactory;
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

    public ClientProviderFactory getClientProviderFactory() {

        if (clientProviderFactory == null) {
            // The following sets avoidExecutionInterceptorsOnClientsUsedByPowerTools to true.
            // This is due to a conflict between aws power tools and Dynatrace, when using OpenTel
            // On the AWS clients used by the power tools providers.
            clientProviderFactory = new ClientProviderFactory(true, true);
        }

        return clientProviderFactory;
    }

    public ApacheHTTPClientFactoryService getApacheHTTPClientFactoryService() {
        if (apacheHTTPClientFactoryService == null) {
            apacheHTTPClientFactoryService = new ApacheHTTPClientFactoryService();
        }

        return apacheHTTPClientFactoryService;
    }

    public ParameterStoreService getParameterStoreService() {

        if (parameterStoreService == null) {
            parameterStoreService =
                    new ParameterStoreService(getClientProviderFactory().getSSMProvider());
        }

        return parameterStoreService;
    }

    public SessionService getSessionService() {

        if (sessionService == null) {
            sessionService =
                    new SessionService(
                            getCommonLibConfigurationService(),
                            getClientProviderFactory().getDynamoDbEnhancedClient());
        }

        return sessionService;
    }

    public AuditService getAuditService() {

        if (auditService == null) {
            auditService =
                    new AuditService(
                            getClientProviderFactory().getSqsClient(),
                            getCommonLibConfigurationService(),
                            getObjectMapper(),
                            new AuditEventFactory(
                                    getCommonLibConfigurationService(), Clock.systemUTC()));
        }

        return auditService;
    }

    public PersonIdentityService getPersonIdentityService() {

        if (personIdentityService == null) {
            this.personIdentityService =
                    new PersonIdentityService(
                            getCommonLibConfigurationService(),
                            getClientProviderFactory().getDynamoDbEnhancedClient());
        }

        return personIdentityService;
    }

    public ConfigurationService getCommonLibConfigurationService() {

        if (commonLibConfigurationService == null) {
            commonLibConfigurationService =
                    new uk.gov.di.ipv.cri.common.library.service.ConfigurationService(
                            getClientProviderFactory().getSSMProvider(),
                            getClientProviderFactory().getSecretsProvider());
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
                            tableName,
                            DocumentCheckResultItem.class,
                            getClientProviderFactory().getDynamoDbEnhancedClient());
        }

        return documentCheckResultStore;
    }
}
