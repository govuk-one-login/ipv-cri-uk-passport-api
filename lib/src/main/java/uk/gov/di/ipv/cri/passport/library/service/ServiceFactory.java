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

    private final ObjectMapper objectMapper;
    private final PassportConfigurationService passportConfigurationService;
    private final ClientFactoryService clientFactoryService;
    private final EventProbe eventProbe;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final PersonIdentityService personIdentityService;

    private final DataStore<DocumentCheckResultItem> documentCheckResultStore;

    /** Creates common service objects used by *both* passport lambdas */
    @ExcludeFromGeneratedCoverageReport
    public ServiceFactory() {
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        this.clientFactoryService = new ClientFactoryService();
        this.passportConfigurationService = new PassportConfigurationService(clientFactoryService);

        this.eventProbe = new EventProbe();
        this.sessionService = createSessionService(passportConfigurationService);
        this.auditService =
                createAuditService(
                        passportConfigurationService, objectMapper, clientFactoryService);
        this.personIdentityService = new PersonIdentityService(passportConfigurationService);

        this.documentCheckResultStore =
                createDocumentCheckResultStore(passportConfigurationService);
    }

    public ServiceFactory(
            ObjectMapper objectMapper,
            PassportConfigurationService passportConfigurationService,
            ClientFactoryService clientFactoryService,
            EventProbe eventProbe,
            SessionService sessionService,
            AuditService auditService,
            PersonIdentityService personIdentityService,
            DataStore<DocumentCheckResultItem> documentCheckResultStore) {
        this.objectMapper = objectMapper;

        this.clientFactoryService = clientFactoryService;
        this.passportConfigurationService = passportConfigurationService;

        this.eventProbe = eventProbe;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.personIdentityService = personIdentityService;

        this.documentCheckResultStore = documentCheckResultStore;
    }

    private SessionService createSessionService(
            PassportConfigurationService passportConfigurationService) {
        return new SessionService(passportConfigurationService);
    }

    private AuditService createAuditService(
            ConfigurationService commonConfigurationService,
            ObjectMapper objectMapper,
            ClientFactoryService clientFactoryService) {

        return new AuditService(
                clientFactoryService.getSqsClient(),
                commonConfigurationService,
                objectMapper,
                new AuditEventFactory(commonConfigurationService, Clock.systemUTC()));
    }

    private DataStore<DocumentCheckResultItem> createDocumentCheckResultStore(
            ConfigurationService commonConfigurationService) {
        final String tableName =
                commonConfigurationService.getParameterValue(DOCUMENT_CHECK_RESULT_TABLE_NAME);
        return new DataStore<>(tableName, DocumentCheckResultItem.class, DataStore.getClient());
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public EventProbe getEventProbe() {
        return eventProbe;
    }

    public PassportConfigurationService getPassportConfigurationService() {
        return passportConfigurationService;
    }

    public SessionService getSessionService() {
        return sessionService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public PersonIdentityService getPersonIdentityService() {
        return personIdentityService;
    }

    public ClientFactoryService getClientFactoryService() {
        return clientFactoryService;
    }

    public DataStore<DocumentCheckResultItem> getDocumentCheckResultStore() {
        return documentCheckResultStore;
    }
}
