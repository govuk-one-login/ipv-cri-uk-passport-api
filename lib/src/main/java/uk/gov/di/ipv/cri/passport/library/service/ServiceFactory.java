package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.service.AuditEventFactory;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
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
    private PassportConfigurationService passportConfigurationService;
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

    public PassportConfigurationService getPassportConfigurationService() {

        if (passportConfigurationService == null) {
            passportConfigurationService =
                    new PassportConfigurationService(getClientFactoryService());
        }

        return passportConfigurationService;
    }

    public SessionService getSessionService() {

        if (sessionService == null) {
            sessionService = new SessionService(getPassportConfigurationService());
        }

        return sessionService;
    }

    public AuditService getAuditService() {

        if (auditService == null) {
            auditService =
                    new AuditService(
                            getClientFactoryService().getSqsClient(),
                            getPassportConfigurationService(),
                            getObjectMapper(),
                            new AuditEventFactory(
                                    getPassportConfigurationService(), Clock.systemUTC()));
        }

        return auditService;
    }

    public PersonIdentityService getPersonIdentityService() {

        if (personIdentityService == null) {
            personIdentityService = new PersonIdentityService(getPassportConfigurationService());
        }

        return personIdentityService;
    }

    public DataStore<DocumentCheckResultItem> getDocumentCheckResultStore() {

        if (documentCheckResultStore == null) {
            final String tableName =
                    getPassportConfigurationService()
                            .getParameterValue(DOCUMENT_CHECK_RESULT_TABLE_NAME);

            documentCheckResultStore =
                    new DataStore<>(
                            tableName, DocumentCheckResultItem.class, DataStore.getClient());
        }

        return documentCheckResultStore;
    }
}
