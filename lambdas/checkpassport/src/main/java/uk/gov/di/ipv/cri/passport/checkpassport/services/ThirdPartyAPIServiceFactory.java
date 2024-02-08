package uk.gov.di.ipv.cri.passport.checkpassport.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dcs.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dcs.DcsThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.DvadThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.library.service.ClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.IS_DCS_PERFORMANCE_STUB;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.IS_DVAD_PERFORMANCE_STUB;

public class ThirdPartyAPIServiceFactory {
    private final EventProbe eventProbe;
    private final ObjectMapper objectMapper;

    private final PassportConfigurationService passportConfigurationService;

    public final ClientFactoryService clientFactoryService;

    private static final int DVAD = 0;
    private static final int DCS = 1;
    private final ThirdPartyAPIService[] thirdPartyAPIServices = new ThirdPartyAPIService[2];

    public ThirdPartyAPIServiceFactory(ServiceFactory serviceFactory) {
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();
        this.eventProbe = serviceFactory.getEventProbe();
        this.objectMapper = serviceFactory.getObjectMapper();
        this.clientFactoryService = serviceFactory.getClientFactoryService();

        // TLS On/Off
        boolean tlsOnDvad =
                !Boolean.parseBoolean(
                        passportConfigurationService.getPassportParameterValue(
                                IS_DVAD_PERFORMANCE_STUB));

        boolean tlsOnDCS =
                !Boolean.parseBoolean(
                        passportConfigurationService.getPassportParameterValue(
                                IS_DCS_PERFORMANCE_STUB));

        // Done this way to allow switching if needed to lazy init + singletons
        thirdPartyAPIServices[DVAD] = createDvadThirdPartyAPIService(tlsOnDvad);
        thirdPartyAPIServices[DCS] = createDcsThirdPartyAPIService(tlsOnDCS);
    }

    private ThirdPartyAPIService createDvadThirdPartyAPIService(boolean tlsOn) {
        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getCloseableHttpClient(tlsOn, passportConfigurationService);

        // Reduces constructor load in DvadThirdPartyAPIService and allow endpoints to be mocked
        DvadAPIEndpointFactory dvadAPIEndpointFactory =
                new DvadAPIEndpointFactory(passportConfigurationService);

        return new DvadThirdPartyAPIService(
                dvadAPIEndpointFactory,
                passportConfigurationService,
                eventProbe,
                closeableHttpClient,
                objectMapper);
    }

    private ThirdPartyAPIService createDcsThirdPartyAPIService(boolean tlsOn) {
        CloseableHttpClient closeableHttpClient =
                clientFactoryService.getLegacyCloseableHttpClient(
                        tlsOn, passportConfigurationService);

        return new DcsThirdPartyAPIService(
                passportConfigurationService,
                eventProbe,
                new DcsCryptographyService(passportConfigurationService),
                closeableHttpClient);
    }

    public ThirdPartyAPIService getDvadThirdPartyAPIService() {
        return thirdPartyAPIServices[DVAD];
    }

    public ThirdPartyAPIService getDcsThirdPartyAPIService() {
        return thirdPartyAPIServices[DCS];
    }
}
