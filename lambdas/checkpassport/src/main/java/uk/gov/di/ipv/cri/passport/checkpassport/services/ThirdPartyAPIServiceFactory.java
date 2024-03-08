package uk.gov.di.ipv.cri.passport.checkpassport.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DVADCloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.library.service.ClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

public class ThirdPartyAPIServiceFactory {
    private final EventProbe eventProbe;
    private final ObjectMapper objectMapper;

    private final ParameterStoreService parameterStoreService;

    public final ClientFactoryService clientFactoryService;

    // Formerly DVAD(0)+DCS(1)
    private static final int DVAD = 0;
    private final ThirdPartyAPIService[] thirdPartyAPIServices = new ThirdPartyAPIService[1];

    // TLS On/Off
    private final boolean tlsOn =
            !Boolean.parseBoolean(System.getenv("DVAD_PERFORMANCE_STUB_IN_USE"));

    public ThirdPartyAPIServiceFactory(ServiceFactory serviceFactory) {
        this.parameterStoreService = serviceFactory.getParameterStoreService();
        this.eventProbe = serviceFactory.getEventProbe();
        this.objectMapper = serviceFactory.getObjectMapper();
        this.clientFactoryService = serviceFactory.getClientFactoryService();

        // Done this way to allow switching if needed to lazy init + singletons
        thirdPartyAPIServices[DVAD] = createDvadThirdPartyAPIService();
    }

    private ThirdPartyAPIService createDvadThirdPartyAPIService() {

        CloseableHttpClient closeableHttpClient =
                new DVADCloseableHttpClientFactory()
                        .getClient(tlsOn, parameterStoreService, clientFactoryService);

        // Reduces constructor load in DvadThirdPartyAPIService and allow endpoints to be mocked
        DvadAPIEndpointFactory dvadAPIEndpointFactory =
                new DvadAPIEndpointFactory(parameterStoreService);

        return new DvadThirdPartyAPIService(
                dvadAPIEndpointFactory,
                parameterStoreService,
                eventProbe,
                closeableHttpClient,
                objectMapper);
    }

    public ThirdPartyAPIService getDvadThirdPartyAPIService() {
        return thirdPartyAPIServices[DVAD];
    }
}
