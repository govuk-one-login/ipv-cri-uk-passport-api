package uk.gov.di.ipv.cri.passport.checkpassport.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.impl.client.CloseableHttpClient;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DVADCloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.library.service.ApacheHTTPClientFactoryService;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

public class ThirdPartyAPIServiceFactory {
    private final EventProbe eventProbe;
    private final ObjectMapper objectMapper;

    private final ParameterStoreService parameterStoreService;

    public final ApacheHTTPClientFactoryService apacheHTTPClientFactoryService;

    // UAT/LIVE DVAD(0) - STUB DVAD(1)
    private static final int DVAD = 0;
    private static final int STUB = 1;
    private final ThirdPartyAPIService[] thirdPartyAPIServices = new ThirdPartyAPIService[2];

    public ThirdPartyAPIServiceFactory(ServiceFactory serviceFactory)
            throws JsonProcessingException {
        this.parameterStoreService = serviceFactory.getParameterStoreService();
        this.eventProbe = serviceFactory.getEventProbe();
        this.objectMapper = serviceFactory.getObjectMapper();
        this.apacheHTTPClientFactoryService = serviceFactory.getApacheHTTPClientFactoryService();

        // Done this way to allow switching if needed to lazy init + singletons
        thirdPartyAPIServices[DVAD] = createDvadThirdPartyAPIService();
        thirdPartyAPIServices[STUB] = createDvadThirdPartyAPIServiceForStub();
    }

    private ThirdPartyAPIService createDvadThirdPartyAPIService() throws JsonProcessingException {

        CloseableHttpClient closeableHttpClient =
                new DVADCloseableHttpClientFactory()
                        .getClient(true, parameterStoreService, apacheHTTPClientFactoryService);

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

    private ThirdPartyAPIService createDvadThirdPartyAPIServiceForStub()
            throws JsonProcessingException {

        CloseableHttpClient closeableHttpClient =
                new DVADCloseableHttpClientFactory()
                        .getClient(false, parameterStoreService, apacheHTTPClientFactoryService);

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

    public ThirdPartyAPIService getDvadThirdPartyAPIServiceForStub() {
        return thirdPartyAPIServices[STUB];
    }
}
