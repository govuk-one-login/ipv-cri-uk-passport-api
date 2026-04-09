package uk.gov.di.ipv.cri.passport.checkpassport.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DVADCloseableHttpClientFactory;
import uk.gov.di.ipv.cri.passport.library.dvad.services.DvadThirdPartyAPIService;
import uk.gov.di.ipv.cri.passport.library.dvad.services.endpoints.DvadAPIEndpointFactory;
import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;
import uk.gov.di.ipv.cri.passport.library.service.ThirdPartyAPIService;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ThirdPartyAPIServiceFactoryTest {

    @Mock private ServiceFactory mockServiceFactory;
    @Mock private ParameterStoreService mockParameterStoreService;
    @Mock private EventProbe mockEventProbe;
    @Mock private ObjectMapper mockObjectMapper;
    @Mock private CloseableHttpClient mockHttpClient;

    @SuppressWarnings("java:S1481") // httpClientFactoryMock / endpointFactoryMock
    private ThirdPartyAPIServiceFactory createFactory() throws JsonProcessingException {
        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);
        when(mockServiceFactory.getObjectMapper()).thenReturn(mockObjectMapper);

        try (MockedConstruction<DVADCloseableHttpClientFactory> httpClientFactoryMock =
                        mockConstruction(
                                DVADCloseableHttpClientFactory.class,
                                (mock, context) ->
                                        when(mock.getClient(
                                                        anyBoolean(),
                                                        eq(mockParameterStoreService)))
                                                .thenReturn(mockHttpClient));
                MockedConstruction<DvadAPIEndpointFactory> endpointFactoryMock =
                        mockConstruction(DvadAPIEndpointFactory.class)) {

            return new ThirdPartyAPIServiceFactory(mockServiceFactory);
        }
    }

    @Test
    void shouldCreateFactorySuccessfully() throws JsonProcessingException {
        ThirdPartyAPIServiceFactory factory = createFactory();
        assertNotNull(factory);
    }

    @Test
    void shouldReturnDvadThirdPartyAPIService() throws JsonProcessingException {
        ThirdPartyAPIServiceFactory factory = createFactory();

        ThirdPartyAPIService service = factory.getDvadThirdPartyAPIService();

        assertNotNull(service);
        assertInstanceOf(DvadThirdPartyAPIService.class, service);
    }

    @Test
    void shouldReturnDvadThirdPartyAPIServiceForStub() throws JsonProcessingException {
        ThirdPartyAPIServiceFactory factory = createFactory();

        ThirdPartyAPIService service = factory.getDvadThirdPartyAPIServiceForStub();

        assertNotNull(service);
        assertInstanceOf(DvadThirdPartyAPIService.class, service);
    }

    @Test
    void shouldReturnDifferentServicesForDvadAndStub() throws JsonProcessingException {
        ThirdPartyAPIServiceFactory factory = createFactory();

        ThirdPartyAPIService dvadService = factory.getDvadThirdPartyAPIService();
        ThirdPartyAPIService stubService = factory.getDvadThirdPartyAPIServiceForStub();

        assertNotSame(dvadService, stubService);
    }

    @Test
    @SuppressWarnings("java:S1481") // ignored
    void shouldCreateHttpClientWithTlsOnForDvad() throws JsonProcessingException {
        when(mockServiceFactory.getParameterStoreService()).thenReturn(mockParameterStoreService);
        when(mockServiceFactory.getEventProbe()).thenReturn(mockEventProbe);
        when(mockServiceFactory.getObjectMapper()).thenReturn(mockObjectMapper);

        try (MockedConstruction<DVADCloseableHttpClientFactory> httpClientFactoryMock =
                        mockConstruction(
                                DVADCloseableHttpClientFactory.class,
                                (mock, context) ->
                                        when(mock.getClient(
                                                        anyBoolean(),
                                                        eq(mockParameterStoreService)))
                                                .thenReturn(mockHttpClient));
                MockedConstruction<DvadAPIEndpointFactory> ignored =
                        mockConstruction(DvadAPIEndpointFactory.class)) {

            new ThirdPartyAPIServiceFactory(mockServiceFactory);

            DVADCloseableHttpClientFactory constructedFactory =
                    httpClientFactoryMock.constructed().get(0);
            verify(constructedFactory).getClient(true, mockParameterStoreService);
            verify(constructedFactory).getClient(false, mockParameterStoreService);
        }
    }
}
