package uk.gov.di.ipv.cri.passport.library.config;

import org.apache.http.client.config.RequestConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class HttpRequestConfigTest {

    @Test
    void shouldCreateHttpRequestConfigWithExpectedDefaultValues() {
        RequestConfig defaultRequestConfig = new HttpRequestConfig().getDefaultRequestConfig();

        // Connection Pool
        assertEquals(5000, defaultRequestConfig.getConnectTimeout());
        // Connection
        assertEquals(5000, defaultRequestConfig.getConnectionRequestTimeout());
        // Read timeout
        assertEquals(10000, defaultRequestConfig.getSocketTimeout());
    }
}
