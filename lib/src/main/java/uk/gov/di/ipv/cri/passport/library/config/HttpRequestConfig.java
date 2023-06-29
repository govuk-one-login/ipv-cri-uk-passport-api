package uk.gov.di.ipv.cri.passport.library.config;

import org.apache.http.client.config.RequestConfig;

/** A shared RequestConfig applied to each http request to DCS/DVAD ThirdPartyAPI endpoints. */
public class HttpRequestConfig {

    // HTTP client connection stage timeouts Totals are additive.

    // Initial connection attempt
    private static final int HTTP_INITIAL_CONNECTION_TIMEOUT_MS = 5000;

    // Reading a packet
    private static final int HTTP_SOCKET_READ_TIMEOUT_MS = 5000;

    // Requesting a connection from the http clients connection pool
    private static final int HTTP_CONN_POOL_REQ_TIMEOUT_MS = 5000;

    /**
     * Prevents waiting until the lambda timeout is reached when there are connection issues.
     *
     * @return RequestConfig
     */
    public RequestConfig getDefaultRequestConfig() {
        // RequestConfig is set per request to apply the timeouts
        // Only socket read maters if the HTTP client is able to re-use a connection
        return RequestConfig.custom()
                .setConnectTimeout(HTTP_INITIAL_CONNECTION_TIMEOUT_MS)
                .setSocketTimeout(HTTP_SOCKET_READ_TIMEOUT_MS)
                .setConnectionRequestTimeout(HTTP_CONN_POOL_REQ_TIMEOUT_MS)
                .build();
    }
}
