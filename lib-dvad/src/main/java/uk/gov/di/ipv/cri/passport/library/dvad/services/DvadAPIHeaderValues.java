package uk.gov.di.ipv.cri.passport.library.dvad.services;

import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_API_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_CLIENT_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_GRANT_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_NETWORK_TYPE;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_SECRET;
import static uk.gov.di.ipv.cri.passport.library.config.ParameterStoreParameters.HMPO_API_HEADER_USER_AGENT;

public class DvadAPIHeaderValues {
    public final String apiKey;
    public final String userAgent;
    public final String networkType;

    public final String clientId;
    public final String secret;

    public final String grantType;

    public DvadAPIHeaderValues(ParameterStoreService parameterStoreService) {
        apiKey = parameterStoreService.getEncryptedParameterValue(HMPO_API_HEADER_API_KEY);
        userAgent = parameterStoreService.getParameterValue(HMPO_API_HEADER_USER_AGENT);
        networkType = parameterStoreService.getParameterValue(HMPO_API_HEADER_NETWORK_TYPE);

        clientId = parameterStoreService.getParameterValue(HMPO_API_HEADER_CLIENT_ID);
        secret = parameterStoreService.getParameterValue(HMPO_API_HEADER_SECRET);

        grantType = parameterStoreService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE);
    }
}
