package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import uk.gov.di.ipv.cri.passport.library.service.PassportConfigurationService;

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

    public DvadAPIHeaderValues(PassportConfigurationService passportConfigurationService) {
        apiKey = passportConfigurationService.getEncryptedSsmParameter(HMPO_API_HEADER_API_KEY);
        userAgent = passportConfigurationService.getParameterValue(HMPO_API_HEADER_USER_AGENT);
        networkType = passportConfigurationService.getParameterValue(HMPO_API_HEADER_NETWORK_TYPE);

        clientId = passportConfigurationService.getParameterValue(HMPO_API_HEADER_CLIENT_ID);
        secret = passportConfigurationService.getParameterValue(HMPO_API_HEADER_SECRET);

        grantType = passportConfigurationService.getParameterValue(HMPO_API_HEADER_GRANT_TYPE);
    }
}
