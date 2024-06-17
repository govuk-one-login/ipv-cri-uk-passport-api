package uk.gov.di.ipv.cri.passport.library.dvad.services;

import uk.gov.di.ipv.cri.passport.library.service.ParameterStoreService;

import java.util.Map;

public class DvadAPIHeaderValues {

    public static final String DVAD_HEADER_PARAMETER_PATH = "HMPODVAD/API/Header";

    public static final String MAP_KEY_APIKEY = "ApiKey"; // pragma: allowlist secret
    public static final String MAP_KEY_USERAGENT = "UserAgent";
    public static final String MAP_KEY_NETWORKTYPE = "NetworkType";
    public static final String MAP_KEY_CLIENTID = "ClientId";
    public static final String MAP_KEY_SECRET = "Secret"; // pragma: allowlist secret
    public static final String MAP_KEY_GRANTTYPE = "GrantType";

    public final String apiKey;
    public final String userAgent;
    public final String networkType;

    public final String clientId;
    public final String secret;

    public final String grantType;

    public DvadAPIHeaderValues(ParameterStoreService parameterStoreService) {
        Map<String, String> dvadHeaderParameterMap =
                parameterStoreService.getAllParametersFromPathWithDecryption(
                        DVAD_HEADER_PARAMETER_PATH);

        apiKey = dvadHeaderParameterMap.get(MAP_KEY_APIKEY);
        userAgent = dvadHeaderParameterMap.get(MAP_KEY_USERAGENT);
        networkType = dvadHeaderParameterMap.get(MAP_KEY_NETWORKTYPE);
        clientId = dvadHeaderParameterMap.get(MAP_KEY_CLIENTID);
        secret = dvadHeaderParameterMap.get(MAP_KEY_SECRET);
        grantType = dvadHeaderParameterMap.get(MAP_KEY_GRANTTYPE);
    }
}
