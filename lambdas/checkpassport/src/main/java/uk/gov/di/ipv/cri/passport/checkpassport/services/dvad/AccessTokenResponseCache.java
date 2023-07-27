package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import lombok.Data;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.AccessTokenResponseCacheExpiryWindowException;

import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.endpoints.TokenRequestService.MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS;

@Data
public class AccessTokenResponseCache {
    public static final String INVALID_EXPIRY_WINDOW_ERROR_MESSAGE =
            "AccessTokenResponseCache expiry window not valid";

    private final AccessTokenResponse cachedAccessTokenResponse;

    public boolean isNearExpiration(long expiryWindow) {

        if (expiryWindow <= 0 || expiryWindow >= MAX_ALLOWED_ACCESS_TOKEN_LIFETIME_SECONDS) {
            throw new AccessTokenResponseCacheExpiryWindowException(
                    INVALID_EXPIRY_WINDOW_ERROR_MESSAGE);
        }

        long expiresTime = getExpiresTime();

        long now = Instant.now().toEpochMilli();

        long windowStart =
                Instant.ofEpochMilli(expiresTime).minusSeconds(expiryWindow).toEpochMilli();

        return now >= windowStart;
    }

    public long getExpiresTime() {
        long expiresIn = cachedAccessTokenResponse.getExpiresIn();

        return Instant.now().plusSeconds(expiresIn).toEpochMilli();
    }
}
