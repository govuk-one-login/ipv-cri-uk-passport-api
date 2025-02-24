package uk.gov.di.ipv.cri.passport.library.dvad.services;

import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.AccessTokenResponseCacheExpiryWindowException;

import java.time.Instant;

public record AccessTokenResponseCache(
        AccessTokenResponse cachedAccessTokenResponse, long maxAllowedAccessTokenLifetimeSeconds) {
    public static final String INVALID_EXPIRY_WINDOW_ERROR_MESSAGE =
            "AccessTokenResponseCache expiry window not valid";

    public boolean isNearExpiration(long expiryWindow) {

        if (expiryWindow <= 0 || expiryWindow >= maxAllowedAccessTokenLifetimeSeconds) {
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
        long expiresIn = cachedAccessTokenResponse.expiresIn();

        return Instant.now().plusSeconds(expiresIn).toEpochMilli();
    }
}
