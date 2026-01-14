package uk.gov.di.ipv.cri.passport.library.dvad.services;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.AccessTokenResponseCacheExpiryWindowException;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.cri.passport.library.dvad.services.AccessTokenResponseCache.INVALID_EXPIRY_WINDOW_ERROR_MESSAGE;

@Tag("QualityGateUnitTest")
@ExtendWith(MockitoExtension.class)
class AccessTokenResponseCacheTest {

    @ParameterizedTest
    @CsvSource({"300", "600", "1200", "1800"})
    void shouldTokenCalculateExpiryCorrectly(long tokenExpiresIn) {

        AccessTokenResponse accessTokenResponse =
                AccessTokenResponse.builder()
                        .accessToken("TOKEN")
                        .expiresIn(tokenExpiresIn)
                        .refreshToken(null)
                        .refreshExpiresIn(0)
                        .scope("NA")
                        .build();

        AccessTokenResponseCache accessTokenResponseCache =
                new AccessTokenResponseCache(accessTokenResponse, 1800L);

        long expectedExpires = Instant.now().plusSeconds(tokenExpiresIn).toEpochMilli();
        long actualExpires = accessTokenResponseCache.getExpiresTime();

        assertEquals(
                expectedExpires, actualExpires, 100); // Delta to account for unit test run speed
    }

    @ParameterizedTest
    @CsvSource({
        "0, 60, true", // Token is expired by default
        "59,60, true", // Token expires just inside window
        "60,60, true", // Token expires at start of window
        "30, 60, true", // Token expires in middle of window
        "61,60, false"
    }) // Token expires just outside window
    void shouldTokenReturnTokenIsExpiredWhenTokenExpiryIsWithinExpiryWindow(
            long tokenExpiresIn, long expiryWindow, boolean expired) {

        AccessTokenResponse accessTokenResponse =
                AccessTokenResponse.builder().expiresIn(tokenExpiresIn).build();

        AccessTokenResponseCache accessTokenResponseCache =
                new AccessTokenResponseCache(accessTokenResponse, 1800L);

        assertEquals(expired, accessTokenResponseCache.isNearExpiration(expiryWindow));
    }

    @ParameterizedTest
    @CsvSource({"-1", "0", "1800", "1801"}) // Token expires just outside window
    void shouldThrowExceptionForInvalidExpiryWindow(long expiryWindow) {

        AccessTokenResponse accessTokenResponse =
                AccessTokenResponse.builder().expiresIn(1800).build();

        AccessTokenResponseCache accessTokenResponseCache =
                new AccessTokenResponseCache(accessTokenResponse, 1800L);

        AccessTokenResponseCacheExpiryWindowException expectedReturnedException =
                new AccessTokenResponseCacheExpiryWindowException(
                        INVALID_EXPIRY_WINDOW_ERROR_MESSAGE);

        AccessTokenResponseCacheExpiryWindowException thrownException =
                Assertions.assertThrows(
                        AccessTokenResponseCacheExpiryWindowException.class,
                        () -> accessTokenResponseCache.isNearExpiration(expiryWindow),
                        "An Error Message");

        Assertions.assertEquals(
                expectedReturnedException.getMessage(), thrownException.getMessage());
    }
}
