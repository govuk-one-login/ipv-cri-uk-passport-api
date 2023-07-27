package uk.gov.di.ipv.cri.passport.checkpassport.services.dvad;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.AccessTokenResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.AccessTokenResponseCacheExpiryWindowException;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.cri.passport.checkpassport.services.dvad.AccessTokenResponseCache.INVALID_EXPIRY_WINDOW_ERROR_MESSAGE;

@ExtendWith(MockitoExtension.class)
class AccessTokenResponseCacheTest {

    @ParameterizedTest
    @CsvSource({"300", "600", "1200", "1800"})
    void shouldTokenCalculateExpiryCorrectly(long tokenExpiresIn) {

        AccessTokenResponse accessTokenResponse =
                AccessTokenResponse.builder().expiresIn(tokenExpiresIn).build();

        AccessTokenResponseCache accessTokenResponseCache =
                new AccessTokenResponseCache(accessTokenResponse);

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
                new AccessTokenResponseCache(accessTokenResponse);

        assertEquals(expired, accessTokenResponseCache.isNearExpiration(expiryWindow));
    }

    @ParameterizedTest
    @CsvSource({"-1", "0", "1800", "1801"}) // Token expires just outside window
    void shouldThrowExceptionForInvalidExpiryWindow(long expiryWindow) {

        AccessTokenResponse accessTokenResponse =
                AccessTokenResponse.builder().expiresIn(1800).build();

        AccessTokenResponseCache accessTokenResponseCache =
                new AccessTokenResponseCache(accessTokenResponse);

        AccessTokenResponseCacheExpiryWindowException expectedReturnedException =
                new AccessTokenResponseCacheExpiryWindowException(
                        INVALID_EXPIRY_WINDOW_ERROR_MESSAGE);

        AccessTokenResponseCacheExpiryWindowException thrownException =
                assertThrows(
                        AccessTokenResponseCacheExpiryWindowException.class,
                        () -> accessTokenResponseCache.isNearExpiration(expiryWindow),
                        "An Error Message");

        assertEquals(expectedReturnedException.getMessage(), thrownException.getMessage());
    }
}
