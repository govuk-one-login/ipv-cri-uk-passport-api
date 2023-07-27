package uk.gov.di.ipv.cri.passport.library.exceptions;

public class AccessTokenResponseCacheExpiryWindowException extends RuntimeException {
    public AccessTokenResponseCacheExpiryWindowException(String message) {
        super(message);
    }
}
