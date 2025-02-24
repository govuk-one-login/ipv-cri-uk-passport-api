package uk.gov.di.ipv.cri.passport.library.dvad.domain.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AccessTokenResponse(
        @JsonProperty(value = "access_token", required = true) String accessToken,
        @JsonProperty(value = "token_type", required = true) String tokenType,
        @JsonProperty(value = "expires_in", required = true) long expiresIn,
        @JsonProperty(value = "refresh_token", required = false) String refreshToken,
        @JsonProperty(value = "refresh_expires_in", required = false) long refreshExpiresIn,
        @JsonProperty(value = "scope", required = false) String scope) {

    public static AccessTokenResponseBuilder builder() {
        return new AccessTokenResponseBuilder();
    }

    public static class AccessTokenResponseBuilder {
        private String accessToken;
        private String tokenType;
        private long expiresIn;
        private String refreshToken;
        private long refreshExpiresIn;
        private String scope;

        private AccessTokenResponseBuilder() {
            // Intended
        }

        public AccessTokenResponseBuilder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public AccessTokenResponseBuilder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public AccessTokenResponseBuilder expiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public AccessTokenResponseBuilder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public AccessTokenResponseBuilder refreshExpiresIn(long refreshExpiresIn) {
            this.refreshExpiresIn = refreshExpiresIn;
            return this;
        }

        public AccessTokenResponseBuilder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public AccessTokenResponse build() {
            return new AccessTokenResponse(
                    accessToken, tokenType, expiresIn, refreshToken, refreshExpiresIn, scope);
        }
    }
}
