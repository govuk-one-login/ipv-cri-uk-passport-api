package uk.gov.di.ipv.cri.passport.library.dvad.domain.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@Builder
public class AccessTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("refresh_expires_in")
    private long refreshExpiresIn;

    @JsonProperty("scope")
    private String scope;

    @JsonCreator
    public AccessTokenResponse(
            @JsonProperty(value = "access_token", required = true) String accessToken,
            @JsonProperty(value = "token_type", required = true) String tokenType,
            @JsonProperty(value = "expires_in", required = true) long expiresIn,
            @JsonProperty(value = "refresh_token", required = false) String refreshToken,
            @JsonProperty(value = "refresh_expires_in", required = false) long refreshExpiresIn,
            @JsonProperty(value = "scope", required = false) String scope) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.refreshExpiresIn = refreshExpiresIn;
        this.scope = scope;
    }
}
