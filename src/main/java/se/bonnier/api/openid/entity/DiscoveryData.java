package se.bonnier.api.openid.entity;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * Created by rene on 23/01/17.
 */
public class DiscoveryData {
    @JsonProperty("issuer")
    private String issuer;
    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;
    @JsonProperty("token_endpoint")
    private String tokenEndpoint;
    @JsonProperty("userinfo_endpoint")
    private String userinfoEndpoint;
    @JsonProperty("revocation_endpoint")
    private String revocationEndpoint;
    @JsonProperty("check_session_iframe")
    private String checkSessionIframe;
    @JsonProperty("end_session_endpoint")
    private String endSessionEndpoint;
    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;
    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported;
    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported;
    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;
    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;
    @JsonProperty("claims_supported")
    private List<String> claimsSupported;

    @JsonProperty("frontchannel_logout_supported")
    private boolean frontchannelLogoutSupported;
    @JsonProperty("frontchannel_logout_session_supported")
    private boolean frontchannelLogoutSessionSupported;
    @JsonProperty("backchannel_logout_supported")
    private boolean backchannelLogoutSupported;
    @JsonProperty("backchannel_logout_session_supported")
    private boolean backchannelLogoutSessionSupported;

    //private List<String> response_types_supported;
    //private List<String> subject_types_supported;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    public void setRevocationEndpoint(String revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
    }

    public String getCheckSessionIframe() {
        return checkSessionIframe;
    }

    public void setCheckSessionIframe(String checkSessionIframe) {
        this.checkSessionIframe = checkSessionIframe;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

}
