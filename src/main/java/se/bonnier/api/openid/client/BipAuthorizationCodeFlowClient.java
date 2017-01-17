package se.bonnier.api.openid.client;

import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

/**
 * Created by rene on 11/01/17.
 */
public class BipAuthorizationCodeFlowClient extends SplusOpenIdClient {

    public BipAuthorizationCodeFlowClient(String endpoint, String clientId, String clientSecret) {
        super(endpoint, clientId, clientSecret);
    }

    public String getAuthorizeUrl(String authorizationRequestUri, String clientId, String redirectUri, String scope, String state,
                                  String nonce, String display, String lc, String loginHint, String cancelUri, String codeChallenge, String codeChallengeMethod) {
        String url = authorizationRequestUri + "?response_type=code";
        url += "&client_id=" + clientId;
        url += "&redirect_uri=" + redirectUri;
        url += "&scope=" + scope;
        url += state != null ? "&state=" + state : "";
        url += nonce != null ? "&nonce=" + nonce : "";
        url += display != null ? "&display=" + display : "";
        url += lc != null ? "&lc=" + lc : "";
        url += loginHint != null ? "&login_hint=" + loginHint : "";
        url += cancelUri != null ? "&cancel_uri=" + cancelUri : "";
        url += codeChallenge != null ? "&code_challenge=" + codeChallenge : "";
        url += codeChallengeMethod != null ? "&code_challenge_method=" + codeChallengeMethod : "";

        return url;
    }

    public String getLogoutUrl(String authorizationRequestUri, String appId, String postLogoutRedirectUri, String state) {
        String url = authorizationRequestUri;
        url += "?post_logout_redirect_uri=" + postLogoutRedirectUri;
        url += "&appId=" + appId;
        url += state != null ? "&state=" + state : "";

        return url;
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @param longLivedToken if token is long lived (30d) or not (8h)
     * @return OAuth2Response object
     * @throws se.bonnier.api.openid.exceptions.BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        return apiClient.requestAccessTokenFromCode(clientId, clientSecret, code, redirectURI, longLivedToken);
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code and PKCE (for client that cannot store a secret)
     * @param clientId S+ client Id
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @param longLivedToken if token is long lived (30d) or not (8h)
     * @param codeVerifier used for PKCE concept (in case client cannot store a secret)
     * @return OAuth2Response object
     * @throws se.bonnier.api.openid.exceptions.BonnierOpenIdException
     */
    public OAuth2Response requestAccessTokenWithPKCE(String clientId,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken,
                                             String codeVerifier) throws BonnierOpenIdException {
        return apiClient.requestAccessTokenFromCodePKCE(clientId, code, redirectURI, longLivedToken, codeVerifier);
    }

    public OAuth2Response refreshAccessToken(String refreshToken, String scope) throws BonnierOpenIdException {
        return refreshAccessToken(refreshToken, scope, null, null);
    }

    public OAuth2Response refreshAccessToken(String refreshToken, String scope, String clientId, String clientSecret) throws BonnierOpenIdException {
        return apiClient.refreshAccessToken(refreshToken, scope, clientId, clientSecret);
    }

    public OAuth2Response refreshPublicAccessToken(String refreshToken, String scope, String clientId) throws BonnierOpenIdException {
        return apiClient.refreshAccessToken(refreshToken, scope, clientId, null);
    }

    public void revokeAccessToken(String token) {
        revokeAccessToken(token, null, null);
    }

    public void revokeAccessToken(String token, String clientId, String clientSecret) {
        apiClient.revokeToken(token, clientId, clientSecret);
    }
}
