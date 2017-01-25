package se.bonnier.api.openid.client;

import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

/**
 * Class for using the Bip Authorization code flow
 * Created by rene on 11/01/17.
 */
public class BipAuthorizationCodeFlowClient extends SplusOpenIdClient {

    /**
     * Constructor
     * @param endpoint the oauth2 endpoint to access the API
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     */
    public BipAuthorizationCodeFlowClient(String endpoint, String clientId, String clientSecret) {
        super(endpoint, clientId, clientSecret);
    }

    /**
     * Builds the authorize url with all the parameters needed
     * @param authorizationRequestUri the authorization endpoint url
     * @param clientId S+ client Id
     * @param redirectUri the redirect link to handle the response back from the server
     * @param scope the scope of the access
     * @param state random value to maintain the state between request and response
     * @param nonce unique value generated to prevent from replay attacks
     * @param display full display or iframe display (if user not logged in)
     * @param lc locale
     * @param loginHint To preffil the email on the login form (if user not logged in)
     * @param cancelUri Cancel callback url
     * @param codeChallenge A one time random generated string, result of the encryption method used
     * @param codeChallengeMethod The encryption method used for the code challenge
     * @return thhe built authorize url
     */
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

    /**
     * Builds the logout url with all the parameters needed
     * @param authorizationRequestUri the logout endpoint url
     * @param appId the application id of the client website
     * @param postLogoutRedirectUri the redirect link to handle the response back from the server
     * @param state random value to maintain the state between request and response
     * @return the build logout url
     */
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

    /**
     * Refresh access token
     * @param refreshToken the token needed to refresh the access token
     * @param scope if want to restrict the scope more than the initial one
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response refreshAccessToken(String refreshToken, String scope) throws BonnierOpenIdException {
        return refreshAccessToken(refreshToken, scope, null, null);
    }

    /**
     * Refresh access token
     * @param refreshToken the token needed to refresh the access token
     * @param scope if want to restrict the scope more than the initial one
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response refreshAccessToken(String refreshToken, String scope, String clientId, String clientSecret) throws BonnierOpenIdException {
        return apiClient.refreshAccessToken(refreshToken, scope, clientId, clientSecret);
    }

    /**
     * Refresh access token (public client)
     * @param refreshToken the token needed to refresh the access token
     * @param scope if want to restrict the scope more than the initial one
     * @param clientId S+ client Id
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response refreshPublicAccessToken(String refreshToken, String scope, String clientId) throws BonnierOpenIdException {
        return apiClient.refreshAccessToken(refreshToken, scope, clientId, null);
    }

    /**
     * Revoke access token
     * @param token access token to revoke
     */
    public void revokeAccessToken(String token) {
        revokeAccessToken(token, null, null);
    }

    /**
     * Revoke access token
     * @param token access token to revoke
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     */
    public void revokeAccessToken(String token, String clientId, String clientSecret) {
        apiClient.revokeToken(token, clientId, clientSecret);
    }
}
