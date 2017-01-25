package se.bonnier.api.openid.client;

import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

/**
 * Class for using Password credentials flow
 * Created by rene on 12/01/17.
 */
public class BipPasswordFlowClient extends SplusOpenIdClient {
    /**
     * Constructor
     * @param endpoint the oauth2 endpoint to access the API
     */
    public BipPasswordFlowClient(String endpoint) {
        super(endpoint);
    }

    /**
     * Requests access token from Bonnier Identity Provider using password grant type flow
     * @param clientId S+ client Id
     * @param scope OpenId scope
     * @param username user name credentials
     * @param password password credentials
     * @param longLivedToken long lived token or not
     * @return OAuth2Response object
     * @throws se.bonnier.api.openid.exceptions.BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String scope,
                                             String username,
                                             String password,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        return apiClient.requestAccessTokenWithPassword(clientId, scope, username, password, longLivedToken);
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
     * @param clientId S+ client Id
     */
    public void revokeAccessToken(String token, String clientId) {
        apiClient.revokeToken(token, clientId, null);
    }
}
