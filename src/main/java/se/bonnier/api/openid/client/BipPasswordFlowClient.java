package se.bonnier.api.openid.client;

import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

/**
 * Created by rene on 12/01/17.
 */
public class BipPasswordFlowClient extends SplusOpenIdClient {
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
}
