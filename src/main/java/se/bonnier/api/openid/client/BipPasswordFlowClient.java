package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

import javax.ws.rs.core.MediaType;

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
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("client_id", clientId);
            form.add("grant_type", "password");
            form.add("username", username);
            form.add("password", password);
            form.add("scope", scope);

            if(longLivedToken != null) {
                form.add("long_lived_token", longLivedToken.toString());
            }

            WebResource.Builder builder = resource.path("/token").accept(MediaType.APPLICATION_JSON);
            if(clientId == null) {
                builder.header("Authorization", "Bearer " + accessToken());
            }
            oauthResponse = builder.post(OAuth2Response.class, form);
        } catch (Exception ex) {
            OAuth2Response entity = ((UniformInterfaceException) ex).getResponse().getEntity(OAuth2Response.class);
            switch (entity.errorCode) {
                case CLIENT_ACTIVATION_PERIOD_EXPIRED:
                case UNAUTHORIZED:
                case INVALID_REQUEST:
                    throw new BonnierOpenIdException(entity.errorMsg);
                default:
                    throw new BonnierOpenIdException(ex);
            }
        }
        return oauthResponse;
    }
}
