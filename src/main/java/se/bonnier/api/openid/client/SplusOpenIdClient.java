package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;
import se.bonnier.api.openid.util.JwsUtil;

import javax.ws.rs.core.MediaType;

/**
 * @author vietnq
 */
public class SplusOpenIdClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SplusOpenIdClient.class);

    private WebResource resource;
    private JwsUtil jwsUtil;

    public SplusOpenIdClient(String endpoint) {

        LOGGER.debug("OAuth2 endpoint " + endpoint);

        Client client = Client.create();
        resource = client.resource(endpoint);
        jwsUtil = new JwsUtil(resource.path("/keys").getURI().toString());
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @param scope OpenId scope
     * @param grantType must be set to authorization_code
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String scope,
                                             String grantType,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);
            form.add("grant_type", grantType);
            form.add("redirect_uri", redirectURI);

            if (scope != null) {
                form.add("scope", scope);
            }
            if (code != null) {
                form.add("code", code);
            }

            form.add("long_lived_token",longLivedToken.toString());

            WebResource.Builder builder = resource.path("/token").accept(MediaType.APPLICATION_JSON);
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

    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return jwsUtil.verifyContent(idToken, clientId, resource.path("/keys").getURI().toString());
    }
}
