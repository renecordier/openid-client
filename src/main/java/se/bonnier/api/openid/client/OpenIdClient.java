package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

import javax.ws.rs.core.MediaType;

/**
 * @author vietnq
 */
public class OpenIdClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenIdClient.class);

    private WebResource resource;

    public OpenIdClient(String endpoint) {

        LOGGER.debug("OAuth2 endpoint " + endpoint);

        Client client = Client.create();
        resource = client.resource(endpoint);
    }

    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String scope,
                                             String grantType,
                                             String code,
                                             String redirectURI) throws BonnierOpenIdException {
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
}
