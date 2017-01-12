package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;
import se.bonnier.api.openid.util.JwsUtil;

import javax.ws.rs.core.MediaType;

/**
 * @author vietnq
 */
public abstract class SplusOpenIdClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SplusOpenIdClient.class);

    protected WebResource resource;
    private JwsUtil jwsUtil;

    private OAuth2Response oAuth2Response;
    private Long expireTime;
    private String clientId = "clientId";
    private String clientSecret = "clientSecret";

    public SplusOpenIdClient(String endpoint) {

        LOGGER.debug("OAuth2 endpoint " + endpoint);

        Client client = Client.create();
        resource = client.resource(endpoint);
        jwsUtil = new JwsUtil(resource.path("/keys").getURI().toString());
    }

    public SplusOpenIdClient(String endpoint, String clientId, String clientSecret) {
        this(endpoint);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    protected String accessToken() {
        if (oAuth2Response == null || expireTime <= System.currentTimeMillis()) {
            try {
                expireTime = System.currentTimeMillis();
                oAuth2Response = requestClientAccessToken(clientId, clientSecret, "openid", false);
                expireTime += oAuth2Response.expiresIn * 1000L;
            } catch (Exception e) {
                LOGGER.info("Can not create new client access token", e);
            }
        }
        return oAuth2Response.accessToken;
    }

    private OAuth2Response requestClientAccessToken(String clientId,
                                                    String clientSecret,
                                                    String scope,
                                                    Boolean longLivedToken) {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);
            form.add("grant_type", "client_credentials");
            form.add("long_lived_token",longLivedToken.toString());
            form.add("scope", scope);

            WebResource.Builder builder = resource.path("/token").accept(MediaType.APPLICATION_JSON);
            oauthResponse = builder.post(OAuth2Response.class, form);
        } catch (Exception ex) {
            OAuth2Response entity = ((UniformInterfaceException) ex).getResponse().getEntity(OAuth2Response.class);
            throw new BonnierOpenIdException(entity.errorMsg);
        }
        return oauthResponse;
    }

    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return jwsUtil.verifyContent(idToken, clientId, resource.path("/keys").getURI().toString());
    }
}
