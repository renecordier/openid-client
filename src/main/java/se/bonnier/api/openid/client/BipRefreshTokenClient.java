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
public class BipRefreshTokenClient extends SplusOpenIdClient {
    public BipRefreshTokenClient(String endpoint, String clientId, String clientSecret) {
        super(endpoint, clientId, clientSecret);
    }

    public OAuth2Response refreshAccessToken(String refreshToken, String scope) throws BonnierOpenIdException {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            if (scope != null) {
                form.add("scope", scope);
            }

            WebResource.Builder builder = resource.path("/token").accept(MediaType.APPLICATION_JSON);
            builder.header("Authorization", "Bearer " + accessToken());
            oauthResponse = builder.post(OAuth2Response.class, form);
        } catch (Exception ex) {
            OAuth2Response entity = ((UniformInterfaceException) ex).getResponse().getEntity(OAuth2Response.class);
            switch (entity.errorCode) {
                case CLIENT_ACTIVATION_PERIOD_EXPIRED:
                case UNAUTHORIZED:
                case UNAUTHORIZED_SCOPE:
                case INVALID_REQUEST:
                case TOKEN_EXPIRED:
                    throw new BonnierOpenIdException(entity.errorMsg);
                default:
                    throw new BonnierOpenIdException(ex);
            }
        }
        return oauthResponse;
    }
}
