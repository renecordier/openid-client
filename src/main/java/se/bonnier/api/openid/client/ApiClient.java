package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;
import se.bonnier.api.openid.util.JwsUtil;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Created by rene on 13/01/17.
 */
public class ApiClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiClient.class);

    protected WebResource resource;
    private JwsUtil jwsUtil;

    private OAuth2Response oAuth2Response;
    private Long expireTime;
    private String clientId = "clientId";
    private String clientSecret = "clientSecret";

    public ApiClient(String endpoint) {

        LOGGER.debug("OAuth2 endpoint " + endpoint);

        Client client = Client.create();
        resource = client.resource(endpoint);
        jwsUtil = new JwsUtil(resource.path("/keys").getURI().toString());
    }

    public ApiClient(String endpoint, String clientId, String clientSecret) {
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

    public OAuth2Response requestClientAccessToken(String clientId,
                                                String clientSecret,
                                                String scope,
                                                Boolean longLivedToken) {
        return requestAccessToken(clientId, clientSecret, "client_credentials", null, null, scope,
                longLivedToken, null, null, null);
    }

    public OAuth2Response requestAccessTokenFromCode(String clientId,
                                             String clientSecret,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        return requestAccessToken(clientId, clientSecret, "authorization_code", code, redirectURI, null,
                longLivedToken, null, null, null);
    }

    public OAuth2Response requestAccessTokenFromCodePKCE(String clientId,
                                                     String code,
                                                     String redirectURI,
                                                     Boolean longLivedToken,
                                                     String codeVerifier) throws BonnierOpenIdException {
        return requestAccessToken(clientId, null, "authorization_code", code, redirectURI, null,
                longLivedToken, null, null, codeVerifier);
    }

    public OAuth2Response requestAccessTokenWithPassword(String clientId,
                                             String scope,
                                             String username,
                                             String password,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        return requestAccessToken(clientId, null, "password", null, null, scope,
                longLivedToken, username, password, null);
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @param grantType the grant type of the flow
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @param longLivedToken if token is long lived (30d) or not (8h)
     * @param codeVerifier used for PKCE concept (in case client cannot store a secret)
     * @return OAuth2Response object
     * @throws se.bonnier.api.openid.exceptions.BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String grantType,
                                             String code,
                                             String redirectURI,
                                             String scope,
                                             Boolean longLivedToken,
                                             String username,
                                             String password,
                                             String codeVerifier) throws BonnierOpenIdException {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("client_id", clientId);
            form.add("grant_type", grantType);
            form.add("long_lived_token",longLivedToken.toString());
            form.add("client_secret", clientSecret);
            form.add("redirect_uri", redirectURI);
            form.add("code", code);
            form.add("scope", scope);
            form.add("username", username);
            form.add("password", password);
            form.add("code_verifier", codeVerifier);

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

    public boolean validateToken(String token) throws BonnierOpenIdException {
        boolean valid = false;
        try {
            WebResource.Builder builder = resource.path("/validate").queryParam("access_token", token).accept(MediaType.APPLICATION_JSON);
            ClientResponse response = builder.get(ClientResponse.class);

            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                valid = true;
            }
        } catch (Exception ex) {
            throw new BonnierOpenIdException(ex);
        }
        return valid;
    }

    public void invalidateAccessToken(String invalidateToken, String accessToken) {
        Form form = new Form();
        form.add("invalidate_token", invalidateToken);
        form.add("access_token", accessToken);
        WebResource.Builder builder = resource.path("/invalidate").accept(MediaType.APPLICATION_JSON);
        ClientResponse response = builder.post(ClientResponse.class, form);
        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
            LOGGER.debug("Error invalidate token : " + invalidateToken);
        } else {
            LOGGER.debug("Success invalidate token : " + invalidateToken);
        }
    }

    public void revokeToken(String token, String clientId, String clientSecret) {
        Form form = new Form();
        form.add("token", token);
        form.add("token_type_hint", "access_token");

        WebResource.Builder builder = resource.path("/revoke").accept(MediaType.APPLICATION_JSON);
        if(clientId == null && clientSecret == null) {
            builder.header("Authorization", "Bearer " + accessToken());
        } else {
            form.add("client_id", clientId);
            if(clientSecret != null) {
                form.add("client_secret", clientSecret);
            }
        }

        ClientResponse response = builder.post(ClientResponse.class, form);
        if (response.getStatus() != Response.Status.OK.getStatusCode()) {
            LOGGER.debug("Error revoke token : " + token);
        } else {
            LOGGER.debug("Success revoke token : " + token);
        }
    }

    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return jwsUtil.verifyContent(idToken, clientId, resource.path("/keys").getURI().toString());
    }

    public JSONObject getUserInfo(String accessToken) {
        WebResource.Builder builder = resource.path("/userinfo").accept(MediaType.APPLICATION_JSON);
        builder.header("Authorization", "Bearer " + accessToken);
        ClientResponse response = builder.get(ClientResponse.class);

        JSONObject json = response.getEntity(JSONObject.class);

        return json;
    }


}
