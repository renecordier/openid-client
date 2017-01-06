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
                oAuth2Response = requestAccessToken(clientId, clientSecret, "openid", "client_credentials", "", "", false, null);
                expireTime += oAuth2Response.expiresIn * 1000L;
            } catch (Exception e) {
                LOGGER.info("Can not create new client access token", e);
            }
        }
        return oAuth2Response.accessToken;
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @param scope OpenId scope
     * @param grantType must be set to authorization_code
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @param longLivedToken if token is long lived (30d) or not (8h)
     * @param codeVerifier used for PKCE concept (in case client cannot store a secret)
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String scope,
                                             String grantType,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken,
                                             String codeVerifier) throws BonnierOpenIdException {
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
            if(codeVerifier != null){
                form.add("code_verifier", codeVerifier);
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

    /**
     * Requests access token from Bonnier Identity Provider using password grant type flow
     * @param clientId S+ client Id
     * @param scope OpenId scope
     * @param grantType must be set to password
     * @param username user name credentials
     * @param password password credentials
     * @param longLivedToken long lived token or not
     * @return OAuth2Response object
     * @throws BonnierOpenIdException
     */
    public OAuth2Response requestAccessTokenWithPasswordFlow(String clientId,
                                             String scope,
                                             String grantType,
                                             String username,
                                             String password,
                                             Boolean longLivedToken) throws BonnierOpenIdException {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            if(clientId != null) {
                form.add("client_id", clientId);
            }
            if (scope != null) {
                form.add("scope", scope);
            }
            form.add("grant_type", grantType);
            form.add("username", username);
            form.add("password", password);
            form.add("long_lived_token",longLivedToken.toString());

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

    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return jwsUtil.verifyContent(idToken, clientId, resource.path("/keys").getURI().toString());
    }
}
