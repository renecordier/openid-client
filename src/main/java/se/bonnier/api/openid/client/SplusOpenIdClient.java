package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;

import javax.ws.rs.core.MediaType;

/**
 * Abstract class that defines the general methods of an OpenId client
 * @author vietnq
 */
public abstract class SplusOpenIdClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SplusOpenIdClient.class);

    protected static ApiClient apiClient;

    /**
     * Basic constructor.
     * @param endpoint the oauth2 endpoint to access the API
     */
    public SplusOpenIdClient(String endpoint) {
        apiClient = new ApiClient(endpoint);
    }

    /**
     * Full constructor
     * @param endpoint the oauth2 endpoint to access the API
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     */
    public SplusOpenIdClient(String endpoint, String clientId, String clientSecret) {
        apiClient = new ApiClient(endpoint, clientId, clientSecret);
    }

    /**
     * Verify signature of ID token and extract information
     * @param idToken ID token got in the same time with access token
     * @param clientId S+ client Id
     * @return ClaimsSet containing data of user
     */
    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return apiClient.verifyIdToken(idToken, clientId);
    }

    /**
     * Check if access token is valid or not
     * @param token access token to validate
     * @return true if token still valid, false otherwise
     * @throws BonnierOpenIdException
     */
    public boolean validateAccessToken(String token) throws BonnierOpenIdException {
        if (token != null) {
            return apiClient.validateToken(token);
        } else {
            return false;
        }
    }

    /**
     * Get user information from oauth2 endpoint
     * @param accessToken
     * @return JSON object with info of user
     */
    public JSONObject getUserInfo(String accessToken) {
        return apiClient.getUserInfo(accessToken);
    }

    /**
     * Get Open ID configuration from the discovery endpoint
     * @param discoveryUrl url of the discovery endpoint of OpenID
     * @return JSON object with info of user
     */
    public static JSONObject getOpenIdConfiguration(String discoveryUrl) {
        JSONObject json = new JSONObject();

        Client client = Client.create();
        try {
            WebResource.Builder builder = client.resource(discoveryUrl).accept(MediaType.APPLICATION_JSON);
            ClientResponse response = builder.get(ClientResponse.class);
            json = response.getEntity(JSONObject.class);
        } catch (Exception e) {
            LOGGER.debug("Failed to catch configuration at the discovery endpoint : " + discoveryUrl);
        }

        return json;
    }
}
