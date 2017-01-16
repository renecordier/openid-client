package se.bonnier.api.openid.client;

import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;

/**
 * @author vietnq
 */
public abstract class SplusOpenIdClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SplusOpenIdClient.class);

    protected static ApiClient apiClient;

    public SplusOpenIdClient(String endpoint) {
        apiClient = new ApiClient(endpoint);
    }

    public SplusOpenIdClient(String endpoint, String clientId, String clientSecret) {
        apiClient = new ApiClient(endpoint, clientId, clientSecret);
    }

    public ClaimsSet verifyIdToken(String idToken, String clientId) {
        return apiClient.verifyIdToken(idToken, clientId);
    }

    public boolean validateAccessToken(String token) throws BonnierOpenIdException {
        if (token != null) {
            return apiClient.validateToken(token);
        } else {
            return false;
        }
    }

    public JSONObject getUserInfo(String accessToken) {
        return apiClient.getUserInfo(accessToken);
    }
}
