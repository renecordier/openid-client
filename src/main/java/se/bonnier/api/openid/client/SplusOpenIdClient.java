package se.bonnier.api.openid.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.entity.ClaimsSet;

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
}
