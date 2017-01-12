package se.bonnier.api.openid.client;

import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

import javax.ws.rs.core.MediaType;

/**
 * Created by rene on 11/01/17.
 */
public class BipAuthorizationCodeFlowClient extends SplusOpenIdClient {
    public BipAuthorizationCodeFlowClient(String endpoint, String clientId, String clientSecret) {
        super(endpoint, clientId, clientSecret);
    }

    public String getAuthorizeUrl(String authorizationRequestUri, String clientId, String redirectUri, String scope, String state,
                                  String nonce, String display, String lc, String loginHint, String cancelUri) {
        String url = authorizationRequestUri + "?response_type=code";
        url += "&client_id=" + clientId;
        url += "&redirect_uri=" + redirectUri;
        url += "&scope=" + scope;
        url += state != null ? "&state=" + state : "";
        url += nonce != null ? "&nonce=" + nonce : "";
        url += display != null ? "&display=" + display : "";
        url += lc != null ? "&lc=" + lc : "";
        url += loginHint != null ? "&loginHint=" + loginHint : "";
        url += cancelUri != null ? "&cancelUri=" + cancelUri : "";

        return url;
    }

    /**
     * Requests access token from Bonnier Identity Provider using authorization code
     * @param clientId S+ client Id
     * @param clientSecret S+ client secret
     * @param code the code received in authorization code flow
     * @param redirectURI the redirect uri registered
     * @param longLivedToken if token is long lived (30d) or not (8h)
     * @param codeVerifier used for PKCE concept (in case client cannot store a secret)
     * @return OAuth2Response object
     * @throws se.bonnier.api.openid.exceptions.BonnierOpenIdException
     */
    public OAuth2Response requestAccessToken(String clientId,
                                             String clientSecret,
                                             String code,
                                             String redirectURI,
                                             Boolean longLivedToken,
                                             String codeVerifier) throws BonnierOpenIdException {
        OAuth2Response oauthResponse = null;

        try {
            Form form = new Form();
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);
            form.add("grant_type", "authorization_code");
            form.add("redirect_uri", redirectURI);
            form.add("code", code);
            form.add("long_lived_token",longLivedToken.toString());

            if(codeVerifier != null){
                form.add("code_verifier", codeVerifier);
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
