package se.bonnier.api.openid.examples;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.bonnier.api.openid.client.BipPasswordFlowClient;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;
import se.bonnier.api.openid.response.OAuth2Response;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

/**
 * Created by rene on 20/12/16.
 */
public class PasswordFlow {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordFlow.class);

    private static final Properties props = new Properties();
    private static final String fileName = "passwordflow.conf";

    public static void main( String[] args) throws Exception {
        readConfigFile();

        String endpoint = props.getProperty("bip.endpoint");
        String clientId = props.getProperty("bip.client.id");
        String username = props.getProperty("bip.username");
        String password = props.getProperty("bip.password");

        if(clientId.equals("ENTER_HERE") || username.equals("ENTER_HERE") || password.equals("ENTER_HERE")) {
            LOGGER.error("Please fill the needed values in the configuration file (src/main/resources/passwordflow.conf) given by S+ team after " +
                    "registering your BIP client");
            throw new BonnierOpenIdException("Missing values in config file !");
        }

        String scope = "openid email profile appId:di.se";
        boolean longLivedToken = true;

        OAuth2Response response = null;
        BipPasswordFlowClient ssoClient = new BipPasswordFlowClient(endpoint);
        try {
            //Request access token
            response = ssoClient.requestAccessToken(clientId,
                    scope,
                    username,
                    password,
                    longLivedToken);

            LOGGER.debug("Success !");
            LOGGER.debug("Access token : " + response.accessToken);
            LOGGER.debug("Token type : " + response.tokenType);
            LOGGER.debug("Expires in : " + response.expiresIn);
            LOGGER.debug("Refresh token : " + response.refreshToken);
            LOGGER.debug("Scope : " + response.scope);

            //Verify Id token and claim data
            ClaimsSet claimsSet = ssoClient.verifyIdToken(response.idToken, clientId);
            String accountId = claimsSet.getClaim("sub").toString();
            String firstName = claimsSet.getClaim("given_name").toString();
            String lastName = claimsSet.getClaim("family_name").toString();
            LOGGER.debug("ID token : {accountId:" + accountId + ",firstName:" + firstName + ",lastName:" + lastName + "}");

            //validate access token
            if(ssoClient.validateAccessToken(response.accessToken)) {
                LOGGER.debug("Validate access token success !");

                //revoke access token
                ssoClient.revokeAccessToken(response.accessToken, clientId);
            } else {
                throw new BonnierOpenIdException("Error when validating the access token");
            }
        } catch(BonnierOpenIdException e) {
            LOGGER.error("Error Bonnier OpenId exception : " + e.getMessage());
            throw new BonnierOpenIdException(e.getMessage());
        } catch(Exception e) {
            LOGGER.error("Error exception : " + e.getMessage());
            throw new Exception(e.getMessage());
        }
    }

    private static void readConfigFile() {
        FileReader fr = null;
        try {
            File globalProps = new File("./src/main/resources/" + fileName);
            fr = new FileReader(globalProps);
            props.load(fr);
        } catch (Exception e) {
            LOGGER.error("Could not read config file: " + e.getMessage());
            throw new BonnierOpenIdException("Could not read config file");
        } finally {
            try {
                if (fr != null) {
                    fr.close();
                }
            } catch (Exception e) {
            }
        }
    }
}
