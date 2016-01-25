package se.bonnier.api.openid.util;

import com.sun.media.sound.InvalidDataException;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import se.bonnier.api.openid.client.ClaimsSet;

import java.security.PublicKey;

/**
 * @author kien.nguyen
 */
public class JwsUtil {
    private static final String SALT = "abcdefghijklmno";
    private HttpsJwks httpsJkws;

    public JwsUtil(String keysUrl){
        this.httpsJkws = new HttpsJwks(keysUrl);
    }

    /**
     * Use JSON Web Signature (JWS) algorithm to encrypt the ID token based on the secret key and S+ public key
     * @param rawIdToken content to be verified the signature and decrypted
     * @return signed content
     */
    public ClaimsSet verifyContent(String rawIdToken, String clientId, String keysUrl) {
        return verifyContent(rawIdToken, clientId, keysUrl, null);
    }

    /**
     * Use JSON Web Signature (JWS) algorithm to encrypt the ID token based on the secret key and S+ public key
     * @param rawIdToken content to be verified the signature and decrypted
     * @param jwsAlgorithm
     * @return signed content
     */
    public ClaimsSet verifyContent(String rawIdToken, String clientId, String keysUrl, JwsAlgorithm jwsAlgorithm) {
        try {
            if (JwsAlgorithm.EC.equals(jwsAlgorithm)) {
                String idToken = verifySignatureWithEc(rawIdToken);
                return TokenUtil.parseClaimsSet(idToken);
            } else {
                String idToken = verifySignatureWithRsa(rawIdToken, clientId, keysUrl);
                return TokenUtil.parseClaimsSet(idToken);
            }
        } catch (Exception e) {

        }

        return null;
    }

    /**
     * Use JSON Web Signature (JWS) algorithm to verify the signature and get the payload based on the public key
     * @param signedContent
     * @return payload
     */
    private String verifySignatureWithEc(String signedContent) throws InvalidDataException {
        try {

            // Create a new JsonWebSignature
            JsonWebSignature jws = new JsonWebSignature();

            // Set the compact serialization on the JWS
            jws.setCompactSerialization(signedContent);

            // Set the verification key
            // Note that your application will need to determine where/how to get the key
            // Here we use an example from the JWS spec
            PublicKey publicKey = JwsKeys.PUBLIC_256;
            jws.setKey(publicKey);

            // Check the signature
            if (!jws.verifySignature()) {
                throw new InvalidDataException("Cannot verify the signature, please check the signed content!");
            }

            // Get the payload, or signed content, from the JWS
            return jws.getPayload();
        } catch (JoseException e) {
            throw new RuntimeException("Cannot verify the signature with JWS based on the public key");
        }
    }

    /**
     * Use JSON Web Signature (JWS) algorithm to verify the signature and get the payload based on the public key
     * @param signedContent
     * @return payload
     */
    private String verifySignatureWithRsa(String signedContent, String clientId, String keysUrl) throws InvalidDataException {
        try {
            HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime() // the JWT must have an expiration time
                    .setRequireSubject() // the JWT must have a subject claim
                    .setExpectedAudience(clientId) // the JWT must have a audience claim with client_id
                    .setVerificationKeyResolver(httpsJwksKeyResolver)
                    .build();

            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(signedContent);
            return jwtClaims.toJson();
        } catch (InvalidJwtException e) {
            throw new InvalidDataException("Cannot verify the signature based on the public key");
        }
    }
}
