package se.bonnier.api.openid.client;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import se.bonnier.api.openid.exceptions.BonnierOpenIdException;

import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * @author kien.nguyen
 */
public class IdTokenClaimsSet extends ClaimsSet {
    /**
     * The id, specific claim of S+ by default.
     */
    public static final String ID_CLAIM_NAME = "id";

    /**
     * The issuer claim name.
     */
    public static final String ISS_CLAIM_NAME = "iss";


    /**
     * The subject claim name.
     */
    public static final String SUB_CLAIM_NAME = "sub";


    /**
     * The audience claim name.
     */
    public static final String AUD_CLAIM_NAME = "aud";


    /**
     * The expiration time claim name.
     */
    public static final String EXP_CLAIM_NAME = "exp";


    /**
     * The issue time claim name.
     */
    public static final String IAT_CLAIM_NAME = "iat";


    /**
     * The subject authentication time claim name.
     */
    public static final String AUTH_TIME_CLAIM_NAME = "auth_time";


    /**
     * The nonce claim name.
     */
    public static final String NONCE_CLAIM_NAME = "nonce";


    /**
     * The access token hash claim name.
     */
    public static final String AT_HASH_CLAIM_NAME = "at_hash";


    /**
     * The authorisation code hash claim name.
     */
    public static final String C_HASH_CLAIM_NAME = "c_hash";


    /**
     * The ACR claim name.
     */
    public static final String ACR_CLAIM_NAME = "acr";


    /**
     * The AMRs claim name.
     */
    public static final String AMR_CLAIM_NAME = "amr";


    /**
     * The authorised party claim name.
     */
    public static final String AZP_CLAIM_NAME = "azp";



    /**
     * The names of the standard top-level ID token claims.
     */
    private static final Set<String> stdClaimNames = new LinkedHashSet<String>();


    static {
        stdClaimNames.add(ID_CLAIM_NAME);
        stdClaimNames.add(ISS_CLAIM_NAME);
        stdClaimNames.add(SUB_CLAIM_NAME);
        stdClaimNames.add(AUD_CLAIM_NAME);
        stdClaimNames.add(EXP_CLAIM_NAME);
        stdClaimNames.add(IAT_CLAIM_NAME);
        stdClaimNames.add(AUTH_TIME_CLAIM_NAME);
        stdClaimNames.add(NONCE_CLAIM_NAME);
        stdClaimNames.add(AT_HASH_CLAIM_NAME);
        stdClaimNames.add(C_HASH_CLAIM_NAME);
        stdClaimNames.add(ACR_CLAIM_NAME);
        stdClaimNames.add(AMR_CLAIM_NAME);
        stdClaimNames.add(AZP_CLAIM_NAME);
    }

    /**
     * Gets the names of the standard top-level ID token claims.
     *
     * @return The names of the standard top-level ID token claims
     *         (read-only set).
     */
    public static Set<String> getStandardClaimNames() {

        return Collections.unmodifiableSet(stdClaimNames);
    }

    /**
     * Creates a new minimal ID token claims set. Note that the ID token
     * may require additional claims to be present depending on the
     * original OpenID Connect authorisation request.
     *
     * @param iss The issuer. Must not be {@code null}.
     * @param sub The subject. Must not be {@code null}.
     * @param aud The audience. Must not be {@code null}.
     * @param exp The expiration time. Must not be {@code null}.
     * @param iat The issue time. Must not be {@code null}.
     */
    public IdTokenClaimsSet(final String id,
                            final String iss,
                            final String sub,
                            final List<String> aud,
                            final Long exp,
                            final Long iat) {
        try {
            setClaim(ID_CLAIM_NAME, iss);
            setClaim(ISS_CLAIM_NAME, iss);
            setClaim(SUB_CLAIM_NAME, sub);

            JSONArray audList = new JSONArray();

            for (String a : aud) {
                audList.put(a);
            }

            setClaim(AUD_CLAIM_NAME, audList);

            setDateClaim(EXP_CLAIM_NAME, exp);
            setDateClaim(IAT_CLAIM_NAME, iat);
        } catch (JSONException e) {
            throw new BonnierOpenIdException("Incorrect claims " + e.getMessage());
        }
    }

    /**
     * Creates a new ID token claims set from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must be verified to represent a
     *                   valid ID token claims set and not {@code null}.
     *
     * @throws java.text.ParseException If the JSON object doesn't contain the
     *                        minimally required issuer {@code iss},
     *                        subject {@code sub}, audience list
     *                        {@code aud}, expiration date {@code exp} and
     *                        issue date {@code iat} claims.
     */
    public IdTokenClaimsSet(final JSONObject jsonObject)
            throws ParseException {

        super(jsonObject);
    }
}
