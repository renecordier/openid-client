package se.bonnier.api.openid.client;


import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

/**
 * @author kien.nguyen
 */
public abstract class ClaimsSet {
    /**
     * The JSON object representation of the claims set.
     */
    private final JSONObject claims;

    /**
     * Creates a new empty claims set.
     */
    protected ClaimsSet() {

        claims = new JSONObject();
    }

    /**
     * Creates a new claims set from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     */
    protected ClaimsSet(final JSONObject jsonObject) {

        if (jsonObject == null)
            throw new IllegalArgumentException("The JSON object must not be null");

        claims = jsonObject;
    }

    /**
     * Sets a claim.
     *
     * @param name  The claim name, with an optional language tag. Must not
     *              be {@code null}.
     * @param value The claim value. Should serialise to a JSON entity. If
     *              {@code null} any existing claim with the same name will
     *              be removed.
     */
    public void setClaim(final String name, final Object value) throws JSONException {

        if (value != null)
            claims.put(name, value);
        else
            claims.remove(name);
    }

    /**
     * Gets a claim.
     *
     * @param name The claim name. Must not be {@code null}.
     *
     * @return The claim value, {@code null} if not specified.
     */
    public Object getClaim(final String name) {
        try {
            return claims.get(name);
        } catch (JSONException e) {
            return null;
        }
    }

    /**
     * Gets a String claim.
     *
     * @param name The claim name. Must not be {@code null}.
     *
     * @return The claim value, {@code null} if not specified.
     */
    public String getStringClaim(final String name) {
        try {
            return (String) claims.get(name);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sets a date / time based claim, represented as the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param value The claim value. If {@code null} any existing claim
     *              with the same name will be removed.
     */
    public void setDateClaim(final String name, final Long value) throws JSONException {

        if (value != null)
            setClaim(name, value);
        else
            claims.remove(name);
    }


    @Override
    public String toString() {
        return claims.toString();
    }
}
