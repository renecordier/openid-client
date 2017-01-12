package se.bonnier.api.openid.util;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import se.bonnier.api.openid.entity.ClaimsSet;
import se.bonnier.api.openid.entity.IdTokenClaimsSet;

import java.text.ParseException;

/**
 * @author kien.nguyen
 */
public class TokenUtil {
    public static ClaimsSet parseClaimsSet(String jsonIdToken) {
        try {
            return new IdTokenClaimsSet(new JSONObject(jsonIdToken));
        } catch (ParseException e) {
            return null;
        } catch (JSONException e) {
            return null;
        }
    }
}
