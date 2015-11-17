package se.bonnier.api.openid.client;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by vietnq2 on 11/17/15.
 */
public class BonnierUtil {
    public static String createOpenIdState() {
        String state = new BigInteger(130, new SecureRandom()).toString(32);
        return state;
    }
}
